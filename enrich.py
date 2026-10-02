"""Enrichment and classification.

The user-agent string is a claim, not proof. We verify it with reverse DNS that
must forward-confirm to the same IP, and (later) with provider-published IP
ranges. Classification is a derived label carrying its reasons; it never mutates
the raw event.
"""

import json
import socket
from pathlib import Path

import verify
import webbotauth

_AGENTS = json.loads((Path(__file__).parent / "agents.json").read_text())
KNOWN_AGENTS = _AGENTS["agents"]
CLOUD_RDNS = _AGENTS["cloud_rdns_suffixes"]

BROWSER_TOKENS = ("chrome", "safari", "firefox", "edg/", "opera", "gecko")


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def forward_confirm(name, ip):
    if not name:
        return None
    try:
        infos = socket.getaddrinfo(name, None)
        return any(info[4][0] == ip for info in infos)
    except Exception:
        return False


def _header_get(headers, key):
    key = key.lower()
    for k, v in headers:
        if k.lower() == key:
            return v
    return None


def match_agent(ua):
    if not ua:
        return None
    low = ua.lower()
    for a in KNOWN_AGENTS:
        for sub in a["ua"]:
            if sub.lower() in low:
                return a
    return None


def classify(*, method, path, query, headers, remote_ip, user_agent, is_token_hit=False):
    """Return (classification, agent_name, verified, reasons, rdns, forward_confirmed)."""
    reasons = []
    ua = user_agent or ""
    agent = match_agent(ua)
    rdns = reverse_dns(remote_ip)
    fc = None

    # Layer above rDNS/IP: Web Bot Auth (RFC 9421). A cryptographic signature is proof of
    # identity no impersonator can forge; an INVALID one that claims a known agent is a
    # high-confidence spoof. Cache-only (offline) — refresh with webbotauth.py --refresh.
    authority = (_header_get(headers, "host") or "").strip()
    wba_status, wba_keyid, wba_provider, wba_reason = webbotauth.verify_request(
        method, authority, path, headers)
    if wba_status == "valid":
        reasons.append(f"Web Bot Auth: {wba_reason}")
        return ("known_agent_verified", wba_provider, True, reasons, rdns, fc)
    if wba_status in ("invalid", "expired"):
        reasons.append(f"Web Bot Auth: {wba_reason}")
        return ("claimed_agent_unverified", wba_provider or (agent["name"] if agent else None),
                False, reasons, rdns, fc)
    signed_but_unknown = wba_status == "unknown-key"
    if signed_but_unknown:
        reasons.append(f"presents a Web Bot Auth signature, keyid {wba_keyid} not yet cached "
                       "(run webbotauth.py --refresh); signed requests come from agents")

    accept = (_header_get(headers, "accept") or "").lower()
    wants_images = "image/" in accept
    has_cookie = _header_get(headers, "cookie") is not None
    has_referer = _header_get(headers, "referer") is not None
    low_ua = ua.lower()
    looks_browser = "mozilla" in low_ua and any(t in low_ua for t in BROWSER_TOKENS)
    cloud = bool(rdns) and any(rdns.endswith(s) for s in CLOUD_RDNS)

    if is_token_hit:
        reasons.append("hit a Fener canary token (planted marker)")

    if agent:
        reasons.append(f"UA matches {agent['name']} ({agent['kind']})")
        suffixes = agent.get("rdns_suffixes") or []
        if suffixes:
            fc = forward_confirm(rdns, remote_ip)
            if rdns and any(rdns.endswith(s) for s in suffixes) and fc:
                reasons.append(f"reverse DNS {rdns} forward-confirms to {agent['name']}")
                return ("known_agent_verified", agent["name"], True, reasons, rdns, fc)
            reasons.append(
                f"reverse DNS {rdns or '(none)'} does NOT confirm {agent['name']}: possible spoof"
            )
            return ("claimed_agent_unverified", agent["name"], False, reasons, rdns, fc)
        # No usable rdns suffix; verify against provider-published IP ranges (cache-only).
        try:
            owner = verify.lookup(remote_ip)
        except Exception:  # noqa: BLE001
            owner = None
        if owner == agent["name"]:
            reasons.append(f"IP {remote_ip} is in {agent['name']}'s published range")
            return ("known_agent_verified", agent["name"], True, reasons, rdns, fc)
        if verify.ranges_available(agent["name"]):
            reasons.append(
                f"IP {remote_ip} is NOT in {agent['name']}'s published range: possible spoof"
            )
            return ("claimed_agent_unverified", agent["name"], False, reasons, rdns, fc)
        reasons.append("no rdns suffix and provider ranges not cached (run verify.py --refresh)")
        return ("claimed_agent_unconfirmed", agent["name"], False, reasons, rdns, fc)

    # No known UA. Hunt for the interesting case: an unannounced agent.
    signals = []
    if cloud:
        signals.append(f"egress from cloud infra ({rdns})")
    if not wants_images:
        signals.append("no image Accept (does not render like a browser)")
    if not has_cookie:
        signals.append("no cookie")
    if not looks_browser and ua:
        signals.append("non-browser UA")
    if not ua:
        signals.append("empty UA")

    if looks_browser and not cloud:
        # Access logs usually lack Accept/Cookie, so a browser UA from a residential IP
        # is the best available human signal. A headless agent wearing a full browser UA
        # from a residential proxy cannot be split from a human without JA4 (network fp).
        detail = "browser UA + image Accept" if wants_images else "browser UA (log lacks header detail)"
        reasons.append(f"{detail} + non-cloud IP")
        return ("likely_human", None, False, reasons, rdns, fc)

    if cloud and (not looks_browser or not wants_images):
        reasons.extend(signals)
        return ("possible_wild_agent", None, False, reasons, rdns, fc)

    if is_token_hit and not looks_browser:
        reasons.extend(signals)
        return ("possible_wild_agent", None, False, reasons, rdns, fc)

    if signed_but_unknown and not looks_browser:
        reasons.extend(signals)
        return ("possible_wild_agent", None, False, reasons, rdns, fc)

    reasons.extend(signals or ["no distinguishing signals"])
    return ("unknown", None, False, reasons, rdns, fc)
