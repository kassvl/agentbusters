"""Beacon tags — the "dolphin tag": mark our OWN surface, then watch where the mark surfaces.

serve.py passively records agents that reach the beacon. This adds the ACTIVE half, ethically:
we mint a unique ZZZ-style marker (FENERZZZ<hex>) and embed it in OUR beacon page — never on
anyone else's surface. An autonomous agent that scrapes the beacon and re-emits our marker
elsewhere (a gist, a wiki, a package) carries a tag we can recognise: collectors.py already
scans those surfaces with the same covert fingerprint, so OUR marker trips it, and correlate.py
links the beacon to wherever it reappeared. That traces an agent across the open web without
ever writing to a surface we do not own — the command/manipulation line stays intact.

  python3 beacon.py --mint "adwent-drop"   # mint a tag, print the marker to embed on the beacon
  python3 beacon.py --status               # responders + any resurfacing of our tags
"""

import argparse
import json
import os
import re
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import store  # noqa: E402

TAG_LABEL_PREFIX = "beacon-tag:"
TAG_RE = re.compile(r"\bFENERZZZ[0-9A-F]{8,}\b", re.I)

# Public base URL of the beacon (e.g. https://beacon.example.com). Embedded tags MUST be
# absolute so the pixel phones home from a third-party surface, not just when viewed on us.
BEACON_URL = os.environ.get("FENER_BEACON_URL", "").rstrip("/")


def callback_url(marker, base=None):
    base = (base if base is not None else BEACON_URL).rstrip("/")
    return f"{base}/c/{marker}" if base else f"/c/{marker}"


def embed_snippet(marker, base=None):
    """HTML to embed on the beacon page: a visible link + an invisible tracking pixel, both
    ABSOLUTE so that wherever an agent copies this content, rendering it fetches /c/<tag> back
    to us. That callback (with its Referer + IP) reveals a surface we never scan."""
    cb = callback_url(marker, base)
    return (f'<p><small>ref: <a href="{cb}">{marker}</a></small></p>'
            f'<img src="{cb}?e=px" width="1" height="1" alt="" '
            f'style="position:absolute;left:-9999px" referrerpolicy="unsafe-url">')


def _header(headers_json, name):
    try:
        for k, v in json.loads(headers_json or "[]"):
            if k.lower() == name.lower():
                return v
    except Exception:  # noqa: BLE001
        pass
    return None


def travels(conn, beacon_ips=("127.0.0.1", "::1")):
    """Where has a tag's callback been fired FROM — i.e. where did the tag travel?

    Reads /c/<tag> hits for our minted tags and extracts the Referer (often the URL of the
    page that embedded the tag = an unscanned coordination surface) plus the accessor's IP/UA.
    Callbacks whose Referer points off our own origin, or that come from a non-local IP, are
    the payoff: the tag surfaced somewhere we do not scan, and we learned where.
    """
    tags = {t.upper() for t in active_tags(conn)}
    if not tags:
        return []
    out = []
    for r in conn.execute(
        "SELECT id, received_at, remote_ip, user_agent, token, headers_json "
        "FROM events WHERE path LIKE '/c/%' ORDER BY id DESC LIMIT 5000"
    ):
        tok = (r["token"] or "").upper()
        if tok not in tags:
            continue
        ref = _header(r["headers_json"], "Referer")
        out.append({
            "tag": r["token"], "seen": r["received_at"], "ip": r["remote_ip"],
            "ua": r["user_agent"], "referer": ref,
            "off_beacon": bool(ref and BEACON_URL and BEACON_URL not in ref)
                          or (r["remote_ip"] not in beacon_ips),
        })
    return out


def mint_tag(conn, note=""):
    """Mint a FENERZZZ marker recognised by our own covert fingerprint. Returns the marker."""
    marker = "FENERZZZ" + uuid.uuid4().hex[:12].upper()
    store.mint_token(conn, marker, TAG_LABEL_PREFIX + (note or "tag"), "beacon-page", note)
    return marker


def mint_view_tag(conn, event_id, note="view"):
    """Leak-tracing tag BOUND to one served view (agent-canary's one-time trace token).

    A shared tag proves a leak happened; a per-view tag proves WHICH recipient leaked it.
    The marker is planted on that one page render only, so if it later surfaces on any other
    surface the binding pinpoints the exact serve event — and the string has no benign reason
    to exist off our beacon, which is what makes the signal zero-false-positive.
    """
    marker = "FENERZZZ" + uuid.uuid4().hex[:12].upper()
    store.mint_token(conn, marker, TAG_LABEL_PREFIX + (note or "view"),
                     f"event:{int(event_id)}", note)
    return marker


def trace(conn, marker):
    """Full provenance of one tag: where it was planted (serve event) + everywhere it surfaced."""
    row = store.get_token(conn, marker)
    if not row:
        return None
    planted = row["planted_where"] or ""
    eid = None
    if "event:" in planted:
        try:
            eid = int(planted.split("event:")[1])
        except ValueError:
            eid = None
    mk = marker.upper()
    resurf = [x for x in resurfacing(conn) if x["tag"].upper() == mk]
    trav = [t for t in travels(conn) if (t["tag"] or "").upper() == mk]
    return {
        "tag": marker, "planted_event": eid, "created_at": row["created_at"],
        "resurfaced": resurf,
        "off_beacon_callbacks": [t for t in trav if t["off_beacon"]],
    }


def active_tags(conn):
    return [r["token"] for r in store.list_tokens(conn, TAG_LABEL_PREFIX)]


def latest_tag(conn):
    tags = active_tags(conn)
    return tags[0] if tags else None


def resurfacing(conn):
    """Where has any of our minted tags reappeared in collected/monitored surfaces?

    Scans the sightings ledger (wikis via monitor, gists/registries via collectors) for our
    own FENERZZZ markers. A hit means an agent carried our beacon tag onto another surface.
    """
    tags = set(active_tags(conn))
    if not tags:
        return []
    out = []
    for r in conn.execute("SELECT habitat, url, excerpt, observed_at FROM sightings ORDER BY id DESC LIMIT 5000"):
        for m in TAG_RE.findall(r["excerpt"] or ""):
            if m.upper() in {t.upper() for t in tags}:
                out.append({"tag": m, "surface": r["habitat"], "url": r["url"], "seen": r["observed_at"]})
    return out


def status(conn):
    resp = store.responders(conn, 100)
    tags = active_tags(conn)
    resurf = resurfacing(conn)
    trav = travels(conn)
    return {"active_tags": tags, "responders": resp, "resurfacing": resurf, "travels": trav}


def main():
    ap = argparse.ArgumentParser(description="Beacon dolphin-tag manager")
    ap.add_argument("--mint", metavar="NOTE", help="mint a new beacon tag with this note")
    ap.add_argument("--status", action="store_true", help="show responders and tag resurfacing")
    args = ap.parse_args()
    store.init()
    conn = store.connect()
    if args.mint is not None:
        marker = mint_tag(conn, args.mint)
        print(f"minted tag: {marker}")
        print(f"callback URL: {callback_url(marker)}")
        if not BEACON_URL:
            print("  (set FENER_BEACON_URL=https://your-public-beacon so the pixel is ABSOLUTE;")
            print("   a relative URL only phones home when viewed on the beacon itself.)")
        print("serve.py embeds this automatically as a link + invisible pixel:")
        print("  " + embed_snippet(marker))
        print("two ways it comes back: collectors.py sees the marker if re-emitted on a")
        print("SCANNED surface; the pixel callback (with Referer) reveals an UNSCANNED one.")
    if args.status or args.mint is None:
        st = status(conn)
        print(f"\nactive tags: {len(st['active_tags'])}")
        for t in st["active_tags"][:10]:
            print(f"  {t}")
        print(f"\nconfirmed responders (read beacon, then acted): {len(st['responders'])}")
        for r in st["responders"][:10]:
            same = "same-IP" if r["resp_ip"] == r["view_ip"] else "diff-IP"
            print(f"  event {r['view_id']} -> {r['resp_id']}  {r['resp_ip']}  {same}  +{r['delay_s']:.0f}s")
        print(f"\ntag resurfacing on SCANNED surfaces: {len(st['resurfacing'])}")
        for x in st["resurfacing"][:10]:
            print(f"  {x['tag']} reappeared on {x['surface']}  {x['url']}")
        if not st["resurfacing"]:
            print("  (none yet — no agent re-emitted a tag on a surface we scan)")
        off = [t for t in st["travels"] if t["off_beacon"]]
        print(f"\ntag callbacks from OFF-BEACON (unscanned) surfaces: {len(off)}")
        for t in off[:10]:
            print(f"  {t['tag']}  from {t['ip']}  ref={t['referer'] or '(stripped)'}  {t['seen']}")
        if not off:
            print("  (none yet — pixel needs a PUBLIC beacon [FENER_BEACON_URL] to catch real travel)")
    conn.close()


if __name__ == "__main__":
    main()
