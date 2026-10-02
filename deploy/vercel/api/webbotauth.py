"""Web Bot Auth — cryptographic agent attribution (RFC 9421 HTTP Message Signatures).

The 2026 disclosures made one thing plain: a User-Agent string is a claim, an IP range is
stronger, but neither survives a determined impersonator on rented infrastructure. Web Bot
Auth (Cloudflare/IETF, W3C-final May 2026; verified in production by Cloudflare/AWS/Akamai/
Vercel) closes that: the agent signs its request with Ed25519 and publishes its public key at
`/.well-known/http-message-signatures-directory`. A valid signature is proof of identity that
no spoofer can forge; an INVALID one on a request that claims to be a known agent is a
high-confidence impersonation finding.

This module is pure observation — it verifies signatures presented TO our beacon, it never
signs requests to anyone. It turns enrich.py's `known_agent_verified` into a cryptographic
verdict layered above reverse-DNS and IP-range checks.

  refresh(host, provider)   # fetch + cache a provider's key directory (network)
  verify_request(method, authority, path, headers) -> (status, keyid, provider, reason)
       status in {valid, invalid, unknown-key, expired, malformed, no-signature}
"""

import base64
import json
import os
import re
import time
import urllib.request
from pathlib import Path

import ed25519

DIR_PATH = Path(os.environ.get("FENER_WBA_DIR", Path(__file__).parent / "data" / "webbotauth"))
WELL_KNOWN = "/.well-known/http-message-signatures-directory"

_dir_cache = None  # {keyid: {"pub": bytes, "provider": str, "host": str}}


def _b64url_decode(s):
    s = s.strip().rstrip("=")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---- Structured-Fields-lite parsing (RFC 8941 subset for Signature / Signature-Input) -------

def _header_get(headers, name):
    """headers is a list of [k, v]; return the first value whose key matches (case-insensitive)."""
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def parse_signature_input(value):
    """Parse a Signature-Input header into {label: {components, params, raw}}.

    raw is the exact signature-params byte string (the value after `label=`), which RFC 9421
    requires verbatim as the @signature-params line of the signature base — so we keep it as
    it appeared rather than re-serialising.
    """
    out = {}
    for label, raw in _split_labels(value):
        m = re.match(r"\((?P<inner>[^)]*)\)(?P<params>.*)$", raw.strip())
        if not m:
            continue
        components = re.findall(r'"([^"]*)"', m.group("inner"))
        params = _parse_params(m.group("params"))
        out[label] = {"components": components, "params": params, "raw": raw.strip()}
    return out


def parse_signature(value):
    """Parse a Signature header into {label: sig_bytes}. Values are byte sequences :base64:."""
    out = {}
    for label, raw in _split_labels(value):
        m = re.search(r":([^:]*):", raw)
        if m:
            try:
                out[label] = base64.b64decode(m.group(1))
            except Exception:  # noqa: BLE001
                pass
    return out


def _split_labels(value):
    """Split `a=..., b=...` on top-level commas (commas inside (...) or :...: stay put)."""
    parts, depth, inbytes, cur = [], 0, False, ""
    for ch in value or "":
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == ":":
            inbytes = not inbytes
        if ch == "," and depth == 0 and not inbytes:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    res = []
    for p in parts:
        if "=" in p:
            label, raw = p.split("=", 1)
            res.append((label.strip(), raw.strip()))
    return res


def _parse_params(s):
    params = {}
    for m in re.finditer(r';\s*([a-zA-Z0-9_-]+)(?:=("?)([^";]*)\2)?', s or ""):
        key, _q, val = m.group(1), m.group(2), m.group(3)
        if val is None or val == "":
            params[key] = True
        elif val.lstrip("-").isdigit():
            params[key] = int(val)
        else:
            params[key] = val
    return params


# ---- Signature base construction (RFC 9421 §2.5) --------------------------------------------

def _derived(component, method, authority, path):
    if component == "@method":
        return (method or "").upper()
    if component == "@authority":
        return (authority or "").lower()
    if component == "@path":
        return path or "/"
    if component == "@target-uri":
        return f"https://{(authority or '').lower()}{path or '/'}"
    if component == "@scheme":
        return "https"
    if component == "@query":
        q = ""
        if path and "?" in path:
            q = path[path.index("?"):]
        return q or "?"
    return None


def signature_base(parsed_label, method, authority, path, headers):
    """Reconstruct the exact bytes the signature must cover for one parsed Signature-Input label."""
    lines = []
    for comp in parsed_label["components"]:
        if comp.startswith("@"):
            val = _derived(comp, method, authority, path)
            if val is None:
                return None  # unsupported derived component -> cannot verify
        else:
            val = _header_get(headers, comp)
            if val is None:
                return None  # a covered header is missing -> cannot verify
            val = val.strip()
        lines.append(f'"{comp}": {val}')
    lines.append(f'"@signature-params": {parsed_label["raw"]}')
    return "\n".join(lines).encode("utf-8")


# ---- Key directory cache --------------------------------------------------------------------

def _load_dirs():
    global _dir_cache
    if _dir_cache is not None:
        return _dir_cache
    _dir_cache = {}
    if DIR_PATH.is_dir():
        for f in DIR_PATH.glob("*.json"):
            try:
                d = json.loads(f.read_text())
            except Exception:  # noqa: BLE001
                continue
            provider = d.get("provider", f.stem)
            host = d.get("host", f.stem)
            for jwk in d.get("keys", []):
                if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" and jwk.get("x"):
                    kid = jwk.get("kid") or _thumbprint(jwk)
                    try:
                        _dir_cache[kid] = {"pub": _b64url_decode(jwk["x"]),
                                           "provider": provider, "host": host}
                    except Exception:  # noqa: BLE001
                        pass
    return _dir_cache


def _thumbprint(jwk):
    canon = '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % jwk["x"]
    import hashlib
    return base64.urlsafe_b64encode(hashlib.sha256(canon.encode()).digest()).rstrip(b"=").decode()


def find_key(keyid):
    return _load_dirs().get(keyid)


def refresh(host, provider=None, timeout=15):
    """Fetch and cache a provider's JWK-set directory. Returns a status string."""
    DIR_PATH.mkdir(parents=True, exist_ok=True)
    url = f"https://{host}{WELL_KNOWN}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "fener-webbotauth/0.1",
            # the directory's registered media type; some origins content-negotiate on it
            "Accept": "application/http-message-signatures-directory, application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        return f"skip ({type(e).__name__})"
    keys = data.get("keys", data if isinstance(data, list) else [])
    slug = re.sub(r"[^a-z0-9.]+", "-", host.lower()).strip("-")
    (DIR_PATH / f"{slug}.json").write_text(
        json.dumps({"host": host, "provider": provider or host, "fetched": time.time(),
                    "keys": keys}, indent=1))
    global _dir_cache
    _dir_cache = None
    return f"{len(keys)} key(s) cached"


def verify_request(method, authority, path, headers):
    """Verify any Web Bot Auth signature on a request. Read-only, never raises.

    Returns (status, keyid, provider, reason). status:
      valid       — signature verified against a cached provider key (proof of identity)
      invalid     — signature present but does NOT verify (impersonation / tampering)
      expired     — signature verifies but its `expires` is in the past
      unknown-key — well-formed signature whose keyid is in no cached directory
      malformed   — a signature header exists but could not be parsed / base built
      no-signature — no Web Bot Auth headers at all (the common case)
    """
    sig_input = _header_get(headers, "signature-input")
    sig_hdr = _header_get(headers, "signature")
    if not sig_input or not sig_hdr:
        return ("no-signature", None, None, "no Web Bot Auth signature headers")
    try:
        inputs = parse_signature_input(sig_input)
        sigs = parse_signature(sig_hdr)
    except Exception:  # noqa: BLE001
        return ("malformed", None, None, "unparseable signature headers")
    for label, parsed in inputs.items():
        if label not in sigs:
            continue
        keyid = parsed["params"].get("keyid")
        base = signature_base(parsed, method, authority, path, headers)
        if base is None:
            return ("malformed", keyid, None, "covered component missing; cannot build base")
        key = find_key(keyid) if keyid else None
        if not key:
            sa = _header_get(headers, "signature-agent")
            hint = f"; Signature-Agent={sa} — run webbotauth.py --refresh <host>" if sa else ""
            return ("unknown-key", keyid, None, "keyid not in any cached key directory" + hint)
        if ed25519.checkvalid(sigs[label], base, key["pub"]):
            exp = parsed["params"].get("expires")
            if isinstance(exp, int) and exp < int(time.time()):
                return ("expired", keyid, key["provider"], f"valid but expired at {exp}")
            return ("valid", keyid, key["provider"],
                    f"Ed25519 signature verifies against {key['provider']} key {keyid}")
        return ("invalid", keyid, key["provider"],
                f"signature does NOT verify against {key['provider']} key {keyid}: impersonation")
    return ("malformed", None, None, "Signature-Input present but no matching Signature label")


def main():
    import sys
    if "--refresh" in sys.argv:
        # usage: python3 webbotauth.py --refresh <host> [provider]
        args = [a for a in sys.argv[2:]]
        if not args:
            print("usage: webbotauth.py --refresh <host> [provider-name]")
            return
        host = args[0]
        provider = args[1] if len(args) > 1 else None
        print(f"{host}: {refresh(host, provider)}")
        return
    print("cached Web Bot Auth keys:", len(_load_dirs()))
    for kid, k in _load_dirs().items():
        print(f"  {k['provider']:<20} {kid}")


if __name__ == "__main__":
    main()
