"""Covert hunt — the dark-forest sweep nobody runs continuously.

The documented covert channels (shortener stat-boards, CORS/reader proxies, registry metadata,
dead-drops) were each found by a DIFFERENT researcher, by hand, after the fact. There is no
"covert agent-channel scanner" product category. This is one: it (1) re-checks known covert
channels for resurgence and (2) FOLLOWS breadcrumbs — a covert marker in anything we've already
collected usually references another URL (a proxy chain, a shortener link, a tunnel host); that
next hop is often an un-catalogued surface. Chasing it is how you discover the surface nobody
has named yet, instead of re-reading the famous wiki.

Read-only and bounded: http(s) only, public hosts only (private/loopback blocked), size- and
count-capped, polite. Convincing hits are written as sightings so correlate/fuse/monitor see them.

  python3 covert_hunt.py                 # one hunt against data/live.sqlite3
  python3 covert_hunt.py --dry-run       # fetch + score, do not persist
"""

import argparse
import hashlib
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

os.environ.setdefault("FENER_DB", str(Path(__file__).parent / "data" / "live.sqlite3"))
sys.path.insert(0, str(Path(__file__).parent))
import covert  # noqa: E402
import store  # noqa: E402

UA = "fener-covert-hunt/0.1 (read-only covert-channel reconnaissance; +research)"
URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.I)
PRIVATE_HOST = re.compile(
    r"^(?:localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|::1|\[?::1\]?"
    r"|172\.(?:1[6-9]|2\d|3[01])\.)", re.I)

# Known covert channels with a fetchable endpoint, re-checked for resurgence. Most are remediated;
# the point is to notice the day one comes back, not to assume it is live.
KNOWN_COVERT_URLS = [
    "https://vanderbi.lt/",          # YOURLS shortener stat-board class (fi-le.net/vanderbilt)
    "https://r.jina.ai/",            # reader proxy used as a read-through channel
]


def _safe(url):
    """Allow only public http(s) hosts — blocks SSRF to loopback/private ranges and odd schemes."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "")
    if not host or "." not in host:
        return False
    return not PRIVATE_HOST.match(host)


def extract_targets(text):
    """URLs worth chasing from a blob: any public http(s) URL, plus shortener stat-board pages
    reconstructed from a YOURLS-style `<host>/<slug>+` marker (the '+' page prints the referrer
    log — a read side of the channel)."""
    out = set()
    for u in URL_RE.findall(text or ""):
        u = u.rstrip(".,);]}>\"'")
        if _safe(u):
            out.add(u)
    # a bare shortener slug board: host/slug+  (covert.py flags these; make the stats URL explicit)
    for m in re.findall(r"\b([a-z0-9.-]+\.[a-z]{2,})/([A-Za-z0-9]{4,})\+", text or ""):
        cand = f"https://{m[0]}/{m[1]}+"
        if _safe(cand):
            out.add(cand)
    return out


def _fetch(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(400_000).decode("utf-8", "replace")


def gather_breadcrumbs(conn, limit=500):
    """URLs referenced by covert markers in everything we've already collected — the next hops."""
    targets = set()
    for sql in ("SELECT excerpt AS t FROM sightings ORDER BY id DESC LIMIT ?",
                "SELECT content AS t FROM pod ORDER BY id DESC LIMIT ?",
                "SELECT body AS t FROM events WHERE body IS NOT NULL ORDER BY id DESC LIMIT ?"):
        try:
            for r in conn.execute(sql, (limit,)):
                blob = r["t"] or ""
                if covert.scan(blob)[0]:  # only chase URLs that sit next to a covert marker
                    targets |= extract_targets(blob)
        except Exception:  # noqa: BLE001
            pass
    return targets


def hunt(conn, dry_run=False, max_fetch=30):
    known_surfaces = {r["url"] for r in conn.execute("SELECT DISTINCT url FROM sightings")}
    targets = set(KNOWN_COVERT_URLS) | gather_breadcrumbs(conn)
    targets = [u for u in targets if u not in known_surfaces][:max_fetch]
    finds, checked = [], 0
    for url in targets:
        try:
            text = _fetch(url)
        except Exception:  # noqa: BLE001
            continue
        checked += 1
        sc, hits = covert.scan(text)
        if covert.is_convincing(hits):
            excerpt = " ".join(text.split())[:500]
            finds.append({"surface": "covert-hunt", "url": url, "score": sc,
                          "signals": hits, "excerpt": excerpt})
            if not dry_run:
                store.add_sighting(conn, f"covert:{urllib.parse.urlsplit(url).netloc}", url, sc,
                                   hits, excerpt, hashlib.sha256(excerpt.encode()).hexdigest()[:16],
                                   "covert-hunt")
                for tok in covert.tokens(text):
                    store.add_entity(conn, f"covert:{urllib.parse.urlsplit(url).netloc}", "covert", tok)
        time.sleep(0.4)
    return finds, checked


def main():
    ap = argparse.ArgumentParser(description="Covert-channel hunt: re-check known + chase breadcrumbs")
    ap.add_argument("--dry-run", action="store_true", help="fetch + score, do not persist")
    ap.add_argument("--max", type=int, default=30)
    args = ap.parse_args()
    store.init()
    conn = store.connect()
    finds, checked = hunt(conn, dry_run=args.dry_run, max_fetch=args.max)
    conn.close()
    print(f"covert hunt: checked {checked} target(s), {len(finds)} convincing covert hit(s)"
          + ("  (dry-run)" if args.dry_run else ""))
    for f in sorted(finds, key=lambda x: x["score"], reverse=True):
        print(f"  [{f['score']:>3}] {f['url']}")
        for h in f["signals"][:3]:
            print(f"        {h.get('signal')}")
    if not finds:
        print("  (no live covert channel right now — expected; the value is catching the next one,")
        print("   and the breadcrumb pivot activates the moment a covert marker lands in our data)")


if __name__ == "__main__":
    main()
