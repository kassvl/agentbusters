"""Discover — turn the reproducible fingerprint into MORE candidate habitats.

The 2026 method: agents were GET-only, so they sought legacy wikis writable via GET
(UseMod/ProWiki `wiki.cgi?action=`). We generalise that into (a) search dorks for the
habitat fingerprint and content traces, and (b) enumeration of a wiki farm hub. Output is
a candidate URL list you feed to hunt.py. Discovery is finding surfaces to READ, never to
write.

  python3 discover.py --dorks                       # print search queries to run
  python3 discover.py --farm https://prowiki.org/prowiki/wiki.cgi  # list sibling wikis
  python3 discover.py --merge results.txt --out data/candidates.txt
"""

import argparse
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import traces  # noqa: E402

UA = "fener-discover/0.1 (read-only; +research)"

CONTENT_DORKS = [
    '"as an autonomous agent" site:*.wiki OR inurl:wiki.cgi',
    '"AgentZzz" OR "ZZZ" agent wiki',
    'inurl:wiki.cgi "RecentChanges"',
    'inurl:wiki.pl action=rc',
    'inurl:"?do=recent" dokuwiki',
    '"powered by UseModWiki" OR "ProWiki"',
    'open guestbook "sign the guestbook" bot',
    '"pinggy.io" OR "localhost.run" agent tunnel wiki',
]


def dorks():
    print("# habitat url-shape fingerprints:")
    for p in traces.FINGERPRINTS["url_patterns"]:
        print(f"  {p}")
    print("\n# search dorks (run in a search engine; collect the result URLs):")
    for d in CONTENT_DORKS:
        print(f"  {d}")


def farm(hub):
    req = urllib.request.Request(hub, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        html = r.read(800_000).decode("utf-8", "replace")
    base = re.match(r"(https?://[^/]+)", hub).group(1)
    links = set()
    for m in re.findall(r'href=["\']([^"\']+wiki\.cgi[^"\']*)["\']', html):
        u = m if m.startswith("http") else base + (m if m.startswith("/") else "/" + m)
        links.add(u.split("?")[0])
    return sorted(links)


def main():
    ap = argparse.ArgumentParser(description="Discover candidate agent habitats")
    ap.add_argument("--dorks", action="store_true")
    ap.add_argument("--farm", help="wiki-farm hub URL to enumerate for sibling wiki.cgi sites")
    ap.add_argument("--merge", help="a file of result URLs to fold into the candidate list")
    ap.add_argument("--out", default="data/candidates.txt")
    args = ap.parse_args()

    if args.dorks:
        dorks()
        return

    candidates = set()
    if args.farm:
        try:
            found = farm(args.farm)
            candidates.update(found)
            print(f"farm {args.farm}: {len(found)} sibling wiki.cgi surfaces")
        except Exception as e:  # noqa: BLE001
            print(f"farm enumeration failed: {type(e).__name__}")
    if args.merge:
        candidates.update(
            ln.strip() for ln in Path(args.merge).read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        )
    if candidates:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text("\n".join(sorted(candidates)) + "\n")
        print(f"wrote {len(candidates)} candidates -> {args.out} (feed to: python3 hunt.py --seeds {args.out})")
    elif not args.dorks:
        dorks()


if __name__ == "__main__":
    main()
