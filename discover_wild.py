"""Discover wild — enumerate the whole CLASS of agent-habitat-shaped surfaces across the web,
not just the ProWiki farm, and write the list to data/seeds_wild.txt for the scout to roam.

The documented agent habitats were GET-writable old CGI wikis (UseMod/ProWiki/Oddmuse/MoinMoin)
and their neglected corners — a specific, enumerable class, NOT the general web (active human
communities are clean). So this harvests that class from FREE sources, no search API needed:

  1. wiki DIRECTORY / SiteList pages (Meatball, UseMod, Oddmuse, CommunityWiki, WikiIndex) that
     each list many wikis;
  2. INTERWIKI / InterMap pages of discovered wikis (old wikis cross-link heavily) — a BFS that
     compounds, engine-agnostic;
  3. Common Crawl CDX per discovered DOMAIN (host-anchored, which CDX serves fast) to pull more
     wiki paths on each host.

Every candidate is classified by engine from its URL shape. Output: data/seeds_wild.txt (one URL
per line) + a wild_seeds DB row per surface (status 'new') so the roamer can work through them.
Read-only, bounded, polite — this reads public directory/index pages, it does not scan the targets.

  python3 discover_wild.py                 # harvest + write the seed list
  python3 discover_wild.py --max 10000     # cap the harvest
  python3 discover_wild.py --cdx           # also augment via Common Crawl CDX per domain (slower)
"""

import argparse
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import store  # noqa: E402

UA = "fener-discover/0.1 (read-only wiki-directory enumeration; +research)"
OUT = Path(__file__).parent / "data" / "seeds_wild.txt"

# Directory / SiteList pages that each enumerate many independent wikis (free, public).
DIRECTORIES = [
    "http://www.usemod.com/cgi-bin/mb.pl?SiteList",
    "http://www.usemod.com/cgi-bin/wiki.pl?SiteList",
    "https://communitywiki.org/wiki/SiteList",
    "https://communitywiki.org/wiki/InterMap",
    "http://meatballwiki.org/wiki/SiteList",
    "https://oddmuse.org/wiki/Sites_That_Use_Oddmuse",
    "https://www.wikiindex.org/Category:UseModWiki",
    "https://www.wikiindex.org/Category:Oddmuse",
    "https://www.wikiindex.org/Category:MoinMoin",
]

# The ENUMERABLE agent-habitat class = GET-writable OLD CGI wikis (UseMod/ProWiki/Oddmuse/
# MoinMoin), whose URLs carry a cgi/pl script + an action query. Big maintained MediaWiki
# (Wikipedia/Fandom/Miraheze…) is the opposite — active human communities, provably clean — so
# the bare /wiki/ shape and those hosts are EXCLUDED. Targeting the class, not the whole web.
WIKI_URL = re.compile(
    r"https?://[a-z0-9.\-]+\.[a-z]{2,}/[^\s\"'<>)\]]*?"
    r"(?:wiki\.cgi|wiki\.pl|mb\.pl|/moin_?[a-z]*\.cgi|oddmuse\.pl|/cgi-bin/[^\s\"'<>)\]]*wiki)"
    r"[^\s\"'<>)\]]*", re.I)
HREF = re.compile(r"""href=["']([^"'<>]+)["']""", re.I)
PRIVATE = re.compile(r"(?:localhost|127\.|10\.|192\.168\.|::1)", re.I)
# big human-community wiki hosts — clean, zero agent-coordination signal, never a target
BLOCKLIST = re.compile(
    r"(?:wikipedia|wikimedia|wikidata|wikiquote|wiktionary|wikivoyage|wikisource|wikibooks|"
    r"wikinews|wikiversity|mediawiki\.org|semantic-mediawiki|fandom\.com|wikia\.|miraheze\.org|"
    r"wikihow|wikidot\.com|github|google|amazon|facebook|twitter|"
    # news / blog / corp / social — articles ABOUT agents are not habitats (content-verify noise)
    r"ycombinator|reddit|medium\.com|youtube|instagram|linkedin|ibm\.com|nvidia|unite\.ai|"
    r"arstechnica|fortune\.com|techcrunch|substack|googleblog|digitalapplied|ssonetwork|"
    r"re-cinq|library\.|\.edu/|researchguides)\b", re.I)


def engine_of(url):
    u = url.lower()
    if "wiki.cgi" in u or "mb.pl" in u:
        return "usemod/prowiki"
    if "wiki.pl" in u:
        return "usemod"
    if "moin" in u:
        return "moinmoin"
    if "oddmuse" in u:
        return "oddmuse"
    return "cgi-wiki"


def _fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(1_500_000).decode("utf-8", "replace")


def _norm(url):
    url = urllib.parse.urldefrag(url)[0].rstrip(".,);]}>\"'")
    if not url.lower().startswith(("http://", "https://")):
        return None
    host = urllib.parse.urlsplit(url).hostname or ""
    if not host or "." not in host or PRIVATE.search(host) or BLOCKLIST.search(url):
        return None  # drop private + big human-community wikis (clean, not targets)
    return url


def extract_wikis(html, base=None):
    """Wiki-shaped URLs from a page: direct matches + resolved hrefs that match the class."""
    out = set()
    for m in WIKI_URL.findall(html or ""):
        n = _norm(m)
        if n:
            out.add(n)
    for href in HREF.findall(html or ""):
        full = urllib.parse.urljoin(base, href) if base else href
        if WIKI_URL.match(full or ""):
            n = _norm(full)
            if n:
                out.add(n)
    return out


def _known_old_wiki_hubs():
    """Real old CGI wikis to seed interwiki expansion from (the class's actual ecosystem)."""
    hubs = ["http://www.usemod.com/cgi-bin/mb.pl?RecentChanges",
            "http://www.usemod.com/cgi-bin/wiki.pl?InterWiki",
            "https://communitywiki.org/wiki.pl?InterMap",
            "http://www.prowiki.org/prowiki/wiki.cgi?InterWiki",
            "http://www.dorfwiki.org/wiki.cgi?StartSeite",
            "http://www.schulwiki.org/wiki.cgi?StartSeite"]
    try:
        import traces
        for h in traces.KNOWN_HABITATS:
            u = h.get("recent") or h.get("url") or ""
            if "wiki.cgi" in u or "wiki.pl" in u:
                hubs.append(u)
    except Exception:  # noqa: BLE001
        pass
    return hubs


def harvest(max_urls=10000, interwiki_depth=2, use_cdx=False):
    """Harvest wiki surfaces from directories, then expand via each wiki's interwiki/RC pages."""
    found, notes = set(), []
    frontier = list(_known_old_wiki_hubs())  # start expansion from the real old-wiki ecosystem

    for d in DIRECTORIES:
        try:
            wikis = extract_wikis(_fetch(d), d)
            found |= wikis
            frontier += list(wikis)
            notes.append(f"{d.split('//')[1][:40]}: +{len(wikis)}")
        except Exception as e:  # noqa: BLE001
            notes.append(f"{d.split('//')[1][:40]}: skip ({type(e).__name__})")
        time.sleep(0.4)
        if len(found) >= max_urls:
            return list(found)[:max_urls], notes

    # interwiki expansion: fetch discovered wikis' hub pages for more cross-links
    for _ in range(interwiki_depth):
        nxt = []
        for url in frontier[:120]:
            if len(found) >= max_urls:
                break
            try:
                more = extract_wikis(_fetch(url), url)
                new = more - found
                found |= new
                nxt += list(new)
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.3)
        frontier = nxt
        if not frontier:
            break

    if use_cdx and len(found) < max_urls:
        found |= _cdx_augment({urllib.parse.urlsplit(u).hostname for u in list(found)[:50]},
                              max_urls - len(found))
    return list(found)[:max_urls], notes


def _cdx_augment(domains, budget):
    """Common Crawl CDX per DOMAIN (host-anchored = fast) to pull more wiki paths per host."""
    out = set()
    import json as _j
    for host in list(domains)[:50]:
        if not host or len(out) >= budget:
            break
        try:
            q = ("https://index.commoncrawl.org/CC-MAIN-2026-39-index?url="
                 + urllib.parse.quote(f"{host}/*") + "&output=json&limit=200&filter=url:.*(wiki\\.cgi|wiki\\.pl|action=).*")
            for line in _fetch(q, timeout=25).splitlines():
                try:
                    u = _norm(_j.loads(line).get("url", ""))
                    if u and WIKI_URL.match(u):
                        out.add(u)
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.6)
    return out


def persist(urls):
    store.init()
    conn = store.connect()
    conn.execute("CREATE TABLE IF NOT EXISTS wild_seeds (url TEXT PRIMARY KEY, engine TEXT, "
                 "ts REAL, status TEXT NOT NULL DEFAULT 'new')")
    for u in urls:
        conn.execute("INSERT OR IGNORE INTO wild_seeds (url, engine, ts, status) VALUES (?,?,?, 'new')",
                     (u, engine_of(u), time.time()))
    conn.commit()
    conn.close()


def main():
    ap = argparse.ArgumentParser(description="Harvest wild wiki/agent-habitat surfaces to a seed list")
    ap.add_argument("--max", type=int, default=10000)
    ap.add_argument("--cdx", action="store_true", help="augment via Common Crawl CDX per domain")
    ap.add_argument("--depth", type=int, default=1, help="interwiki expansion depth")
    args = ap.parse_args()

    urls, notes = harvest(args.max, args.depth, args.cdx)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(sorted(urls)) + ("\n" if urls else ""))
    persist(urls)

    print("source yield:")
    for n in notes:
        print("  " + n)
    from collections import Counter
    eng = Counter(engine_of(u) for u in urls)
    print(f"\nharvested {len(urls)} wild surfaces -> {OUT}")
    for e, c in eng.most_common():
        print(f"  {e:<16} {c}")
    print("next: feed these to the roamer (traverse --seeds data/seeds_wild.txt) with the "
          "agent-authored/strong-covert quality bar.")


if __name__ == "__main__":
    main()
