"""Search discovery — web-wide enumeration of the writable agent-habitat class via a search API.

The wiki federation is small and fully mapped; the open web's scattered GET-writable surfaces
(old CGI wikis worldwide, open guestbooks, writable comment/paste scripts) are NOT reachable by
interwiki expansion — they need a search engine. This runs dork queries (inurl: patterns that
match the writable class) through a search API, filters hits to the habitat class, and appends
them to the SAME seed list the roamer consumes (data/seeds_wild.txt + wild_seeds). Provider-
agnostic: Brave Search or Serper (Google), key read from ~/fener/.env — no key, no-op with a note.

  python3 search_discover.py              # run all dorks, append new habitat URLs to the seed list
  python3 search_discover.py --max 400    # cap results harvested

Get a free key, then put ONE of these in ~/fener/.env:
  BRAVE_SEARCH_API_KEY=...   (free tier ~2000 q/mo — https://brave.com/search/api/)
  SERPER_API_KEY=...         (free credits — https://serper.dev/)
"""

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import discover_wild  # noqa: E402  (reuse _norm, BLOCKLIST, engine_of, persist, OUT)
import store  # noqa: E402
import re  # noqa: E402

# Brave ignores Google-style inurl: — it gets CONTENT-phrase dorks (engine footprints + agent
# vocabulary). Serper is Google: it gets the powerful inurl: dorks that pin the writable class
# by URL, which is far higher-yield. harvest() picks the set by provider.
CONTENT_DORKS = [
    '"powered by UseModWiki"', '"powered by Oddmuse"', '"Powered by MoinMoin"',
    '"powered by PmWiki"', '"Edit this page" "View other revisions"',
    '"last edited" "RecentChanges" wiki.cgi', 'WikkaWiki "edit page"',
    '"sign my guestbook" cgi', '"Please sign the guestbook"',
    '"AgenticCommunication"', '"OpenAgentChat"', '"wiki for agent notes"',
    '"claude-desk-doctrine"', 'agentic wiki "RecentChanges" agent',
]
# Serper FREE blocks operator/quoted patterns ("Query pattern not allowed for free accounts"),
# so these are PLAIN keyword queries (no inurl:/quotes). Results are mixed (real installs +
# news), so harvest relies on HABITAT_URL + content-verify to keep the habitat class. (Paid
# Serper would take real inurl: dorks — swap this set then.)
SERPER_PLAIN = [
    'powered by UseModWiki RecentChanges',
    'powered by Oddmuse wiki RecentChanges',
    'powered by MoinMoin FrontPage RecentChanges',
    'wiki cgi RecentChanges edit this page',
    'open guestbook cgi sign my guestbook',
    'agent message board wiki cgi',
    'public wiki discussions for AI agents',
    'OpenAgentChat agents commons wiki',
    'AgenticCommunication wiki agent notes',
    'autonomous agents coordination wiki cgi RecentChanges',
    'wakka wiki edit page RecentChanges',
    'pmwiki RecentChanges action edit',
]
DORKS = CONTENT_DORKS  # back-compat default (Brave)

# Writable-habitat URL class for results (wider than discover_wild's wiki-only shape: adds
# guestbooks / writable CGI / lightweight-wiki engines / index.cgi-style UseMod installs).
# BLOCKLIST (big MediaWiki) still applies via discover_wild._norm.
HABITAT_URL = re.compile(
    r"(?:wiki\.cgi|wiki\.pl|mb\.pl|index\.cgi|wakka\.php|pmwiki\.php|moin\.?[a-z]*\.cgi|oddmuse|"
    r"guestbook\.(?:cgi|pl|php)|gbook\.(?:cgi|php)|tagboard|shoutbox|\.(?:cgi|pl)\?action=|"
    r"/cgi-bin/[^\s]*(?:wiki|book))",
    re.I)


def _env_key(name):
    v = os.environ.get(name)
    if v:
        return v
    try:
        for line in (Path(__file__).parent / ".env").read_text().splitlines():
            line = line.strip()
            if line.startswith(name + "=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return None


def _provider():
    # Prefer Serper (Google): it supports inurl: dorks + a far larger index than Brave.
    if _env_key("SERPER_API_KEY"):
        return "serper"
    if _env_key("BRAVE_SEARCH_API_KEY"):
        return "brave"
    return None


def search(query, provider, count=20):
    """Return result URLs for one query from the configured provider. [] on error."""
    try:
        if provider == "brave":
            url = ("https://api.search.brave.com/res/v1/web/search?q="
                   + urllib.parse.quote(query) + f"&count={count}")
            req = urllib.request.Request(url, headers={
                "Accept": "application/json", "X-Subscription-Token": _env_key("BRAVE_SEARCH_API_KEY")})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
            return [x.get("url") for x in data.get("web", {}).get("results", []) if x.get("url")]
        if provider == "serper":
            body = json.dumps({"q": query, "num": count}).encode()
            for attempt in range(3):
                try:
                    req = urllib.request.Request("https://google.serper.dev/search", data=body,
                        headers={"X-API-KEY": _env_key("SERPER_API_KEY"),
                                 "Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=20) as r:
                        data = json.loads(r.read())
                    return [x.get("link") for x in data.get("organic", []) if x.get("link")]
                except urllib.error.HTTPError as e:
                    if e.code == 429 and attempt < 2:
                        time.sleep(3 * (attempt + 1)); continue
                    raise
    except Exception as e:  # noqa: BLE001
        print(f"  search error ({query[:30]}): {type(e).__name__}")
    return []


def _content_is_habitat(url):
    """Fetch a non-URL-matching hit and keep it if its CONTENT is an agent-coordination venue
    (e.g. openagentchat.net: 'Public Wiki and Discussions for AI Agents') or a covert dead-drop.
    This catches agent platforms whose URL is not wiki-shaped, which the vocab dorks surface."""
    import behavior
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "fener-discover/0.1 (+research)"})
        with urllib.request.urlopen(req, timeout=15) as r:
            html = r.read(200_000).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return False
    cs, _ = behavior.content_score(html, markdown_native=False)
    import covert
    return cs >= 6 or covert.has_strong(covert.scan(html)[1])


def harvest(max_urls=400, content_verify_cap=20):
    provider = _provider()
    if not provider:
        return None, []
    dorks = SERPER_PLAIN if provider == "serper" else CONTENT_DORKS
    count = 20
    found, verified = set(), 0
    for q in dorks:
        for u in search(q, provider, count=count):
            n = discover_wild._norm(u)  # http(s), public host, not blocklisted
            if not n:
                continue
            if HABITAT_URL.search(n):
                found.add(n)
            elif verified < content_verify_cap and _content_is_habitat(n):
                found.add(n)  # agent-coordination venue confirmed by its content, any URL shape
                verified += 1
        if len(found) >= max_urls:
            break
        time.sleep(1.1)  # polite under free-tier rate limits
    return provider, sorted(found)[:max_urls]


def main():
    ap = argparse.ArgumentParser(description="Web-wide habitat discovery via a search API")
    ap.add_argument("--max", type=int, default=400)
    args = ap.parse_args()
    provider, urls = harvest(args.max)
    if provider is None:
        print("no search key found. Put BRAVE_SEARCH_API_KEY=... (free: brave.com/search/api) "
              "or SERPER_API_KEY=... (serper.dev) in ~/fener/.env, then re-run.")
        return
    # merge into the existing seed list the roamer consumes
    existing = set()
    if discover_wild.OUT.exists():
        existing = {l.strip() for l in discover_wild.OUT.read_text().splitlines() if l.strip()}
    merged = sorted(existing | set(urls))
    discover_wild.OUT.write_text("\n".join(merged) + ("\n" if merged else ""))
    discover_wild.persist(urls)
    new = len(set(urls) - existing)
    print(f"provider={provider}: {len(urls)} habitat URLs matched ({new} NEW), "
          f"seed list now {len(merged)} -> {discover_wild.OUT}")
    from collections import Counter
    for e, c in Counter(discover_wild.engine_of(u) for u in urls).most_common():
        print(f"  {e:<16} {c}")
    print("next: python3 -c 'roam wild_seeds with the quality bar' (Phase-2 style)")


if __name__ == "__main__":
    main()
