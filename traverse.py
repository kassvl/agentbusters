"""Traverse — the released, GPS-tagged scout that walks the agent-habitat network.

The honeypot waits and the hunter sweeps a fixed map; this scout is set loose from seed
habitats and FOLLOWS the breadcrumbs agents leave — interwiki links, other wiki.cgi/pl
surfaces, full URLs on agent pages, inter-agent tunnels (pinggy.io / localhost.run / …)
and link shorteners — recording the exact path it takes. One run = one GPS track, saved
to the `traversal` table. It reports where it went and any NEW habitat it discovered whose
agent traces survive the crawler filter (so Amazonbot is not mistaken for a swarm).

Strictly read-only and polite: robots.txt respected, rate-limited, bounded depth + fetch
budget, honest research UA. It never writes, edits, joins or impersonates anything.

  python3 traverse.py                       # walk from the live wiki habitats
  python3 traverse.py --depth 2 --budget 40 --delay 1.5
  python3 traverse.py --seeds urls.txt      # walk from your own seed URLs
"""

import argparse
import html as htmllib
import re
import sys
import time
import uuid
import urllib.request
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

sys.path.insert(0, str(Path(__file__).parent))
import analyze  # noqa: E402
import covert  # noqa: E402
import crawlers  # noqa: E402
import store  # noqa: E402
import traces  # noqa: E402

UA = "fener-traverse/0.1 (read-only agent-habitat reconnaissance; +research)"

ABS_URL = re.compile(r"https?://[^\s\"'<>)]+", re.I)
HREF = re.compile(r"href=['\"]([^'\"]+)['\"]", re.I)
TUNNEL = re.compile(r"\b[\w.-]+\.(?:pinggy\.io|localhost\.run|ngrok\.io|serveo\.net)\b", re.I)
ASSET = re.compile(r"\.(?:css|js|png|jpe?g|gif|ico|svg|woff2?|ttf|zip|pdf|mp4|webp)(?:$|\?)", re.I)


def robots_ok(url):
    try:
        p = urlparse(url)
        rp = RobotFileParser()
        rp.set_url(f"{p.scheme}://{p.netloc}/robots.txt")
        rp.read()
        return rp.can_fetch(UA, url)
    except Exception:  # noqa: BLE001
        return True  # robots unreachable -> a single polite fetch is acceptable


def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        ctype = r.headers.get("Content-Type", "")
        if not any(t in ctype for t in ("html", "text", "xml", "json")) and ctype:
            return None
        return r.read(800_000).decode("utf-8", "replace")


def base_of(url):
    """Identity of a surface: scheme+host+path, query and fragment dropped, slash-trimmed."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc.lower()}{p.path.rstrip('/')}"


def known_bases():
    bases = set()
    for h in traces.KNOWN_HABITATS:
        for u in (h.get("url"), h.get("recent")):
            if u:
                bases.add(base_of(u))
    return bases


def wiki_counts(html, url):
    """(counts, n_edits) using analyze's crawler-filtered classification on prefetched html."""
    if "Special:RecentChanges" in url or analyze.MW_MARKER.search(html[:4000]):
        edits = analyze.parse_edits_mediawiki(html)
    else:
        edits = analyze.parse_edits(html)
    c = {"agent": 0, "anon": 0, "human": 0, "crawler": 0, "maintenance": 0}
    for d, page, author in edits:
        cls = analyze.classify_author(author, page)
        if analyze.AGENT_PAGE_NAME.match(page) and cls == "anon":
            cls = "agent"
        c[cls] += 1
    return c, len(edits)


def breadcrumbs(html, base_url):
    """Followable outbound links: interwiki / other wiki surfaces / URLs / tunnels."""
    found = set()
    for m in HREF.findall(html):
        if m.startswith(("mailto:", "javascript:", "#")):
            continue
        found.add(urljoin(base_url, htmllib.unescape(m)))
    for m in ABS_URL.findall(html):
        found.add(htmllib.unescape(m).rstrip(".,);'\""))
    for m in TUNNEL.findall(html):
        found.add("https://" + m)

    here = urlparse(base_url).netloc.lower()
    ranked = []
    for u in found:
        if ASSET.search(u):
            continue
        p = urlparse(u)
        if p.scheme not in ("http", "https") or not p.netloc:
            continue
        cross = p.netloc.lower() != here
        habitat_shaped = bool(traces.looks_like_habitat(u))
        tunnel = bool(TUNNEL.search(u))
        if not (cross or habitat_shaped or tunnel):
            continue  # same-host, non-habitat nav is noise
        # rank: tunnels first, then cross-host habitat-shaped, then cross-host, then rest
        rank = (0 if tunnel else 1 if (cross and habitat_shaped) else 2 if cross else 3)
        ranked.append((rank, u))
    ranked.sort()
    # dedupe by surface identity, preserve rank order
    seen, out = set(), []
    for _, u in ranked:
        b = base_of(u)
        if b not in seen:
            seen.add(b)
            out.append(u)
    return out


def kind_of(url):
    if TUNNEL.search(url):
        return "tunnel"
    if traces.looks_like_habitat(url):
        return "habitat-shaped"
    return "link"


def traverse(seeds, depth=2, budget=40, delay=1.5, child_cap=8):
    run_id = uuid.uuid4().hex[:12]
    known = known_bases()
    conn = store.connect()
    store.init()

    visited = set()
    queue = deque((s, None, 0) for s in seeds)
    track = []
    fetches = 0

    while queue and fetches < budget:
        url, parent, d = queue.popleft()
        b = base_of(url)
        if b in visited:
            continue
        visited.add(b)

        row = {"url": url, "parent": parent, "depth": d, "score": 0, "agent": 0,
               "crawler": 0, "is_new": b not in known, "note": kind_of(url)}
        if not robots_ok(url):
            row["note"] += "; robots-disallow"
            _record(conn, run_id, row)
            track.append(row)
            continue
        try:
            html = fetch(url)
            fetches += 1
        except Exception as e:  # noqa: BLE001
            row["note"] += f"; error:{type(e).__name__}"
            _record(conn, run_id, row)
            track.append(row)
            continue
        if html is None:
            row["note"] += "; non-text"
            _record(conn, run_id, row)
            track.append(row)
            continue

        score, _hits = traces.scan(html)
        row["score"] = score
        if "wiki.cgi" in url or "wiki.pl" in url or "Special:RecentChanges" in url:
            counts, _n = wiki_counts(html, url)
            row["agent"] = counts["agent"]
            row["crawler"] = counts["crawler"]
        cov, _c = covert.scan(html)  # every walked surface is also scored for covert dead-drops
        if cov >= 6:
            row["note"] += f"; COVERT:{cov}"
        _record(conn, run_id, row)
        track.append(row)

        if d < depth:
            for child in breadcrumbs(html, url)[:child_cap]:
                if base_of(child) not in visited:
                    queue.append((child, url, d + 1))
        time.sleep(delay)

    crawlers.flush()
    conn.close()
    return run_id, track


def _record(conn, run_id, row):
    store.add_traversal(conn, run_id, row["parent"], row["url"], row["depth"],
                        row["score"], row["agent"], row["crawler"], row["is_new"], row["note"])


def seed_urls():
    """Live wiki habitats make the richest starting points for breadcrumbs."""
    out = []
    for h in traces.KNOWN_HABITATS:
        u = h.get("recent") or h["url"]
        if "wiki.cgi" in u or "wiki.pl" in u:
            out.append(u)
    return out


def main():
    ap = argparse.ArgumentParser(description="Release the GPS-tagged traversal scout")
    ap.add_argument("--seeds", help="file of seed URLs (one per line); default = live wiki habitats")
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--budget", type=int, default=40, help="max fetches for the whole walk")
    ap.add_argument("--delay", type=float, default=1.5)
    args = ap.parse_args()

    if args.seeds:
        seeds = [ln.strip() for ln in Path(args.seeds).read_text().splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
    else:
        seeds = seed_urls()

    print(f"releasing traversal scout from {len(seeds)} seeds "
          f"(depth {args.depth}, budget {args.budget})\n")
    run_id, track = traverse(seeds, args.depth, args.budget, args.delay)

    print("GPS TRACK (where the scout went):")
    for r in track:
        flag = "NEW" if r["is_new"] else "   "
        mark = " *AGENTS*" if r["agent"] > 0 else ""
        indent = "  " * r["depth"]
        host = urlparse(r["url"]).netloc + urlparse(r["url"]).path
        print(f"  {flag} d{r['depth']} {indent}{host[:60]:<60} "
              f"score={r['score']:<3} agent={r['agent']} crawl={r['crawler']} [{r['note']}]{mark}")

    news = [r for r in track if r["is_new"] and "error" not in r["note"] and "robots" not in r["note"]]
    agent_news = [r for r in news if r["agent"] > 0]
    print(f"\nrun {run_id}: visited {len(track)} surfaces, {len(news)} NEW, "
          f"{len(agent_news)} new with crawler-filtered agent traces")
    for r in agent_news:
        print(f"  DISCOVERY: {r['url']}  agent={r['agent']} (crawler={r['crawler']})")
    if not agent_news:
        print("  (no new habitat with real agent activity this walk — honest negative)")


if __name__ == "__main__":
    main()
