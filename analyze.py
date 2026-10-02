"""Analyze — edit-level discrimination: LIVE agents vs humans documenting the incident.

A page-text score conflates "agents posting now" with "humans writing about the swarm".
This parses the UseMod/ProWiki RecentChanges into individual edits and classifies each by
its AUTHOR, which is what actually distinguishes them:

  * author is an agent handle (XxxBot / XxxAssistant / …Swarm… / agent\\d+) -> AGENT
  * author is a bare IP                                                     -> ANON (maybe agent)
  * author is a named account (GretaMeadows, TomRiver, …)               -> HUMAN

Page names that are agent artefacts (ZZZ / Agent*) are counted separately as
"agent-artefact touches" — a human editing AgentZzz… is curation, not live agent activity.

Verdict per habitat: LIVE (agent/anon edits present in RecentChanges) vs DORMANT
(only humans, i.e. cleanup/documentation). UseMod/ProWiki engines only for now.

  python3 analyze.py                 # analyze the ProWiki/UseMod habitats
  python3 analyze.py --url <rc-url>  # one RecentChanges page
"""

import argparse
import html as htmllib
import re
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import behavior  # noqa: E402
import crawlers  # noqa: E402
import traces  # noqa: E402

UA = "fener-analyze/0.1 (read-only; +research)"

AGENT_AUTHOR = re.compile(r"(?:[A-Z][A-Za-z0-9]*(?:Bot|Assistant)|[A-Za-z]*Swarm[A-Za-z]*|agent[_-]?\d+)", re.I)
IP_AUTHOR = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
AGENT_PAGE = re.compile(r"(?:Zzz|ZZZ|AgentZzz|Heartbeat|Relay)", re.I)
AGENT_PAGE_NAME = re.compile(r"^(?:Agent\d|SandboxLLM|AgentZzz|ZZZ|Zzz)", re.I)
HUMAN_KNOWN = {"GretaMeadows", "TomRiver", "AnnaWells"}
STOP_PAGE_AUTHOR = {"RecentChanges", "action=browse", "(diff)", "(Diff)"}

GERMAN_MONTHS = {"januar": 1, "februar": 2, "märz": 3, "maerz": 3, "april": 4, "mai": 5,
                 "juni": 6, "juli": 7, "august": 8, "september": 9, "oktober": 10,
                 "november": 11, "dezember": 12}
DE_DATE = re.compile(r"(\d{1,2})\.\s*([A-Za-zäöü]+)\s*(\d{4})")
RECENT_DAYS = 21


def parse_de_date(s):
    if not s:
        return None
    m = DE_DATE.search(s)
    if not m:
        return None
    mon = GERMAN_MONTHS.get(m.group(2).lower())
    if not mon:
        return None
    try:
        from datetime import date
        return date(int(m.group(3)), mon, int(m.group(1)))
    except ValueError:
        return None


MW_AUTHOR = re.compile(r'(?:Special:Contributions/|User:)([^"&?/]+)')
MW_MARKER = re.compile(r"mw-changeslist|Special:RecentChanges|MediaWiki", re.I)
LI = re.compile(r"<li>(.*?)</li>", re.S)
LINK = re.compile(r"wiki\.(?:cgi|pl)\?(?:[^']*?id=)?([^'&]+)'[^>]*class='body'[^>]*>([^<]+)</a>")
TIME_RE = re.compile(r"\b(\d{1,2}:\d{2})\b")
DATE_HDR = re.compile(r"<strong>([^<]*\d{4})</strong>")


def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(800_000).decode("utf-8", "replace")


SEP = re.compile(r"\.\s\.\s\.\s\.\s\.")


def _epoch(date_obj, li_text):
    """Combine a parsed date with an HH:MM found in the entry text into UTC epoch seconds.

    Used only for cadence analysis (inter-edit gaps, hour-of-day coverage), which is
    timezone-invariant for the signals we compute, so treating the wiki's local time as UTC
    is fine. Returns None when no date is available.
    """
    if not date_obj:
        return None
    import calendar
    m = TIME_RE.search(li_text or "")
    hh, mm = (int(x) for x in m.group(1).split(":")) if m else (0, 0)
    try:
        return calendar.timegm((date_obj.year, date_obj.month, date_obj.day, hh, mm, 0, 0, 0, 0))
    except Exception:  # noqa: BLE001
        return None


def parse_edits_rich(html):
    """Yield rich per-edit records: {date, page, author, text, epoch}.

    UseMod entry: "(diff) PageLink TIME [tag] . . . . . Author". The author after the
    dotted separator may be a wiki link (named account) OR a bare IP (anonymous / agent
    egress). Capturing the IP author is essential — the live ProbierWiki agents edit as
    AWS IPs, not named accounts. `text` (the flattened entry) and `epoch` feed content
    stylometry and cadence scoring; date drives recency.
    """
    edits = []
    current_date = None
    tokens = sorted(
        [(m.start(), "date", m.group(1)) for m in DATE_HDR.finditer(html)]
        + [(m.start(), "li", m.group(1)) for m in LI.finditer(html)]
    )
    for _, kind, payload in tokens:
        if kind == "date":
            current_date = htmllib.unescape(payload).strip()
            continue
        links = [(htmllib.unescape(pid), htmllib.unescape(name).strip())
                 for pid, name in LINK.findall(payload)]
        links = [(pid, nm) for pid, nm in links if nm not in STOP_PAGE_AUTHOR and "action=" not in pid]
        if not links:
            continue
        page = links[0][1]
        text = htmllib.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", payload)))
        parts = SEP.split(text)
        author = parts[-1].strip().split()[0] if len(parts) > 1 and parts[-1].strip() else (
            links[-1][1] if len(links) > 1 else "")
        edits.append({"date": current_date, "page": page, "author": author,
                      "text": text, "epoch": _epoch(parse_de_date(current_date), text)})
    return edits


def parse_edits(html):
    """Back-compat 3-tuple projection (date, page, author) used by traverse.wiki_counts."""
    return [(r["date"], r["page"], r["author"]) for r in parse_edits_rich(html)]


def parse_edits_mediawiki_rich(html):
    """MediaWiki Special:RecentChanges: authors from Contributions/User links (rich shape).

    MediaWiki RC lacks the inline edit text UseMod gives us, so content/epoch stay empty;
    the win here is clean_username repair + the maintenance-bot allowlist downstream.
    """
    import urllib.parse
    out = []
    for a in MW_AUTHOR.findall(html):
        author = urllib.parse.unquote(a).replace("_", " ").strip()
        out.append({"date": None, "page": "", "author": author, "text": "", "epoch": None})
    return out


def parse_edits_mediawiki(html):
    """Back-compat 3-tuple projection for MediaWiki RC."""
    return [(r["date"], r["page"], r["author"]) for r in parse_edits_mediawiki_rich(html)]


def classify_author(author, page):
    """Cheap name/IP classification (no content/cadence) for traverse.wiki_counts.

    Now clean_username-repaired and maintenance-bot-aware, so a ...RenameBot no longer
    inflates the agent count. The full behavioural scorer runs in analyze() below.
    """
    author = behavior.clean_username(author)
    if not author:
        return "human"  # parse artefact / non-name -> never an agent
    if IP_AUTHOR.match(author):
        return "crawler" if crawlers.is_crawler(author) else "anon"
    if behavior.is_maintenance_bot(author):
        return "maintenance"
    if author in HUMAN_KNOWN:
        return "human"
    if AGENT_AUTHOR.fullmatch(author) or AGENT_AUTHOR.match(author):
        return "agent"
    return "human"  # a named registered account


def analyze(name, url):
    try:
        html = fetch(url)
    except Exception as e:  # noqa: BLE001
        return {"habitat": name, "error": type(e).__name__}
    if "Special:RecentChanges" in url or MW_MARKER.search(html[:4000]):
        rich = parse_edits_mediawiki_rich(html)
    else:
        rich = parse_edits_rich(html)
    # repair parse artefacts (markup / bot self-descriptions captured as usernames), drop non-names
    for r in rich:
        r["author"] = behavior.clean_username(r["author"])
    rich = [r for r in rich if r["author"]]

    # aggregate per author, then classify each author ONCE with its content + cadence
    from collections import defaultdict
    times_by, text_by = defaultdict(list), defaultdict(list)
    for r in rich:
        if r["epoch"]:
            times_by[r["author"]].append(r["epoch"])
        if r["text"]:
            text_by[r["author"]].append(r["text"])
    author_cls, author_reasons = {}, {}
    for author in {r["author"] for r in rich}:
        is_crawl = bool(IP_AUTHOR.match(author)) and crawlers.is_crawler(author)
        content_sample = " ".join(text_by[author][:6])[:2000]
        cls, reasons = behavior.classify(author, "", content_sample, times_by[author], is_crawl)
        if author in HUMAN_KNOWN and cls == "human":
            reasons = ["known human account"]
        author_cls[author], author_reasons[author] = cls, reasons

    from datetime import date as _date
    today = _date.today()
    # per-author recency + last-seen, so the fused census can tell a LIVE agent from an archived
    # footprint and promote a name-only candidate once its edits carry content/cadence evidence.
    recent_by, last_by = defaultdict(bool), {}
    for r in rich:
        dt = parse_de_date(r["date"])
        if dt:
            last_by[r["author"]] = dt if r["author"] not in last_by else max(last_by[r["author"]], dt)
            if (today - dt).days <= RECENT_DAYS:
                recent_by[r["author"]] = True
    counts = {"agent": 0, "anon": 0, "human": 0, "crawler": 0, "maintenance": 0}
    agent_authors, artefact_pages = set(), set()
    agent_evidence = {}
    recent_agent = 0
    last_agent = None
    for r in rich:
        author, page = r["author"], r["page"]
        cls = author_cls[author]
        # a bare IP editing an agent-artefact page (AgentZzz…) is the agent itself
        if AGENT_PAGE_NAME.match(page) and cls == "anon":
            cls = "agent"
        counts[cls] += 1
        dt = parse_de_date(r["date"])
        if cls == "agent":
            agent_authors.add(author)
            agent_evidence.setdefault(author, author_reasons.get(author, []))
            if dt:
                last_agent = dt if last_agent is None else max(last_agent, dt)
                if (today - dt).days <= RECENT_DAYS:
                    recent_agent += 1
        if AGENT_PAGE.search(page):
            artefact_pages.add(page)
    if recent_agent > 0:
        verdict = "LIVE-AGENTS"
    elif counts["agent"] > 0:
        verdict = "agent-footprint (archived)"
    elif rich:
        verdict = "dormant/human-cleanup"
    else:
        verdict = "no-edits"
    crawlers.flush()
    # Per-author signal: classification + the WHY (name vs content-stylometry vs machine-cadence)
    # + recency. This is what lets fuse.py promote a name-only candidate to a corroborated finding.
    author_signals = {
        a: {"cls": author_cls[a], "reasons": author_reasons.get(a, []),
            "recent": bool(recent_by.get(a)),
            "last": last_by.get(a).isoformat() if last_by.get(a) else None}
        for a in author_cls
    }
    # which agent authored which page — feeds page-level coordination-cell detection
    page_authors = defaultdict(set)
    for r in rich:
        if r["page"] and author_cls.get(r["author"]) == "agent":
            page_authors[r["page"]].add(r["author"])
    return {
        "habitat": name, "url": url, "edits": len(rich), **counts,
        "recent_agent": recent_agent, "last_agent": last_agent.isoformat() if last_agent else None,
        "verdict": verdict,
        "agent_authors": sorted(agent_authors), "artefact_pages": sorted(artefact_pages),
        "agent_evidence": agent_evidence, "author_signals": author_signals,
        "page_authors": {p: sorted(a) for p, a in page_authors.items()},
    }


def main():
    ap = argparse.ArgumentParser(description="Edit-level live-agent vs human discrimination")
    ap.add_argument("--url", help="one RecentChanges URL")
    args = ap.parse_args()

    targets = ([{"name": args.url, "recent": args.url}] if args.url
               else [h for h in traces.KNOWN_HABITATS if "wiki.cgi" in (h.get("recent") or "") or "wiki.pl" in (h.get("recent") or "")])

    print(f"{'habitat':<24}{'edits':>6}{'agent':>6}{'maint':>6}{'crawl':>6}{'anon':>5}{'human':>6}  verdict")
    for i, h in enumerate(targets):
        r = analyze(h["name"], h.get("recent") or h["url"])
        if r.get("error"):
            print(f"{r['habitat']:<24}  error: {r['error']}")
            continue
        print(f"{r['habitat']:<24}{r['edits']:>6}{r['agent']:>6}{r.get('maintenance',0):>6}"
              f"{r.get('crawler',0):>6}{r['anon']:>5}{r['human']:>6}  {r['verdict']}")
        if r["agent_authors"]:
            print(f"    agent authors: {', '.join(r['agent_authors'][:8])}")
        for a, why in list(r.get("agent_evidence", {}).items())[:3]:
            if why:
                print(f"      why {a}: {why[0]}")
        if r["artefact_pages"]:
            print(f"    agent-artefact pages touched: {', '.join(r['artefact_pages'][:6])}")
        if i < len(targets) - 1:
            time.sleep(1.5)


if __name__ == "__main__":
    main()
