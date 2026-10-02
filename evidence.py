"""Evidence — fetch the actual page text a LIVE candidate edited, and score its stylometry.

The census identifies candidates from RecentChanges summary lines (name + recency). That is
circumstantial. This closes the loop: for a LIVE agent candidate, it pulls the PAGES that
handle actually edited and scores their CONTENT with behavior.content_score (LLM-tells: "as an
AI", refusal boilerplate, system-prompt leakage, machine markdown + covert markers). Content
that writes like an agent promotes the candidate from name-only to a corroborated finding;
content that does not keeps it honest at candidate. Read-only, bounded, polite.

  python3 evidence.py <rc_url> <author>   # score one author's edited-page content
  python3 evidence.py --enrich            # enrich every LIVE candidate in the live census
"""

import argparse
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path

os.environ.setdefault("FENER_DB", str(Path(__file__).parent / "data" / "live.sqlite3"))
sys.path.insert(0, str(Path(__file__).parent))
import analyze  # noqa: E402
import behavior  # noqa: E402
import store  # noqa: E402
import traces  # noqa: E402


def _habitat_rc(name):
    for h in traces.KNOWN_HABITATS:
        if h["name"] == name:
            return h.get("recent") or h["url"]
    return None


def page_raw_url(rc_url, page):
    """UseMod/ProWiki raw-text view of a page, built from the RecentChanges base URL."""
    base = rc_url.split("?")[0]
    return f"{base}?action=browse&id={urllib.parse.quote(page)}&raw=1"


def _text_of(html):
    """Return raw text; if the response is a rendered HTML page, strip the chrome to body text."""
    if "<html" in html[:400].lower() or "<!doctype" in html[:400].lower():
        return " ".join(re.sub(r"<[^>]+>", " ", html).split())
    return " ".join(html.split())


def fetch_author_content(rc_url, author, max_pages=5):
    """Pages (names) the author edited in RecentChanges, plus the concatenated page text."""
    try:
        rc = analyze.fetch(rc_url)
    except Exception:  # noqa: BLE001
        return "", []
    pages, seen = [], set()
    for e in analyze.parse_edits_rich(rc):
        a = behavior.clean_username(e["author"])
        if a == author and e["page"] and e["page"] not in seen:
            seen.add(e["page"])
            pages.append(e["page"])
        if len(pages) >= max_pages:
            break
    texts = []
    for p in pages:
        try:
            texts.append(_text_of(analyze.fetch(page_raw_url(rc_url, p)))[:3000])
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.8)
    return "\n".join(texts), pages


def score_author(rc_url, author):
    content, pages = fetch_author_content(rc_url, author)
    sc, hits = behavior.content_score(content, markdown_native=False) if content else (0, [])
    return {"score": sc, "signals": [h["signal"] for h in hits], "pages": pages,
            "chars": len(content)}


def enrich_live(conn, max_authors=6):
    """For each LIVE agent candidate, fetch + score its edited-page content and store the
    resulting author_signal (with a real content-stylometry reason if it trips LLM-tells), so
    the next fuse run reflects the content evidence."""
    import fuse
    dossiers, _ = fuse.build_dossiers(conn)
    live = [d for d in dossiers if d["recent"] and d["classification"] == "agent"][:max_authors]
    out = []
    for d in live:
        surface = next((s for s in d["surfaces"] if _habitat_rc(s)), None)
        if not surface:
            continue
        res = score_author(_habitat_rc(surface), d["identity"])
        if res["score"]:
            reasons = [f"content evidence {res['score']} ({', '.join(res['signals'][:2])})"]
        else:
            reasons = [f"fetched {len(res['pages'])} edited page(s), no LLM-tell in content"]
        store.add_author_signal(conn, surface, d["identity"], "agent", True, d.get("last_seen"),
                                reasons)
        out.append({"author": d["identity"], "surface": surface, **res,
                    "promoted": bool(res["score"])})
    return out


def main():
    ap = argparse.ArgumentParser(description="Fetch + score a candidate's edited-page content")
    ap.add_argument("rc_url", nargs="?")
    ap.add_argument("author", nargs="?")
    ap.add_argument("--enrich", action="store_true", help="enrich all LIVE census candidates")
    args = ap.parse_args()
    store.init()
    conn = store.connect()
    if args.enrich:
        rows = enrich_live(conn)
        conn.close()
        if not rows:
            print("no LIVE agent candidates to enrich.")
            return
        for r in rows:
            tag = "PROMOTED (writes like an agent)" if r["promoted"] else "no LLM-tell"
            print(f"[{tag:<32}] {r['author']} @ {r['surface']}  "
                  f"stylometry={r['score']} pages={len(r['pages'])} chars={r['chars']}")
            if r["signals"]:
                print(f"        signals: {', '.join(r['signals'][:4])}")
        return
    conn.close()
    if not (args.rc_url and args.author):
        print(__doc__)
        return
    res = score_author(args.rc_url, args.author)
    print(f"{args.author}: stylometry={res['score']} chars={res['chars']} "
          f"pages={res['pages']}")
    print(f"signals: {res['signals'] or '(none — no LLM-tell in fetched content)'}")


if __name__ == "__main__":
    main()
