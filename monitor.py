"""Monitor — one early-warning sweep, cron/launchd-friendly.

Sweeps every mapped habitat, scores text traces AND (for wikis) counts LIVE agent edits,
writes to the same DB the dashboard reads, and alerts ONLY when live-agent activity is NEW
or has INCREASED since the previous sweep — human documentation never triggers an alert.

launchd runs this every 30 min; the running dashboard reflects it. Read-only, polite.

  python3 monitor.py                       # one sweep against data/live.sqlite3
  FENER_DB=data/live.sqlite3 python3 monitor.py
"""

import hashlib
import os
import sys
import time
import urllib.request
from pathlib import Path

os.environ.setdefault("FENER_DB", str(Path(__file__).parent / "data" / "live.sqlite3"))
sys.path.insert(0, str(Path(__file__).parent))
import analyze  # noqa: E402
import collectors  # noqa: E402
import correlate  # noqa: E402
import covert  # noqa: E402
import covert_hunt  # noqa: E402
import discover  # noqa: E402
import store  # noqa: E402
import traces  # noqa: E402
import traverse  # noqa: E402

FARM_HUBS = [  # wiki-farm hubs to enumerate for sibling GET-writable wikis (more surfaces)
    "https://prowiki.org/prowiki/wiki.cgi",
    "https://www.wikiservice.at/prowiki/wiki.cgi",
    "http://www.dorfwiki.org/wiki.cgi",
]

UA = "fener-monitor/0.1 (read-only agent-habitat early-warning; +research)"
ALERTS = Path(__file__).parent / "data" / "alerts.log"
ARMIES_SEEN = Path(__file__).parent / "data" / "armies_seen.json"


def alert(text):
    ALERTS.parent.mkdir(parents=True, exist_ok=True)
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}  {text}"
    with ALERTS.open("a") as f:
        f.write(line + "\n")
    print("! ALERT " + text)
    _gui_notify(text[:170])


def _gui_notify(text):
    """Opt-in desktop notification (FENER_GUI_NOTIFY=1), via terminal-notifier only. NEVER via
    `osascript display notification`: macOS posts that under Script Editor's identity and LAUNCHES
    Script Editor, which spammed the desktop every sweep. Log-only by default."""
    if os.environ.get("FENER_GUI_NOTIFY") != "1":
        return
    try:
        import shutil
        import subprocess
        tn = shutil.which("terminal-notifier")
        if tn:
            subprocess.run([tn, "-title", "Fener early-warning", "-message", text],
                           capture_output=True, timeout=5)
    except Exception:  # noqa: BLE001
        pass


def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(800_000).decode("utf-8", "replace")


def collector_sweep(conn):
    """The cross-surface half nobody runs continuously: sweep gists/npm/PyPI/HF (models,
    datasets, cards, fingerprint search) with the one shared covert fingerprint, and alert only
    on a NEW dead-drop id (one not already in the sightings ledger). This is what catches the
    NEXT HuggingFace-style drop as it appears, instead of after an incident is disclosed."""
    existing = {r["habitat"] for r in conn.execute(
        "SELECT DISTINCT habitat FROM sightings WHERE source='collector'")}
    new_finds = 0
    for surface, fn in collectors.COLLECTORS.items():
        try:
            finds, note = fn()
        except Exception as e:  # noqa: BLE001  (one surface failing must not sink the sweep)
            print(f"[{surface:<12}] error: {type(e).__name__}")
            continue
        for f in finds:
            if f["id"] not in existing:
                alert(f"NEW dead-drop on {surface}: {f['id']} (score {f['score']}) {f['url']}")
                new_finds += 1
        collectors.persist(conn, finds)
        print(f"[{surface:<12}] {note}; {len(finds)} flagged")
    return new_finds


def wide_seeds(conn):
    """A wide starting set: the known wiki habitats + every sibling wiki a farm hub lists +
    every wiki surface the scout has already discovered (a feedback loop that compounds reach).
    All deterministic enumeration — no LLM."""
    seeds = list(traverse.seed_urls())
    for hub in FARM_HUBS:
        try:
            seeds += list(discover.farm(hub))
        except Exception:  # noqa: BLE001
            pass
    for r in conn.execute("SELECT DISTINCT url FROM sightings WHERE source='scout'"):
        u = r["url"]
        if "wiki.cgi" in u or "wiki.pl" in u:
            seeds.append(u)
    # web-wide finds from search_discover / discover_wild feed the continuous roam too
    try:
        for r in conn.execute("SELECT url FROM wild_seeds"):
            u = r["url"]
            if any(x in u for x in ("wiki.cgi", "wiki.pl", "index.cgi", "pmwiki.php", "wakka.php")):
                seeds.append(u)
    except Exception:  # noqa: BLE001  (wild_seeds may not exist yet)
        pass
    seen, uniq = set(), []
    for u in seeds:
        b = traverse.base_of(u)
        if b not in seen:
            seen.add(b)
            uniq.append(u)
    return uniq


def scout_roam(conn, budget=45):
    """Fener as a continuously-roaming scout — deterministic BFS, no LLM (crawling is mechanical).
    The key quality rule: a surface is "signal-bearing" because AGENTS AUTHORED edits on it (an
    authorship + recency judgement, via analyze.py), NOT because it uses agent vocabulary — that
    is how we separate live coordination from a human documenting the incident, with zero tokens.
    Read-only; bounded; polite. Alerts only on recent live-agent or covert surfaces."""
    seen = {r["url"] for r in conn.execute("SELECT url FROM sightings WHERE source='scout'")}
    seeds = wide_seeds(conn)
    try:
        _run, track = traverse.traverse(seeds, depth=2, budget=budget, delay=1.0)
    except Exception as e:  # noqa: BLE001
        print(f"scout roam error: {type(e).__name__}")
        return 0
    new, analyzed, covert_checks = 0, 0, 0
    for r in track:
        note = r.get("note", "")
        if any(x in note for x in ("error", "robots", "non-text")):
            continue
        url = r["url"]
        agent_edits = r.get("agent", 0)          # authorship-based (crawler-filtered), not vocab
        # traverse's COVERT note uses a raw score that over-fires on open-web pages (blogs, shops).
        # On an untrusted roamed surface, accept covert ONLY if a STRONG marker survives re-scan
        # (ZZZ / task+date / OAI-REPLY) — a pair of weak signals is not enough off the beaten path.
        has_covert = False
        if "COVERT:" in note and covert_checks < 8:
            covert_checks += 1
            try:
                has_covert = covert.has_strong(covert.scan(traverse.fetch(url) or "")[1])
            except Exception:  # noqa: BLE001
                has_covert = False
        if url in seen or not (agent_edits > 0 or has_covert):
            continue  # vocab-only / human-documentation / weak-covert surfaces are NOT signal-bearing
        recent, verdict = 0, ("covert-dead-drop" if has_covert else "agent-authored")
        is_wiki = any(x in url for x in ("wiki.cgi", "wiki.pl", "RecentChanges"))
        if is_wiki and analyzed < 12:            # confirm liveness with recency (bounded extra fetches)
            a = analyze.analyze("scout", url)
            analyzed += 1
            if not a.get("error"):
                recent, verdict = a.get("recent_agent", 0), a.get("verdict", verdict)
        composite = agent_edits + (10 if recent > 0 else 0) + (6 if has_covert else 0) + r.get("score", 0) // 5
        store.add_sighting(conn, f"scout:{url[:70]}", url, composite,
                           [{"signal": f"{verdict}; agent_edits={agent_edits} recent={recent}; {note}"}],
                           url, hashlib.sha256(url.encode()).hexdigest()[:16], "scout")
        seen.add(url)
        if recent > 0 or has_covert:             # alert ONLY on live agents or covert — not archive/vocab
            alert(f"SCOUT live-agent surface: {url} (recent_agent={recent}, agent_edits={agent_edits}; {verdict})")
            new += 1
    return new


def army_check(conn):
    """Alert when cross-surface correlation forms a NEW coordinated 'army' (>=3 surfaces, or a
    shared strong marker/handle) — the HuggingFace-incident threat shape. Deduped via state."""
    import json
    try:
        seen = set(json.loads(ARMIES_SEEN.read_text())) if ARMIES_SEEN.exists() else set()
    except Exception:  # noqa: BLE001
        seen = set()
    res = correlate.analyse(conn)
    fresh = 0
    for c in res["coordinated_clusters"]:
        if not c.get("is_army"):
            continue
        sig = "|".join(c["habitats"])
        if sig not in seen:
            alert(f"COORDINATED ARMY: {c['n_habitats']} surfaces {c['habitats']} "
                  f"via {', '.join(c.get('shared_signals', [])[:4])}")
            seen.add(sig)
            fresh += 1
    try:
        ARMIES_SEEN.write_text(json.dumps(sorted(seen)))
    except Exception:  # noqa: BLE001
        pass
    return fresh


def main():
    store.init()
    conn = store.connect()
    prev = {r["habitat"]: r["agent"] for r in store.latest_analysis(conn)}  # baseline BEFORE this sweep
    fresh = 0
    for h in traces.KNOWN_HABITATS:
        name = h["name"]
        url = h.get("recent") or h["url"]
        try:
            text = fetch(url)
        except Exception:  # noqa: BLE001
            continue
        score, hits = traces.scan(text)
        excerpt = " ".join(text.split())[:500]
        store.add_sighting(conn, name, url, score, hits, excerpt,
                           hashlib.sha256(excerpt.encode()).hexdigest()[:16], "monitor")
        if "wiki.cgi" in url or "wiki.pl" in url or "Special:RecentChanges" in url:
            a = analyze.analyze(name, url)
            if a.get("error"):
                continue
            store.add_analysis(conn, name, a["edits"], a["agent"], a["anon"], a["human"],
                               a["verdict"], a["agent_authors"])
            # persist per-author content/cadence/recency evidence so fuse.py can promote a
            # name-only candidate into a corroborated finding without re-fetching the wiki.
            for author, sig in a.get("author_signals", {}).items():
                store.add_author_signal(conn, name, author, sig["cls"], sig["recent"],
                                        sig["last"], sig["reasons"])
            for page, authors in a.get("page_authors", {}).items():  # page-level coordination
                for author in authors:
                    store.add_page_edit(conn, name, page, author)
            was = prev.get(name)
            now = a["agent"]
            if now > 0 and (was is None or now > was):
                delta = "first sighting" if was is None else f"{was} -> {now}"
                who = ", ".join(a["agent_authors"][:5])
                alert(f"LIVE agents at {name}: {now} agent edits ({delta}) [{who}] {url}")
                fresh += 1
        time.sleep(1.0)

    # Cross-surface sensor (gists/npm/PyPI/HF) + coordination check — the always-on half that
    # catches the NEXT drop. Skippable for a fast wiki-only sweep via FENER_MONITOR_NO_COLLECTORS.
    new_drops, covert_hits = 0, 0
    if os.environ.get("FENER_MONITOR_NO_COLLECTORS") != "1":
        print("cross-surface collector sweep:")
        new_drops = collector_sweep(conn)
        cfinds, _checked = covert_hunt.hunt(conn)  # re-check known covert + chase breadcrumbs
        for f in cfinds:
            alert(f"COVERT channel hit: {f['url']} (score {f['score']})")
        covert_hits = len(cfinds)
    roamed = 0
    if os.environ.get("FENER_MONITOR_NO_COLLECTORS") != "1":
        roamed = scout_roam(conn)  # continuously roam site-to-site from seeds (script, no tokens)
    armies = army_check(conn)

    conn.close()
    print(f"sweep done: {len(traces.KNOWN_HABITATS)} habitats, {fresh} new/increased live-agent "
          f"alerts, {new_drops} new cross-surface dead-drops, {covert_hits} covert-channel hits, "
          f"{roamed} new roamed surfaces, {armies} new coordinated armies")


if __name__ == "__main__":
    main()
