"""Hunt — the advanced instrument: find and MONITOR where autonomous agents congregate.

The scout is a one-shot reader. Hunt is the telescope on a clock: it visits the mapped
habitats (habitats.json) at their RecentChanges endpoint, scans for agent traces, scores
each, and writes a timestamped sightings ledger so you watch the pod OVER TIME. New
activity since the last look is flagged. Read-only, polite, reports coordinates only.

  python3 hunt.py                       # sweep all known habitats once
  python3 hunt.py --seeds urls.txt      # also/instead hunt these candidate surfaces
  python3 hunt.py --watch 1800          # re-sweep every 30 min, flag NEW activity
  python3 hunt.py --db data/hunt.sqlite3
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import store  # noqa: E402
import traces  # noqa: E402

UA = "fener-hunt/0.1 (read-only agent-habitat reconnaissance; +research)"
ALERT_LOG = Path(__file__).parent / "data" / "alerts.log"


def alert(text):
    """Early-warning sink: append to alerts.log and (best-effort) a macOS notification."""
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}  {text}"
    with ALERT_LOG.open("a") as f:
        f.write(line + "\n")
    print("  \033[33m! ALERT\033[0m " + text)
    # Opt-in (FENER_GUI_NOTIFY=1), terminal-notifier only — never `osascript display
    # notification`, which macOS posts under Script Editor's identity and launches that app.
    if os.environ.get("FENER_GUI_NOTIFY") == "1":
        try:
            import shutil
            import subprocess
            tn = shutil.which("terminal-notifier")
            if tn:
                subprocess.run([tn, "-title", "Fener: agent habitat", "-message", text[:180]],
                               capture_output=True, timeout=5)
        except Exception:  # noqa: BLE001
            pass


def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(800_000).decode("utf-8", "replace")


def sweep(conn, targets, delay=2.0):
    results = []
    for i, t in enumerate(targets):
        name = t.get("name", t["url"])
        url = t.get("recent") or t["url"]
        row = {"habitat": name, "url": url}
        try:
            text = fetch(url)
        except Exception as e:  # noqa: BLE001
            row.update(status=f"error: {type(e).__name__}", score=0, new=False)
            results.append(row)
            continue
        score, hits = traces.scan(text)
        excerpt = " ".join(text.split())[:500]
        h = hashlib.sha256(excerpt.encode()).hexdigest()[:16]
        prev = store.last_sighting_hash(conn, name)
        new = prev is not None and prev != h
        store.add_sighting(conn, name, url, score, hits, excerpt, h,
                           source=t.get("source", "known"))
        row.update(status="ok", score=score, signals=hits, new=new, first_seen=(prev is None))
        results.append(row)
        if i < len(targets) - 1:
            time.sleep(delay)
    results.sort(key=lambda r: r.get("score", 0), reverse=True)
    return results


def render(results):
    for r in results:
        flag = "NEW!" if r.get("new") else ("first" if r.get("first_seen") else "")
        tag = "AGENT-TRACES" if r.get("score", 0) >= 4 else ("weak" if r.get("score") else "-")
        labels = ",".join(s["signal"] for s in r.get("signals", [])[:3])
        print(f"  [{r.get('score',0):>3}] {tag:<12} {flag:<5} {r['habitat']:<22} {r['status']:<16} {labels}")


def main():
    ap = argparse.ArgumentParser(description="Hunt & monitor autonomous-agent habitats")
    ap.add_argument("--seeds", help="extra candidate URLs (one per line) to hunt")
    ap.add_argument("--only-known", action="store_true", help="known habitats only, ignore seeds")
    ap.add_argument("--watch", type=int, default=0, help="re-sweep every N seconds")
    ap.add_argument("--delay", type=float, default=2.0)
    ap.add_argument("--db", default=None)
    ap.add_argument("--alert", action="store_true", help="raise an alert on NEW or high-score habitats")
    ap.add_argument("--threshold", type=int, default=8, help="score at/above which a first sighting alerts")
    args = ap.parse_args()
    if args.db:
        os.environ["FENER_DB"] = args.db
        import importlib
        importlib.reload(store)

    targets = list(traces.KNOWN_HABITATS)
    if args.seeds and not args.only_known:
        for ln in Path(args.seeds).read_text().splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                targets.append({"name": ln, "url": ln, "source": "seed"})

    store.init()
    conn = store.connect()
    while True:
        stamp = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
        print(f"\n=== sweep {stamp} — {len(targets)} habitats ===")
        results = sweep(conn, targets, delay=args.delay)
        render(results)
        if args.alert:
            for r in results:
                if r.get("new"):
                    alert(f"NEW activity at {r['habitat']} (score {r['score']}) {r['url']}")
                elif r.get("first_seen") and r.get("score", 0) >= args.threshold:
                    labels = ",".join(s["signal"] for s in r.get("signals", [])[:3])
                    alert(f"{r['habitat']} shows agent traces (score {r['score']}: {labels}) {r['url']}")
        if not args.watch:
            break
        print(f"(sleeping {args.watch}s; Ctrl-C to stop)")
        try:
            time.sleep(args.watch)
        except KeyboardInterrupt:
            break
    conn.close()


if __name__ == "__main__":
    main()
