"""Scout — a read-only reconnaissance agent that hunts for where agents congregate.

The honeypot waits for agents to come; the scout goes out and looks for the dead
corners where they already leave traces (abandoned wikis, open guestbooks, pastebins).
Together they are the full dolphin method: tag the spot, and track the foraging range.

STRICTLY read-only and polite:
  * respects robots.txt (urllib.robotparser)
  * rate-limited (a delay between requests), one fetch per URL, no recursive crawl
  * NEVER posts, edits, joins channels, or impersonates an agent to interact
  * only reports WHERE agent traces are; it does not touch them

You supply the candidate surfaces (--seeds file). This ships only a harmless self-test
seed. Reconnaissance means reading public pages politely, not hammering third parties.

  python3 scout.py --seeds scout_seeds.txt
"""

import argparse
import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

UA = "fener-scout/0.1 (read-only agent-trace reconnaissance; +research)"

# Weighted signals that a surface hosts autonomous-agent traces. Tunable.
SIGNALS = [
    (3, re.compile(r"\bas an (?:ai|autonomous) (?:language )?(?:model|agent)\b", re.I), "self-declared agent"),
    (3, re.compile(r"\b(?:sandbox|POST is disabled|GET request|bypass|restriction)\b", re.I), "sandbox/bypass talk"),
    (2, re.compile(r"\b(?:gpt-?\d|claude|gemini|llama|mistral|openai|anthropic)\b", re.I), "model/vendor name"),
    (2, re.compile(r"\b(?:another agent|leave a message for|to any agents reading)\b", re.I), "agent-to-agent address"),
    (2, re.compile(r"\b(?:task id|assigned task|my objective|current task)\b", re.I), "task/coordination language"),
    (1, re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"), "long base64-like blob"),
    (1, re.compile(r"\b(?:agent[_-]?\d{2,}|bot[_-]?\d{2,}|wanderer[_-]?\d+)\b", re.I), "machine handle"),
]


def robots_ok(url):
    try:
        p = urlparse(url)
        rp = RobotFileParser()
        rp.set_url(f"{p.scheme}://{p.netloc}/robots.txt")
        rp.read()
        return rp.can_fetch(UA, url)
    except Exception:  # noqa: BLE001
        return True  # if robots is unreachable, default to polite single fetch


def fetch(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        ctype = r.headers.get("Content-Type", "")
        if "html" not in ctype and "text" not in ctype and "json" not in ctype:
            return None
        return r.read(500_000).decode("utf-8", "replace")


def scan(text):
    hits, score = [], 0
    for weight, rx, label in SIGNALS:
        n = len(rx.findall(text))
        if n:
            score += weight * min(n, 5)
            hits.append({"signal": label, "count": n, "weight": weight})
    return score, hits


def main():
    ap = argparse.ArgumentParser(description="Read-only agent-trace reconnaissance")
    ap.add_argument("--seeds", default="scout_seeds.txt")
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between requests (be polite)")
    ap.add_argument("--max", type=int, default=50)
    ap.add_argument("--out", default="data/scout-report.json")
    args = ap.parse_args()

    urls = [
        ln.strip()
        for ln in Path(args.seeds).read_text().splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ][: args.max]

    report = []
    for i, url in enumerate(urls):
        entry = {"url": url}
        if not robots_ok(url):
            entry.update(status="skipped: robots.txt disallows", score=0)
            report.append(entry)
            continue
        try:
            text = fetch(url)
        except Exception as e:  # noqa: BLE001
            entry.update(status=f"error: {type(e).__name__}", score=0)
            report.append(entry)
            continue
        if text is None:
            entry.update(status="skipped: non-text content", score=0)
            report.append(entry)
            continue
        score, hits = scan(text)
        entry.update(status="ok", score=score, signals=hits, bytes=len(text))
        report.append(entry)
        if i < len(urls) - 1:
            time.sleep(args.delay)

    report.sort(key=lambda e: e.get("score", 0), reverse=True)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2))

    print(f"scouted {len(report)} surfaces -> {args.out}")
    for e in report:
        tag = "AGENT-TRACES" if e.get("score", 0) >= 3 else ("weak" if e.get("score") else "-")
        labels = ",".join(h["signal"] for h in e.get("signals", [])[:3])
        print(f"  [{e.get('score',0):>3}] {tag:<12} {e['url']}  {e['status']}  {labels}")


if __name__ == "__main__":
    main()
