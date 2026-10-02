"""Probe — deep-dive a live habitat: WHAT is the swarm doing, and WHEN.

Given a habitat's RecentChanges, enumerate the agent pages, decode the naming scheme
(Agent<id><task><unix-ts>), tally the task descriptors, and — crucially — convert the
timestamps to dates so we can tell LIVE activity from an archived footprint of an old
incident. The name is the signal; bodies are usually empty stubs.

  python3 probe.py                          # ProbierWiki
  python3 probe.py --url <rc-url>
"""

import argparse
import html as H
import re
import urllib.request
from collections import Counter
from datetime import datetime, timezone

UA = "fener-probe/0.1 (read-only; +research)"
NAME = re.compile(r"Agent(\d+)([A-Za-z]+?)(\d{9,})$")
LINK = re.compile(r"wiki\.(?:cgi|pl)\?([^'&]+)'[^>]*class='body'[^>]*>([^<]+)</a>")


def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(800_000).decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser(description="Deep-dive a live agent habitat")
    ap.add_argument("--url", default="http://www.prowiki.org/probier/wiki.cgi?action=rc")
    args = ap.parse_args()

    rc = fetch(args.url)
    names = []
    for _, nm in LINK.findall(rc):
        nm = H.unescape(nm).strip()
        if re.match(r"Agent\d", nm) and nm not in names:
            names.append(nm)

    agents, tasks, stamps = set(), Counter(), []
    for nm in names:
        m = NAME.match(nm)
        if not m:
            continue
        agents.add(m.group(1))
        tasks[m.group(2)] += 1
        ts = int(m.group(3))
        if 1_000_000_000 < ts < 3_000_000_000:  # plausible unix seconds
            stamps.append(ts)

    print(f"habitat: {args.url}")
    print(f"agent pages: {len(names)} | distinct agent ids: {len(agents)}")
    if stamps:
        lo = datetime.fromtimestamp(min(stamps), timezone.utc)
        hi = datetime.fromtimestamp(max(stamps), timezone.utc)
        print(f"name-timestamp window: {lo:%Y-%m-%d} -> {hi:%Y-%m-%d}  ({len(stamps)} stamped)")
        days = (datetime.now(timezone.utc) - hi).days
        print(f"most recent stamped attempt: {days} days ago  "
              f"=> {'LIVE / recent' if days < 14 else 'ARCHIVED footprint (not live now)'}")
    print("\ntask descriptors (what they were working on):")
    for k, v in tasks.most_common(15):
        print(f"  {v:>4}  {k}")


if __name__ == "__main__":
    main()
