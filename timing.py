"""Timing classifier — separate LLM agents from scripted bots and humans by behaviour in time.

Palisade Research's honeypot showed that WHEN an actor acts is as telling as what it does. Three
regimes are separable:

  * scripted bot — acts sub-second with near-zero variance; it pre-knows its target and never
    "reads", so there is no inference pause.
  * LLM agent    — acts after a model-inference/tool-call pause (the "think" band, ~1-45s) and,
    across many requests, holds a machine-regular cadence a human never sustains.
  * human        — reads at leisure: long, bursty, high-variance gaps.

Two inputs feed it, both already in Fener's store: `delays` (seconds between being served the
honeypot page and acting on its planted marker — the responders() delay_s) and `intervals`
(seconds between an IP's consecutive requests). `classify_actor` is a pure function over those
numbers so it is deterministic and unit-testable; `classify_ip` wraps the DB.

This is pure observation of timing we already log — no probing, no manipulation.

  python3 timing.py            # classify recent active IPs from the live DB
"""

import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import store  # noqa: E402

THINK_MIN = 0.8       # below this no model could read+reason: scripted, not thinking
THINK_MAX = 45.0      # upper bound of the model inference + tool-call latency band
SCRIPT_INTERVAL = 1.2  # sub-second, constant cadence => raw machine
HUMAN_DELAY = 90.0     # a reading pause this long reads as human


def _cv(xs):
    """Coefficient of variation (spread / mean): low = machine-regular, high = bursty/human."""
    xs = [x for x in xs if x is not None]
    if len(xs) < 2:
        return None
    m = statistics.mean(xs)
    if m == 0:
        return 0.0
    return statistics.pstdev(xs) / m


def classify_actor(delays=None, intervals=None):
    """Return (label, reasons). label in {scripted_bot, llm_agent, human, unknown}."""
    delays = [d for d in (delays or []) if d is not None and d >= 0]
    intervals = [i for i in (intervals or []) if i is not None and i >= 0]
    if len(delays) + len(intervals) < 2:
        return ("unknown", ["insufficient timing samples"])

    reasons = []
    votes = {"scripted_bot": 0.0, "llm_agent": 0.0, "human": 0.0}

    if delays:
        md = statistics.median(delays)
        reasons.append(f"median act-delay {md:.2f}s over {len(delays)} action(s)")
        if md < THINK_MIN:
            votes["scripted_bot"] += 2.0
            reasons.append("acts faster than a model could read the page: no think latency")
        elif md <= THINK_MAX:
            votes["llm_agent"] += 2.0
            reasons.append("acts within the model inference/tool-call latency band")
        elif md > HUMAN_DELAY:
            votes["human"] += 2.0
            reasons.append("acts after a human-scale reading pause")
        else:
            votes["llm_agent"] += 0.5
            votes["human"] += 0.5

    if len(intervals) >= 2:
        md_i = statistics.median(intervals)
        cv = _cv(intervals)
        reasons.append(f"median inter-request {md_i:.2f}s, CV {cv:.2f}")
        if md_i < SCRIPT_INTERVAL and cv is not None and cv < 0.25:
            votes["scripted_bot"] += 1.5
            reasons.append("sub-second, near-constant cadence: raw machine")
        elif cv is not None and cv < 0.35 and len(intervals) >= 4:
            votes["llm_agent"] += 1.5
            reasons.append("regular machine cadence (cron-like), slower than a raw script")
        elif cv is not None and cv > 0.8:
            votes["human"] += 1.0
            reasons.append("bursty, high-variance cadence: human-like")

    label = max(votes, key=votes.get)
    ordered = sorted(votes.values(), reverse=True)
    if votes[label] == 0:
        return ("unknown", reasons + ["no timing signal crossed a threshold"])
    if len(ordered) >= 2 and ordered[0] - ordered[1] < 0.5:
        return ("unknown", reasons + ["timing signals mixed: no confident class"])
    return (label, reasons)


def _responder_delays(conn, ip):
    return [r["delay_s"] for r in store.responders(conn, 500)
            if r["resp_ip"] == ip and r["delay_s"] is not None]


def classify_ip(conn, ip):
    """Timing verdict for one IP from its event cadence + responder think-delays."""
    ts = [r["ts"] for r in conn.execute(
        "SELECT ts FROM events WHERE remote_ip=? ORDER BY ts", (ip,)).fetchall()]
    intervals = [b - a for a, b in zip(ts, ts[1:])]
    return classify_actor(delays=_responder_delays(conn, ip), intervals=intervals)


def classify_all(conn, min_events=3):
    ips = [r["remote_ip"] for r in conn.execute(
        "SELECT remote_ip, COUNT(*) c FROM events GROUP BY remote_ip HAVING c >= ? "
        "ORDER BY c DESC", (min_events,)).fetchall()]
    return {ip: classify_ip(conn, ip) for ip in ips}


def main():
    store.init()
    conn = store.connect()
    res = classify_all(conn)
    conn.close()
    if not res:
        print("no IP has enough events yet for a timing verdict (need >=3).")
        return
    for ip, (label, reasons) in res.items():
        print(f"{ip:<20} {label}")
        for r in reasons:
            print(f"    - {r}")


if __name__ == "__main__":
    main()
