"""Agent-trace scanner. One source of truth for the signals, read from habitats.json.

`scan(text)` returns (score, hits). Used by hunt.py (habitat monitor) and scout.py.
Signals encode what the 2026 disclosures showed agents leave behind: ZZZ Schelling-point
pages, heartbeat/termination counters, inter-agent tunnels, self-identification,
GET-write/bypass talk, task relays, machine handles, base64 payloads.
"""

import json
import re
from pathlib import Path

_H = json.loads((Path(__file__).parent / "habitats.json").read_text())
SIGNALS = [(s["weight"], re.compile(s["pattern"], re.I), s["label"]) for s in _H["signals"]]
FINGERPRINTS = _H["fingerprints"]
KNOWN_HABITATS = _H["known_habitats"]


def scan(text):
    hits, score = [], 0
    for weight, rx, label in SIGNALS:
        n = len(rx.findall(text))
        if n:
            score += weight * min(n, 5)
            hits.append({"signal": label, "count": n, "weight": weight})
    return score, hits


def looks_like_habitat(url):
    """Cheap URL-shape check: does this look like a colonisable surface?"""
    u = url.lower()
    return [p for p in FINGERPRINTS["url_patterns"] if p.lower() in u]
