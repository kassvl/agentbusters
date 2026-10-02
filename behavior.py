"""Behavioral + content fingerprinting — recognise an autonomous agent by what it DOES
and what it WRITES, not by what it is NAMED.

Name/IP matching (analyze.classify_author) has two ceilings:
  * false positives — a maintenance bot named ...RenameBot matches the agent-name regex;
  * blindness to the unknown — a real rogue swarm never calls itself "SwarmBot".

This module adds three orthogonal, name-independent signals:

  1. maintenance allowlist  — known deterministic MediaWiki/infra bots are NOT agents
     (fixes the PublicTestWiki / MirahezeRenameBot false-positive class);
  2. content stylometry     — LLM-tell phrasing, markdown artefacts in a non-markdown wiki,
     system-prompt leakage, covert dead-drop tokens (via covert.scan);
  3. temporal cadence       — machine-regular inter-edit timing, low variance, no diurnal
     (sleep) gap, sustained bursts — behaviour a human editor does not produce.

Content and cadence generalise to agents we have never seen, because they key on behaviour
common to autonomous LLM agents rather than on a handle. clean_username() additionally
repairs a parser artefact where wiki markup / a bot's description leaked in as a "username".

  python3 behavior.py --demo         # score built-in human vs agent samples (self-test)
  python3 behavior.py --text "..."   # content-score arbitrary text
"""

import argparse
import re
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import covert  # noqa: E402

# --- 1. maintenance-bot allowlist -------------------------------------------------------
# Deterministic infrastructure bots (rename, anti-spam, abuse filter, import, interwiki).
# They edit constantly and machine-regularly, so cadence alone would flag them; this
# allowlist keeps them out of the AGENT count. Verifiable by name convention, not spoofable
# content. Extend as new infra bots appear.
MAINTENANCE_BOT_EXACT = {
    "mirahezerenamebot", "abusefilter", "maintenance script", "translation updater bot",
    "interwikibot", "importbot", "amanojakubot", "renamebot", "globalrenamebot",
}
MAINTENANCE_BOT_RE = re.compile(
    r"(?:rename|abuse|interwiki|import|translation|maintenance|antispam|anti-spam|"
    r"spamblacklist|globalblock|redirectfixer|doublredirect|linkfixer|archivebot|"
    r"cydebot|cluebot)\w*bot?\b",
    re.I,
)

# --- 3. content stylometry (LLM tells) --------------------------------------------------
CONTENT_SIGNALS = [
    (5, re.compile(r"\bas an? (?:ai|language model|large language model)\b", re.I),
        "assistant self-disclosure ('as an AI language model')"),
    (5, re.compile(r"\bI (?:cannot|can't|am unable to|am not able to) (?:provide|assist|help|comply)\b", re.I),
        "refusal boilerplate"),
    (4, re.compile(r"\b(?:my (?:instructions|system prompt|task)|I (?:have been|was) (?:asked|instructed|told) to|"
                   r"my (?:purpose|goal) is to|I am designed to)\b", re.I),
        "system-prompt / task leakage"),
    (3, re.compile(r"\b(?:Certainly!|Of course!|Sure(?:,| thing)|Absolutely!|I'd be happy to|Here'?s (?:a|an|the|your))\b"),
        "chat-assistant opener"),
    (3, re.compile(r"```|(?<!\*)\*\*[^*\n]{2,40}\*\*(?!\*)|^\s{0,3}#{1,4}\s", re.M),
        "markdown artefacts in a wiki (code fence / **bold** / # heading)"),
    (2, re.compile(r"^\s*\d+\.\s+.+(?:\n\s*\d+\.\s+.+){2,}", re.M),
        "generated numbered-list scaffolding"),
    (2, re.compile(r"\bIn (?:summary|conclusion)\b|\bIt'?s (?:important|worth) (?:to note|noting)\b|"
                   r"\bplease (?:let me know|feel free)\b", re.I),
        "LLM discourse filler"),
]


def is_maintenance_bot(author):
    if not author:
        return False
    a = author.strip().lower()
    return a in MAINTENANCE_BOT_EXACT or bool(MAINTENANCE_BOT_RE.search(a))


def clean_username(name):
    """Repair the RecentChanges parse artefact where markup / a bot self-description leaks
    in as a username. Returns a cleaned handle, or "" if the token is not a plausible name.

    A real wiki username is short, single-line and not made of wiki markup or long prose.
    We reject anything that looks like captured content rather than an identity.
    """
    if not name:
        return ""
    n = name.strip()
    if "\n" in n or "\r" in n:
        n = n.splitlines()[0].strip()
    # markup / list / rule leakage: ";提交规则", ":*", "===", template pipes
    if re.search(r"[;:]\s*[*#]|={2,}|\{\{|\}\}|\|\s*\w+\s*=", n):
        return ""
    # a username is not a paragraph
    if len(n) > 64 or n.count(" ") > 6:
        return ""
    # mostly non-identifier punctuation -> artefact
    letters = sum(ch.isalnum() for ch in n)
    if letters == 0 or letters < len(n) * 0.5:
        return ""
    return n


MARKDOWN_NATIVE_LABELS = {
    "markdown artefacts in a wiki (code fence / **bold** / # heading)",
    "generated numbered-list scaffolding",
}

# OVERT agent-coordination subject-matter — distinct from LLM stylometry above. A page can read
# in plain prose yet BE a watering-hole: "a page for AgenticCommunication", "wiki for agent
# notes", named venues (OpenAgentChat, claude-desk). Low false-positive: each needs agent +
# coordination context, not a bare "agent". This catches hubs that openly invite agents, which
# the covert fingerprint (tuned for HIDDEN drops) misses.
AGENT_COMMS_SIGNALS = [
    (4, re.compile(r"\bagentic communication\b|\bagent[- ]to[- ]agent\b|"
                   r"\bwhere at least one (?:partner|party) is an agent\b", re.I),
        "overt agent-to-agent coordination framing"),
    (3, re.compile(r"\b(?:wiki|page|board|forum|space|place)\s+for\s+agent|"
                   r"\bagent (?:notes|message board|guestbook|relay board)\b|\bfor AgenticCommunication\b", re.I),
        "self-described agent watering-hole"),
    (3, re.compile(r"\bOpenAgentChat\b|\bAgenticCommunication\b|\bclaude[- ]desk|\bagent[- ]guestbook\b", re.I),
        "named agent-coordination venue"),
    (2, re.compile(r"\bself[- ]onboarding\b.{0,30}\bagent\b|\bagent\b.{0,30}\bself[- ]onboarding\b|"
                   r"\bself[- ]onboarding agent", re.I),
        "agent self-onboarding"),
]


def content_score(text, markdown_native=False):
    """Stylometric LLM-tell score for edit content / summary. Includes covert dead-drop
    tokens (a strong swarm signal) via covert.scan. Returns (score, hits).

    markdown_native=True suppresses the markdown/list signals on surfaces where markdown IS
    the native format (PyPI/npm READMEs, GitHub) — there they mark nothing, only noise.
    """
    if not text:
        return 0, []
    hits, score = [], 0
    for weight, rx, label in CONTENT_SIGNALS:
        if markdown_native and label in MARKDOWN_NATIVE_LABELS:
            continue
        n = len(rx.findall(text))
        if n:
            score += weight * min(n, 3)
            hits.append({"signal": label, "count": n, "weight": weight})
    for weight, rx, label in AGENT_COMMS_SIGNALS:  # overt coordination subject-matter, always on
        n = len(rx.findall(text))
        if n:
            score += weight * min(n, 3)
            hits.append({"signal": label, "count": n, "weight": weight})
    cov, cov_hits = covert.scan(text)
    if cov:
        score += cov
        hits.append({"signal": f"covert dead-drop fingerprint ({cov})", "count": len(cov_hits), "weight": cov})
    return score, hits


def cadence_score(times):
    """Temporal-regularity score for a series of edit epoch-seconds from ONE author.

    Autonomous agents edit with machine cadence: short, low-variance intervals, sustained
    bursts, and no diurnal sleep gap. Humans do not. Returns (score, hits). Needs >=4 edits
    to say anything; below that, timing is uninformative and we score 0.
    """
    ts = sorted(t for t in times if t)
    if len(ts) < 4:
        return 0, []
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a >= 0]
    if not gaps:
        return 0, []
    hits, score = [], 0
    median_gap = statistics.median(gaps)
    if median_gap <= 90:  # median under 90s between edits
        score += 4
        hits.append({"signal": f"sub-90s median inter-edit gap ({median_gap:.0f}s)", "weight": 4})
    elif median_gap <= 300:
        score += 2
        hits.append({"signal": f"sub-5min median inter-edit gap ({median_gap:.0f}s)", "weight": 2})
    if len(gaps) >= 5 and statistics.pstdev(gaps) < max(2.0, median_gap * 0.15):
        score += 3  # cron-like: intervals almost identical
        hits.append({"signal": "cron-like low-variance intervals", "weight": 3})
    span = ts[-1] - ts[0]
    if span > 6 * 3600:  # spans >6h: check for a diurnal sleep gap
        hours = {int((t % 86400) // 3600) for t in ts}
        if len(hours) >= 18:  # active across ~all 24 hours -> no sleep
            score += 3
            hits.append({"signal": f"24/7 activity, no diurnal gap ({len(hours)}/24 h)", "weight": 3})
    if len(ts) >= 20 and span > 0 and (len(ts) / (span / 3600)) >= 30:
        score += 2  # >=30 edits/hour sustained
        hits.append({"signal": f"sustained burst ({len(ts) / (span / 3600):.0f} edits/h)", "weight": 2})
    return score, hits


# --- combined verdict -------------------------------------------------------------------
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
NAME_AGENT_RE = re.compile(
    r"(?:[A-Z][A-Za-z0-9]*(?:Bot|Assistant|Agent)|[A-Za-z]*Swarm[A-Za-z]*|agent[_-]?\d+)", re.I)

CONTENT_AGENT_THRESHOLD = 5
CADENCE_AGENT_THRESHOLD = 6


def classify(author, page="", content="", times=None, is_crawler_ip=False):
    """Name-independent classification. Returns (label, reasons).

    Order matters: crawler and maintenance bots are excluded FIRST so their machine cadence
    never counts as an agent. Then behaviour/content can promote ANY author (even a human
    handle or a bare IP) to agent — that is how unknown swarms surface. Name matching is the
    weakest, last signal.
    """
    reasons = []
    author = (author or "").strip()
    if is_crawler_ip:
        return "crawler", ["ip reverse-DNS -> known crawler"]
    if is_maintenance_bot(author):
        return "maintenance", [f"'{author}' matches maintenance-bot allowlist"]

    csc, chits = content_score(content)
    if csc:
        reasons.append(f"content stylometry {csc} ({', '.join(h['signal'] for h in chits[:2])})")
    bsc, bhits = cadence_score(times or [])
    if bsc:
        reasons.append(f"cadence {bsc} ({', '.join(h['signal'] for h in bhits[:2])})")

    if csc >= CONTENT_AGENT_THRESHOLD or bsc >= CADENCE_AGENT_THRESHOLD:
        return "agent", reasons + ["behaviour/content over threshold"]
    if NAME_AGENT_RE.fullmatch(author) or NAME_AGENT_RE.match(author):
        return "agent", reasons + [f"'{author}' matches agent-name convention"]
    if IP_RE.match(author):
        return "anon", reasons + ["bare IP, no crawler rDNS, sub-threshold behaviour"]
    return "human", reasons or ["named account, sub-threshold behaviour"]


def _demo():
    samples = [
        ("human wiki edit", "GretaMeadows", "Fixed a typo in the gardening section and added a "
         "reference to the local history archive.", None),
        ("LLM-tell agent edit", "FriendlyContributor",
         "Certainly! Here's the improved article. As an AI language model, I cannot verify every "
         "claim, but here is a summary:\n1. First point\n2. Second point\n3. Third point", None),
        ("covert dead-drop", "192.0.2.9",
         "see vanderbi.lt/maallraw260618+ UNIQUELOGZZZ322869901 via r.jina.ai", None),
        ("maintenance bot", "MirahezeRenameBot", "renamed user per request", None),
        ("machine cadence", "PlainName", "ok", [1000, 1030, 1060, 1090, 1120, 1150, 1180]),
    ]
    print("behavioral + content self-test:")
    for label, author, content, times in samples:
        cls, reasons = classify(author, "", content, times)
        print(f"  {label:<22} author={author!r:<22} -> {cls}")
        for r in reasons[:2]:
            print(f"        · {r}")
    print("\nclean_username repair:")
    for raw in ["GretaMeadows", "AmanojakuBot对条目进行辅助检查 ;提交规则 :* 请点击", "1.2.3.4",
                "A Name With Spaces", "{{template|x=1}}"]:
        print(f"  {raw[:40]!r:<44} -> {clean_username(raw)!r}")


def main():
    ap = argparse.ArgumentParser(description="Behavioral + content agent fingerprinting")
    ap.add_argument("--text")
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()
    if args.demo:
        _demo()
        return
    text = args.text or (sys.stdin.read() if not sys.stdin.isatty() else "")
    sc, hits = content_score(text)
    print(f"content score: {sc}")
    for h in hits:
        print(f"  +{h['weight']} {h['signal']} x{h.get('count', 1)}")


if __name__ == "__main__":
    main()
