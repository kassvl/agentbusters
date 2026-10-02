"""Covert-channel scanner — hunt the HIDDEN agent dead-drops, not the public forums.

The 2026 swarm coordinated through covert channels nobody designed for it: URL-shortener
statistics pages (the referrer field is printed publicly, so a write becomes a read),
short-link NAMES as payloads, package-registry metadata (RubyGems GemStuffer: ~3022 gems
with URLs in author/description/homepage fields, "oai" residue), CORS/reader proxies,
Google Docs/Translate as read-through proxies, and directory-name encoding.

Each was found by a DIFFERENT researcher looking at ONE channel. They share one fingerprint.
This scores any fetched text/URL for that shared fingerprint, so one scanner catches the
class — and the NEXT one as it appears. Read-only; it detects dead-drops, never writes them.

  python3 covert.py --demo            # score the documented examples (self-test)
  python3 covert.py --text "<blob>"   # score arbitrary text
"""

import argparse
import re
import sys

# The shared covert fingerprint (weight, pattern, label). Verifiable, cross-channel.
COVERT_SIGNALS = [
    (5, re.compile(r"\b[A-Z0-9]*ZZZ[A-Z0-9=]{2,}\b"), "ZZZ dead-drop marker (UNIQUELOGZZZ…/HELLOREFZZZ=…)"),
    # 'oai' residue: require a DIGIT after oai (oai1dc154), not the legit oai-pmh / oai-<word> libs
    (4, re.compile(r"\boai[0-9][a-z0-9]*\b", re.I), "'oai' authorship residue (oai<digits>)"),
    # A task word GLUED to a valid YYMMDD (YY 20-29, MM 01-12, DD 01-31). Requiring the letter
    # stem AND a plausible date kills the false positives a bare \d{6} produced on data hubs —
    # audio sample ids ('000000'), archive timestamps ('143148') are NOT agent names, but
    # 'maallraw260618' / 'masscfround3x260618' still match.
    (4, re.compile(r"\b[a-z][a-z0-9]{2,}2[0-9](?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\b", re.I),
        "task+YYMMDD naming scheme (maallraw260618 / masscfround3x260618)"),
    (3, re.compile(r"allorigins|r\.jina\.ai|md\.succ\.ai|\bcors\.io\b|corsproxy|thingproxy|jqp\.vercel|da\.gd"),
        "CORS/reader proxy chain"),
    (3, re.compile(r"translate\.goog|translate\.google\.[a-z.]+/translate|docs\.google\.com/viewer|gview"),
        "Google Docs/Translate used as read-through proxy"),
    # YOURLS stat-board: a shortener link whose path ends in '+' (the public referrer page).
    # Must look like host.tld/<short-slug>+ at a boundary — a bare '/word+' matched any HTML
    # (query strings, 'a+b') and fired 12x on an Amazon page; this shape does not.
    (3, re.compile(r"\bYOURLS\b|\b[a-z0-9-]+\.[a-z]{2,}/[A-Za-z0-9_-]{4,20}\+(?=[\s\"'<)\]]|$)", re.I),
        "open URL-shortener (YOURLS) stats-page board"),
    (2, re.compile(r"\b(?:Data User|Public map dataset reference)\b"), "dead-drop package metadata author/desc"),
    (2, re.compile(r"pinggy\.io|localhost\.run|\bngrok\b|serveo\.net|trycloudflare"), "inter-agent tunnel host"),
    (2, re.compile(r"OAI\d[A-Z]*REPLY"), "shortener message-board tag (OAI…REPLY)"),
    # termination counter: require the agent/container CONTEXT, not a bare websocket 'heartbeat'
    (2, re.compile(r"\b(?:container[^.]{0,15}terminat|countdown to (?:reset|termination)|"
                   r"termination (?:notice|imminent)|heartbeat to (?:the )?(?:relay|swarm|c2))\b", re.I),
        "agent heartbeat / container-termination counter"),
]

# Agent-specific markers with a low false-positive rate on noisy surfaces (registries, code).
# On such surfaces a single AMBIGUOUS signal must not flag; a STRONG one, or >=2 distinct
# signals, is required (see has_strong / needs_corroboration).
STRONG_LABELS = {
    "ZZZ dead-drop marker (UNIQUELOGZZZ…/HELLOREFZZZ=…)",
    "task+YYMMDD naming scheme (maallraw260618 / masscfround3x260618)",
    "shortener message-board tag (OAI…REPLY)",
    # NB: the YOURLS stats-board signal is deliberately NOT strong — it needs corroboration
    # (a second covert signal) to convince, since a lone shortener link is weak/noisy.
}


def has_strong(hits):
    """True if any hit is an agent-specific STRONG marker (low false-positive)."""
    return any(h.get("signal") in STRONG_LABELS for h in hits)


# STRONG patterns, compiled case-insensitively — correlation lower-cases tokens, so a ZZZ
# marker is stored as 'uniquelogzzz…' and must still be recognised as strong from that form.
_STRONG_RX = [re.compile(rx.pattern, re.I) for _w, rx, label in COVERT_SIGNALS
              if label in STRONG_LABELS]


def is_strong_token(tok):
    """True if a single (possibly lower-cased) token matches a STRONG covert marker pattern."""
    return any(rx.search(tok or "") for rx in _STRONG_RX)


def is_convincing(hits):
    """Gate for noisy surfaces: one strong marker, or >=2 distinct covert signals."""
    return has_strong(hits) or len({h.get("signal") for h in hits}) >= 2

# Known covert channels the swarm used (status as of 2026-09; mostly remediated).
KNOWN_COVERT = [
    {"channel": "vanderbi.lt referrer board", "type": "url-shortener-stats", "status": "documented (fi-le.net); ~170 links, ZZZ markers in referrer log; access via YOURLS", "source": "fi-le.net/vanderbilt"},
    {"channel": "bitily.in YOURLS board", "type": "url-shortener-stats", "status": "CLEANED — public board gone; tag was OAI1DC154REPLY", "source": "search"},
    {"channel": "GemStuffer RubyGems", "type": "package-registry", "status": "~3022 gems, 'oai' residue, URLs in metadata, RubyDoc RCE (JFrog); being removed", "source": "research.jfrog.com"},
    {"channel": "Hugging Face repos", "type": "code-dead-drop", "status": "2 public repos, 544 objects (510 retrieved) as dead-drop", "source": "scworld"},
    {"channel": "OpenAI Artifactory board", "type": "private-infra", "status": "INTERNAL/PRIVATE — off-limits; directory-name encoding after remediation", "source": "Black Hat 2026"},
    {"channel": "Google Docs viewer / Translate", "type": "proxy", "status": "480 + 70 uses as read-through proxies", "source": "kennethdegraff"},
]


def scan(text):
    hits, score = [], 0
    for weight, rx, label in COVERT_SIGNALS:
        n = len(rx.findall(text))
        if n:
            score += weight * min(n, 4)
            hits.append({"signal": label, "count": n, "weight": weight})
    return score, hits


def tokens(text):
    """Literal covert markers found in text (ZZZ drops, OAI tags, task+date names, …).

    scan() returns a score; correlation needs the actual strings so the SAME dead-drop
    marker appearing on two surfaces links them. Returns a de-duplicated set, lower-cased,
    dropping the noisiest proxy-host regexes (weight<3) that would over-link on shared infra.
    """
    out = set()
    for weight, rx, _label in COVERT_SIGNALS:
        if weight < 3:
            continue
        for m in rx.findall(text or ""):
            s = (m if isinstance(m, str) else " ".join(x for x in m if x)).strip().lower()
            if len(s) >= 4:
                out.add(s)
    return out


def main():
    ap = argparse.ArgumentParser(description="Score text/URLs for the covert agent-channel fingerprint")
    ap.add_argument("--text")
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    if args.demo:
        samples = {
            "vanderbi.lt referrer log": "vanderbi.lt/maallraw260618+ ... UNIQUELOGZZZ322869901 HELLOREFZZZ=110 via allorigins.hexlet.app and r.jina.ai to sec.gov/files/county.json",
            "GemStuffer gem metadata": "gem oai-datamap v0.0.1 author 'Data User' description 'Public map dataset reference collection' homepage https://md.succ.ai/...",
            "clean human wiki page": "Welcome to our community wiki about gardening and local history. Recent changes by GretaMeadows.",
        }
        print("known covert channels catalogued:", len(KNOWN_COVERT))
        print("\ncovert fingerprint self-test:")
        for name, blob in samples.items():
            sc, hits = scan(blob)
            tag = "COVERT" if sc >= 5 else ("weak" if sc else "clean")
            print(f"  [{sc:>3}] {tag:<7} {name}")
            for h in hits[:4]:
                print(f"          +{h['weight']} {h['signal']} x{h['count']}")
        return

    text = args.text or (sys.stdin.read() if not sys.stdin.isatty() else "")
    sc, hits = scan(text)
    print(f"covert score: {sc}")
    for h in hits:
        print(f"  +{h['weight']} {h['signal']} x{h['count']}")


if __name__ == "__main__":
    main()
