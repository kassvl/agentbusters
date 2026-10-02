"""Crawler filter — the accuracy layer that separates real agents from search crawlers.

GET-writable wikis are contaminated: any crawler that follows an edit-URL triggers an
"edit". On ProbierWiki most recent edits reverse-DNS to crawl.amazonbot.amazon (Amazonbot),
not autonomous agents. This module reverse-DNS-resolves an editor IP and tells whether it
is a known crawler, so it can be excluded from the live-agent count.

Reverse-DNS is cached to data/rdns_cache.json (persists across monitor runs) and bounded
with a short timeout, so a sweep pays the lookup cost once.
"""

import json
import socket
from pathlib import Path

CACHE_FILE = Path(__file__).parent / "data" / "rdns_cache.json"
LOOKUP_TIMEOUT = 2.0

# reverse-DNS suffixes/markers of known crawlers (verifiable, not spoofable UA strings)
CRAWLER_MARKERS = (
    "crawl.amazonbot.amazon", "googlebot.com", ".google.com", "search.msn.com",
    "crawl.bing.com", "applebot.apple.com", "crawl.yahoo.net", "yandex.com",
    "yandex.net", "crawl.baidu", "ahrefs.com", "semrush", "petalbot", "aspiegel",
    "bytespider", "crawl.sogou", "mojeek", "dataforseo", "crawl.naver",
)

_cache = None
_dirty = 0


def _load():
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(CACHE_FILE.read_text())
        except Exception:  # noqa: BLE001
            _cache = {}
    return _cache


def flush():
    if _cache is not None:
        try:
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(_cache))
        except Exception:  # noqa: BLE001
            pass


def rdns(ip):
    c = _load()
    if ip in c:
        return c[ip]
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(LOOKUP_TIMEOUT)
    try:
        host = socket.gethostbyaddr(ip)[0].lower()
    except Exception:  # noqa: BLE001
        host = ""
    finally:
        socket.setdefaulttimeout(old)
    c[ip] = host
    global _dirty
    _dirty += 1
    if _dirty % 25 == 0:
        flush()
    return host


def is_crawler(ip):
    """True if the IP reverse-DNS-resolves to a known search/AI crawler."""
    host = rdns(ip)
    return bool(host) and any(m in host for m in CRAWLER_MARKERS)


def crawler_name(ip):
    host = rdns(ip)
    for m in CRAWLER_MARKERS:
        if m in host:
            return m.split(".")[0].strip("crawl").strip(".") or m
    return None
