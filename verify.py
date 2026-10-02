"""IP-range verification for claimed agents.

Some providers (OpenAI, Google, Anthropic, Perplexity, Bing…) publish the IP ranges
their crawlers/agents use. A user-agent string is a claim; membership in the published
range is proof. This turns 'claimed' into 'verified' — and, crucially, surfaces
IMPERSONATION: a request calling itself GPTBot from an IP outside OpenAI's ranges is a
finding, not a crawler.

Network is used only by `refresh()` (run it periodically). `lookup()` and
`ranges_available()` read the local cache only, so classification stays fast and offline.

  python3 verify.py --refresh     # fetch + cache provider ranges
  python3 verify.py 8.8.8.8       # which provider (if any) owns this IP
"""

import ipaddress
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

RANGES_DIR = Path(__file__).parent / "data" / "ranges"
_AGENTS = json.loads((Path(__file__).parent / "agents.json").read_text())["agents"]

CIDR_RE = re.compile(
    r"(?:(?:\d{1,3}\.){3}\d{1,3}/\d{1,2})"
    r"|(?:[0-9A-Fa-f]{0,4}:(?:[0-9A-Fa-f]{0,4}:){1,6}[0-9A-Fa-f]{0,4}/\d{1,3})"
)

_cache = None  # {slug: {"name":..., "nets":[ip_network,...]}}


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _extract_cidrs(text):
    nets = []
    for m in CIDR_RE.findall(text):
        try:
            nets.append(ipaddress.ip_network(m, strict=False))
        except ValueError:
            pass
    return nets


def refresh(timeout=15):
    RANGES_DIR.mkdir(parents=True, exist_ok=True)
    results = {}
    for a in _AGENTS:
        url = a.get("ip_ranges_url")
        if not url:
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "fener-verify/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                text = r.read().decode("utf-8", "replace")
            cidrs = sorted({str(n) for n in _extract_cidrs(text)})
            if not cidrs:
                results[a["name"]] = "no CIDRs found in response"
                continue
            (RANGES_DIR / f"{slug(a['name'])}.json").write_text(
                json.dumps({"name": a["name"], "fetched": time.time(), "cidrs": cidrs}, indent=1)
            )
            results[a["name"]] = f"{len(cidrs)} ranges cached"
        except Exception as e:  # noqa: BLE001
            results[a["name"]] = f"skip ({type(e).__name__})"
    return results


def _load():
    global _cache
    if _cache is not None:
        return _cache
    _cache = {}
    if RANGES_DIR.is_dir():
        for f in RANGES_DIR.glob("*.json"):
            try:
                d = json.loads(f.read_text())
                nets = [ipaddress.ip_network(c, strict=False) for c in d.get("cidrs", [])]
                if nets:
                    _cache[f.stem] = {"name": d.get("name", f.stem), "nets": nets}
            except Exception:  # noqa: BLE001
                pass
    return _cache


def ranges_available(agent_name):
    return slug(agent_name) in _load()


def lookup(ip):
    """Return the provider name whose published ranges contain ip, else None (cache-only)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for entry in _load().values():
        for net in entry["nets"]:
            if addr.version == net.version and addr in net:
                return entry["name"]
    return None


def main():
    if "--refresh" in sys.argv:
        for name, status in refresh().items():
            print(f"  {name:<28} {status}")
        return
    if len(sys.argv) > 1:
        ip = sys.argv[1]
        print(lookup(ip) or "(not in any cached provider range)")
        return
    print(__doc__)


if __name__ == "__main__":
    main()
