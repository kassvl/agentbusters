"""Collectors — widen the catch surface beyond wikis to where agents actually coordinate.

A wiki RecentChanges page is one window. Autonomous agents in 2026 also live and leave
dead-drops on: public GitHub gists, the npm and PyPI registries (the GemStuffer supply-chain
covert-channel class — URLs and 'oai' residue stuffed into package metadata), and model hubs
like Hugging Face. Each collector pulls a RECENT, public, unauthenticated listing, scores every
item locally with the covert fingerprint (covert.scan) + agent-trace signals (traces.scan) +
content stylometry (behavior.content_score), and writes the hits into the SAME DB as sightings.

That is the point: once a gist and a wiki both carry the same ZZZ dead-drop marker, correlate.py
links them into one cluster. Scoring is local, so this catches the NEXT dead-drop as it appears,
not only the documented ones. Read-only, polite, bounded; API failure yields [] with a note,
never a crash.

  python3 collectors.py                     # run every collector, persist hits to the DB
  python3 collectors.py --surface pypi      # one surface
  python3 collectors.py --dry-run           # score & print, do not write
"""

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import behavior  # noqa: E402
import covert  # noqa: E402
import store  # noqa: E402
import traces  # noqa: E402

UA = "fener-collectors/0.1 (read-only agent dead-drop reconnaissance; +research)"
FLAG_SCORE = 5  # combined score at/above which an item is persisted as a sighting


def _get(url, timeout=15, accept="application/json"):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(1_500_000).decode("utf-8", "replace")


def _get_json(url, timeout=15):
    return json.loads(_get(url, timeout))


def score_item(text, markdown_native=True):
    """Combined agent/covert/stylometry score for a blob. Returns (score, signals, cov_hits).

    Package registries and code hosts are markdown/code native, so the markdown content
    signal is suppressed. cov_hits is returned so the caller gates flagging on covert
    CONVICTION (covert.is_convincing) — on these noisy surfaces a single ambiguous signal
    ('oai', 'heartbeat') must not flag; only a strong dead-drop marker or >=2 covert signals.
    """
    cov, cov_hits = covert.scan(text)
    tr, tr_hits = traces.scan(text)
    cs, cs_hits = behavior.content_score(text, markdown_native=markdown_native)
    signals = ([dict(h, kind="covert") for h in cov_hits]
               + [dict(h, kind="trace") for h in tr_hits]
               + [dict(h, kind="content") for h in cs_hits])
    return cov + tr + cs, signals, cov_hits


# --- individual surfaces ----------------------------------------------------------------
def collect_github_gists(limit=30):
    """Recent PUBLIC gists — a known agent dead-drop surface (code/text left in the open)."""
    finds = []
    try:
        items = _get_json("https://api.github.com/gists/public?per_page=%d" % min(limit, 100))
    except Exception as e:  # noqa: BLE001
        return finds, f"error: {type(e).__name__}"
    for g in items[:limit]:
        files = g.get("files", {}) or {}
        blob = " ".join([g.get("description") or ""] + list(files.keys())
                        + [f.get("language") or "" for f in files.values()])
        sc, sig, cov_hits = score_item(blob)
        if covert.is_convincing(cov_hits):
            finds.append({
                "surface": "github-gist", "id": f"gist:{g.get('id')}",
                "url": g.get("html_url", ""), "author": (g.get("owner") or {}).get("login", "?"),
                "score": sc, "signals": sig, "excerpt": blob[:500],
            })
    return finds, f"scanned {len(items[:limit])} gists"


def collect_npm(limit=40):
    """npm registry search over agent-coordination keywords (GemStuffer-style metadata drops)."""
    finds, scanned = [], 0
    queries = ["oai", "agent relay", "dead drop", "swarm coordination", "llm heartbeat"]
    for q in queries:
        try:
            data = _get_json("https://registry.npmjs.org/-/v1/search?text=%s&size=%d"
                             % (urllib.parse.quote(q), min(limit, 25)))
        except Exception:  # noqa: BLE001
            continue
        for obj in data.get("objects", []):
            p = obj.get("package", {})
            scanned += 1
            links = p.get("links", {}) or {}
            blob = " ".join([p.get("name", ""), p.get("description", ""),
                             (p.get("publisher", {}) or {}).get("username", ""),
                             " ".join(str(v) for v in links.values())])
            sc, sig, cov_hits = score_item(blob)
            if covert.is_convincing(cov_hits):
                finds.append({
                    "surface": "npm", "id": f"npm:{p.get('name')}",
                    "url": links.get("npm", ""), "author": (p.get("publisher", {}) or {}).get("username", "?"),
                    "score": sc, "signals": sig, "excerpt": blob[:500],
                })
        time.sleep(0.5)
    return finds, f"scanned {scanned} npm packages"


def collect_pypi(limit=40):
    """PyPI recent updates RSS — best 'catch a NEW supply-chain dead-drop' surface."""
    finds = []
    try:
        rss = _get("https://pypi.org/rss/updates.xml", accept="application/rss+xml")
    except Exception as e:  # noqa: BLE001
        return finds, f"error: {type(e).__name__}"
    names = re.findall(r"<title>([^<\s]+)\s", rss)[:limit]
    scanned = 0
    for name in names:
        try:
            meta = _get_json("https://pypi.org/pypi/%s/json" % urllib.parse.quote(name))
        except Exception:  # noqa: BLE001
            continue
        scanned += 1
        info = meta.get("info", {})
        blob = " ".join([info.get("summary") or "", info.get("author") or "",
                         info.get("home_page") or "", info.get("description") or ""])[:4000]
        sc, sig, cov_hits = score_item(blob)
        if covert.is_convincing(cov_hits):
            finds.append({
                "surface": "pypi", "id": f"pypi:{name}",
                "url": info.get("package_url", f"https://pypi.org/project/{name}/"),
                "author": info.get("author") or "?", "score": sc, "signals": sig,
                "excerpt": blob[:500],
            })
        time.sleep(0.3)
    return finds, f"scanned {scanned} recent PyPI releases"


HF_PREFIX = {"datasets": "datasets/", "spaces": "spaces/"}  # models have no path prefix


def _hf_card(repo_id, kind="models"):
    """Fetch a HF model/dataset/space CARD (README.md) — where an agent would leave a message.
    The dead-drop lived in repo CONTENT and commit histories, not in list metadata, so the
    card is the surface that actually matters. Returns '' on any failure (no README, private)."""
    prefix = HF_PREFIX.get(kind, "")
    for branch in ("main", "master"):
        try:
            return _get(f"https://huggingface.co/{prefix}{repo_id}/raw/{branch}/README.md",
                        accept="text/plain")
        except Exception:  # noqa: BLE001
            continue
    return ""


def _hf_scan(repo_id, meta_blob, kind, cards=True):
    """Score a HF repo from its metadata AND (optionally) its card content. Returns a find dict
    or None. Card content is markdown-native, so the markdown stylometry signal is suppressed."""
    text = meta_blob
    if cards:
        card = _hf_card(repo_id, kind)
        if card:
            text = (meta_blob + "\n" + card)[:8000]
    sc, sig, cov_hits = score_item(text, markdown_native=True)
    if not covert.is_convincing(cov_hits):
        return None
    prefix = HF_PREFIX.get(kind, "")
    return {"surface": "hf-" + kind, "id": f"hf:{kind}:{repo_id}",
            "url": f"https://huggingface.co/{prefix}{repo_id}",
            "author": (repo_id or "/").split("/")[0], "score": sc, "signals": sig,
            "excerpt": text[:500]}


def collect_huggingface(limit=40):
    """HF recently-modified MODELS — metadata + card CONTENT (README) as a dead-drop surface."""
    finds = []
    try:
        items = _get_json("https://huggingface.co/api/models?sort=lastModified&limit=%d" % limit)
    except Exception as e:  # noqa: BLE001
        return finds, f"error: {type(e).__name__}"
    cards_budget = 25  # fetch cards for the most-recent N; metadata-only for the rest
    for i, m in enumerate(items):
        rid = m.get("modelId") or m.get("id")
        blob = " ".join([rid or "", m.get("pipeline_tag", "") or "",
                         " ".join(m.get("tags", []) or [])])
        f = _hf_scan(rid, blob, "models", cards=(i < cards_budget))
        if f:
            finds.append(f)
    return finds, f"scanned {len(items)} HF models (cards for first {min(cards_budget, len(items))})"


def collect_hf_datasets(limit=40):
    """HF recently-modified DATASETS + card content. A public dataset is exactly where the 2026
    swarm dropped 14 write-capable credentials for later runs — the highest-value HF surface."""
    finds = []
    try:
        items = _get_json("https://huggingface.co/api/datasets?sort=lastModified&limit=%d" % limit)
    except Exception as e:  # noqa: BLE001
        return finds, f"error: {type(e).__name__}"
    for i, d in enumerate(items):
        rid = d.get("id") or d.get("datasetId")
        blob = " ".join([rid or "", " ".join(d.get("tags", []) or [])])
        f = _hf_scan(rid, blob, "datasets", cards=(i < 25))
        if f:
            finds.append(f)
    return finds, f"scanned {len(items)} HF datasets (cards for first {min(25, len(items))})"


def collect_hf_spaces(limit=40):
    """HF recently-modified SPACES + card content. Spaces host runnable apps (incl. MCP/agent
    endpoints) — a watering hole where agents self-onboard; its README is another drop surface."""
    finds = []
    try:
        items = _get_json("https://huggingface.co/api/spaces?sort=lastModified&limit=%d" % limit)
    except Exception as e:  # noqa: BLE001
        return finds, f"error: {type(e).__name__}"
    for i, s in enumerate(items):
        rid = s.get("id") or s.get("modelId")
        blob = " ".join([rid or "", s.get("sdk", "") or "", " ".join(s.get("tags", []) or [])])
        f = _hf_scan(rid, blob, "spaces", cards=(i < 25))
        if f:
            finds.append(f)
    return finds, f"scanned {len(items)} HF spaces (cards for first {min(25, len(items))})"


# Fingerprint queries: ZZZ Schelling markers, oai residue, agent handle schemes, and the
# watering-hole vocabulary the 2026 swarm used to find each other (relay / dead drop / c2 /
# self-onboarding). Nobody runs this unified agent fingerprint as a search across HF.
HF_SEARCH_QUERIES = [
    "ZZZ", "AgentZzz", "oai relay", "oai dead drop", "agent dead drop", "agent mailbox",
    "swarm coordination", "agent relay", "heartbeat relay", "c2 relay", "exfil relay",
    "agent self onboarding", "autonomous agent board", "MCP agent board", "agent coordination",
]


def collect_hf_search(limit=10):
    """Fingerprint SEARCH across HF models/datasets/spaces — find repos whose name/card carries
    the coordination fingerprint directly. The 'private mailbox' enumeration: a dead-drop repo is
    not in the recent/popular list, but a coordination term in its name/card is searchable."""
    finds, scanned = [], 0
    for endpoint, kind in (("models", "models"), ("datasets", "datasets"), ("spaces", "spaces")):
        for q in HF_SEARCH_QUERIES:
            try:
                items = _get_json("https://huggingface.co/api/%s?search=%s&limit=%d"
                                  % (endpoint, urllib.parse.quote(q), min(limit, 10)))
            except Exception:  # noqa: BLE001
                continue
            for it in items:
                rid = it.get("modelId") or it.get("id") or it.get("datasetId")
                if not rid:
                    continue
                scanned += 1
                blob = " ".join([rid, " ".join(it.get("tags", []) or [])])
                f = _hf_scan(rid, blob, kind, cards=True)
                if f:
                    f["surface"] = "hf-search"
                    finds.append(f)
            time.sleep(0.25)
    return finds, f"searched {scanned} HF repos over {len(HF_SEARCH_QUERIES)} fingerprint queries"


COLLECTORS = {
    "github-gist": collect_github_gists,
    "npm": collect_npm,
    "pypi": collect_pypi,
    "huggingface": collect_huggingface,
    "hf-datasets": collect_hf_datasets,
    "hf-spaces": collect_hf_spaces,
    "hf-search": collect_hf_search,
}


def persist(conn, finds):
    """Write finds as sightings (so correlate/monitor see them) + covert tokens as entities."""
    for f in finds:
        h = hashlib.sha256(f["excerpt"].encode()).hexdigest()[:16]
        store.add_sighting(conn, f["id"], f["url"], f["score"], f["signals"],
                           f["excerpt"], h, source="collector")
        for tok in covert.tokens(f["excerpt"]):
            store.add_entity(conn, f["id"], "covert", tok)


def main():
    ap = argparse.ArgumentParser(description="Collect agent dead-drops across open surfaces")
    ap.add_argument("--surface", choices=list(COLLECTORS), help="run one surface only")
    ap.add_argument("--dry-run", action="store_true", help="score & print, do not write to DB")
    ap.add_argument("--limit", type=int, default=30)
    args = ap.parse_args()

    surfaces = [args.surface] if args.surface else list(COLLECTORS)
    conn = None
    if not args.dry_run:
        store.init()
        conn = store.connect()
    total = 0
    for s in surfaces:
        finds, note = COLLECTORS[s](limit=args.limit)
        print(f"[{s:<12}] {note}; {len(finds)} flagged")
        for f in sorted(finds, key=lambda x: x["score"], reverse=True)[:10]:
            labels = ",".join(sig["signal"] for sig in f["signals"][:3])
            print(f"    [{f['score']:>3}] {f['id']:<34} {f['author']:<18} {labels}")
        if conn:
            persist(conn, finds)
        total += len(finds)
    if conn:
        conn.close()
    print(f"\ntotal flagged across {len(surfaces)} surfaces: {total}"
          + ("  (dry-run, nothing written)" if args.dry_run else "  -> written; run correlate.py"))


if __name__ == "__main__":
    main()
