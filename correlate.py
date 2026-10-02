"""Correlate — a lone agent is noise; a COORDINATED cluster is the discovery.

hunt/analyze answer "is THIS surface live?". They cannot answer "are these surfaces the
SAME operation?". This does. It reads every surface's discriminating signals from the DB —
agent handles, covert dead-drop tokens (covert.tokens), agent-artefact page/entity names —
and links two surfaces whenever they SHARE one. Union-find over those shared-signal edges
yields connected components; a component spanning >=2 surfaces is a candidate coordinated
cluster: one operator reaching across the open web, which no single-surface view reveals.

Signals are namespaced (author:/covert:/art:) so only like-for-like links (a shared handle,
a shared ZZZ marker), never incidental wiki chrome. Legacy agent handles are clean_username-
repaired on read, so the old CJK/maintenance-bot artefacts do not create phantom links.

  python3 correlate.py            # cluster the live DB, print report, write data/clusters.json
  python3 correlate.py --json     # machine-readable clusters only
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import beacon  # noqa: E402
import behavior  # noqa: E402
import covert  # noqa: E402
import store  # noqa: E402

OUT = Path(__file__).parent / "data" / "clusters.json"


class UnionFind:
    def __init__(self, items):
        self.parent = {x: x for x in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _authors(js):
    try:
        arr = json.loads(js or "[]")
    except Exception:  # noqa: BLE001
        arr = []
    return {a for a in (behavior.clean_username(str(x)) for x in arr) if a}


def load_signals(conn):
    """Per-habitat discriminating signal set: agent handles, covert tokens, artefacts."""
    sig = defaultdict(lambda: {"authors": set(), "covert": set(), "artefacts": set()})
    for r in store.latest_analysis(conn):
        sig[r["habitat"]]["authors"] |= _authors(r["agent_authors"])
    for r in conn.execute("SELECT habitat, kind, value FROM entities"):
        v = (r["value"] or "").strip()
        if v:
            sig[r["habitat"]]["artefacts"].add(f"{r['kind']}:{v.lower()}")
    for r in conn.execute("SELECT habitat, excerpt FROM sightings ORDER BY id DESC LIMIT 3000"):
        toks = covert.tokens(r["excerpt"] or "")
        if toks:
            sig[r["habitat"]]["covert"] |= toks
    # beacon as a surface: our own dolphin tags + covert tokens agents posted to us. If a tag
    # reappears in a sighting above, both carry it and the beacon links to that surface.
    beacon_toks = set()
    for t in beacon.active_tags(conn):  # normalise tags exactly as covert.tokens does on surfaces
        beacon_toks |= covert.tokens(t)
    for r in conn.execute("SELECT content FROM pod ORDER BY id DESC LIMIT 2000"):
        beacon_toks |= covert.tokens(r["content"] or "")
    for r in conn.execute("SELECT body FROM events WHERE body IS NOT NULL ORDER BY id DESC LIMIT 2000"):
        beacon_toks |= covert.tokens(r["body"] or "")
    if beacon_toks:
        sig["beacon"]["covert"] |= beacon_toks
    return sig


def signal_tokens(s):
    """Flatten one habitat's signals into namespaced, comparable tokens."""
    return ({f"author:{a.lower()}" for a in s["authors"]}
            | {f"covert:{t}" for t in s["covert"]}
            | {f"art:{t}" for t in s["artefacts"]})


def build_clusters(signals):
    habs = list(signals)
    toks = {h: signal_tokens(signals[h]) for h in habs}
    uf = UnionFind(habs)
    edges = []
    for i in range(len(habs)):
        for j in range(i + 1, len(habs)):
            shared = toks[habs[i]] & toks[habs[j]]
            if shared:
                uf.union(habs[i], habs[j])
                edges.append({"a": habs[i], "b": habs[j], "shared": sorted(shared)})
    comps = defaultdict(list)
    for h in habs:
        comps[uf.find(h)].append(h)
    clusters = []
    for members in comps.values():
        merged = set().union(*(toks[h] for h in members)) if members else set()
        clusters.append({
            "habitats": sorted(members),
            "n_habitats": len(members),
            "signals": sorted(merged),
            "edges": [e for e in edges if e["a"] in members and e["b"] in members],
        })
    clusters.sort(key=lambda c: (c["n_habitats"], len(c["signals"])), reverse=True)
    return clusters, edges


def cross_surface_authors(signals):
    """Agent handles appearing on >=2 distinct surfaces (same actor, multiple habitats)."""
    where = defaultdict(set)
    for hab, s in signals.items():
        for a in s["authors"]:
            where[a].add(hab)
    return {a: sorted(h) for a, h in where.items() if len(h) >= 2}


def score_cluster(cluster):
    """Grade a coordinated cluster. An 'army' is the HuggingFace-incident shape: one operation
    reaching across >=3 surfaces, OR two surfaces linked by a STRONG covert marker (a ZZZ
    dead-drop / task+date name) or a SHARED AGENT HANDLE — links a coincidence cannot explain.
    """
    shared = set()
    for e in cluster["edges"]:
        shared |= set(e["shared"])
    strong = any(s.startswith("author:") for s in shared)
    for s in shared:
        if s.startswith("covert:") and covert.is_strong_token(s.split("covert:", 1)[1]):
            strong = True
    is_army = cluster["n_habitats"] >= 3 or strong
    cluster["shared_signals"] = sorted(shared)
    cluster["is_army"] = is_army
    cluster["severity"] = "high" if is_army else "medium"
    return cluster


def analyse(conn):
    signals = load_signals(conn)
    clusters, edges = build_clusters(signals)
    coordinated = [score_cluster(c) for c in clusters if c["n_habitats"] >= 2]
    return {
        "n_surfaces": len(signals),
        "n_edges": len(edges),
        "coordinated_clusters": coordinated,
        "all_clusters": clusters,
        "cross_surface_authors": cross_surface_authors(signals),
    }


def main():
    ap = argparse.ArgumentParser(description="Cross-surface coordination clustering")
    ap.add_argument("--json", action="store_true", help="print clusters JSON only")
    args = ap.parse_args()
    store.init()
    conn = store.connect()
    res = analyse(conn)
    conn.close()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=2))
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return
    print(f"surfaces={res['n_surfaces']}  shared-signal edges={res['n_edges']}  "
          f"coordinated clusters={len(res['coordinated_clusters'])}")
    if not res["coordinated_clusters"]:
        print("\nNo cross-surface coordination yet — every live surface is isolated.")
        print("(Correct at this data volume; clusters light up when surfaces share a token/handle.)")
    for i, c in enumerate(res["coordinated_clusters"], 1):
        flag = "  ⚑ COORDINATED ARMY" if c.get("is_army") else ""
        print(f"\n[cluster {i}] severity={c['severity']}{flag} — "
              f"{c['n_habitats']} surfaces: {', '.join(c['habitats'])}")
        for e in c["edges"][:6]:
            print(f"    {e['a']}  <->  {e['b']}   via {', '.join(e['shared'][:4])}")
    if res["cross_surface_authors"]:
        print("\ncross-surface agent handles (same actor, multiple surfaces):")
        for a, habs in list(res["cross_surface_authors"].items())[:10]:
            print(f"    {a}: {', '.join(habs)}")
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
