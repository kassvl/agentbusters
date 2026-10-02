"""Fuse — the attribution engine: composite agent dossiers from all evidence.

Every other module produces ONE kind of signal. This fuses them into TANGIBLE, named findings.
No single signal names an agent — a handle is a claim, an IP is circumstantial, a marker is
shared — but Web Bot Auth + IP/rDNS + timing + content stylometry + cross-surface handle/token
reuse TOGETHER do. For each detected actor it builds a dossier: identity, every surface it
touched, its behavioural/crypto classification, the coordination cluster it belongs to, and a
confidence grade — each line backed by the signal that produced it. That is the deliverable:
a census of the autonomous agents currently detectable across the surfaces Fener watches.

  python3 fuse.py                 # print the agent census from data/live.sqlite3
  python3 fuse.py --json          # machine-readable dossiers
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import behavior  # noqa: E402
import correlate  # noqa: E402
import store  # noqa: E402

OUT = Path(__file__).parent / "data" / "census.json"


def _actor_surfaces(conn):
    """handle -> set of surfaces where it authored, from the latest analysis per habitat."""
    where = defaultdict(set)
    times = defaultdict(list)
    for r in store.latest_analysis(conn):
        try:
            authors = json.loads(r["agent_authors"] or "[]")
        except Exception:  # noqa: BLE001
            authors = []
        for a in authors:
            h = behavior.clean_username(str(a))
            if h:
                where[h].add(r["habitat"])
    return where, times


def _author_evidence(conn):
    """Aggregate stored per-author signals: behavioural (content/cadence) reasons + recency.
    A reason naming stylometry or cadence is EVIDENCE the handle writes/edits like an agent —
    the corroboration that turns a name-only candidate into a finding."""
    agg = defaultdict(lambda: {"recent": False, "last": None, "behavioral": []})
    for r in store.author_signals(conn):
        a = agg[r["author"]]
        a["recent"] = a["recent"] or bool(r["recent"])
        if r["last_seen"] and (a["last"] is None or r["last_seen"] > a["last"]):
            a["last"] = r["last_seen"]
        try:
            reasons = json.loads(r["reasons_json"] or "[]")
        except Exception:  # noqa: BLE001
            reasons = []
        for reason in reasons:
            s = str(reason)
            if any(k in s for k in ("content stylometry", "content evidence", "cadence",
                                    "behaviour/content over threshold", "agent-to-agent",
                                    "watering-hole", "coordination venue", "self-onboarding")):
                if s not in a["behavioral"]:
                    a["behavioral"].append(s)
    return agg


def _covert_for(conn, surfaces):
    """covert markers recorded on any of an actor's surfaces (shared dead-drop evidence)."""
    if not surfaces:
        return set()
    qs = ",".join("?" * len(surfaces))
    rows = conn.execute(
        f"SELECT DISTINCT value FROM entities WHERE kind='covert' AND habitat IN ({qs})",
        tuple(surfaces)).fetchall()
    return {r["value"] for r in rows}


def build_dossiers(conn):
    """Return ranked agent dossiers + the coordinated clusters they belong to."""
    corr = correlate.analyse(conn)
    xsurf = corr["cross_surface_authors"]  # handle -> [habitats] (seen on >=2 surfaces)
    # map each surface to the army cluster it is in (if any)
    surface_cluster = {}
    for i, c in enumerate(corr["coordinated_clusters"]):
        for h in c["habitats"]:
            surface_cluster[h] = (i, c)

    evidence = _author_evidence(conn)
    where, _times = _actor_surfaces(conn)
    dossiers = []
    for handle, surfaces in where.items():
        cls, reasons = behavior.classify(handle)
        if cls in ("maintenance", "crawler"):
            continue  # not a wild/coordinating agent — exclude from the census
        ev = evidence.get(handle, {"recent": False, "last": None, "behavioral": []})
        covert = _covert_for(conn, surfaces)
        cross = handle in xsurf or len(surfaces) >= 2
        clusters = sorted({surface_cluster[s][0] for s in surfaces if s in surface_cluster})
        in_army = any(surface_cluster[s][1].get("is_army") for s in surfaces if s in surface_cluster)

        # Name convention alone is a weak signal (the project's own lesson: name != live agent),
        # so it only seeds a CANDIDATE. The weight that makes a finding tangible is corroboration:
        # the SAME handle across surfaces, covert dead-drop markers, army membership. Handles come
        # from analyze.py's agent_authors, already crawler-filtered and recency-bounded (<=21d).
        score, why = 0, []
        if cls == "agent":
            score += 1
            why.append("agent-name convention (" + "; ".join(str(r) for r in reasons[:1]) +
                       ") — candidate on name alone")
        elif cls == "human":
            why.append("behavioural classifier: human-like")
        if cross:
            score += 3
            why.append(f"cross-surface: SAME handle on {len(surfaces)} surfaces ({', '.join(sorted(surfaces))})")
        if covert:
            score += 2
            why.append(f"covert dead-drop markers on its surfaces: {', '.join(sorted(covert)[:3])}")
        if in_army:
            score += 2
            why.append("member of a coordinated ARMY cluster")
        if ev["behavioral"]:
            score += 2
            why.append("behavioural evidence (writes/edits like an agent): " + "; ".join(ev["behavioral"][:2]))
        if ev["recent"]:
            score += 1
            why.append(f"recent activity (<=21d, last {ev['last'] or '?'})")
        elif ev["last"]:
            why.append(f"archived footprint (last seen {ev['last']}, not recent)")

        grade = "high" if score >= 6 else "medium" if score >= 3 else "candidate"
        dossiers.append({
            "identity": handle, "classification": cls, "surfaces": sorted(surfaces),
            "n_surfaces": len(surfaces), "cross_surface": cross, "covert_markers": sorted(covert),
            "clusters": clusters, "in_army": in_army, "recent": ev["recent"], "last_seen": ev["last"],
            "behavioral_evidence": ev["behavioral"], "confidence": grade, "score": score,
            "evidence": why,
        })
    dossiers.sort(key=lambda d: (d["score"], d["n_surfaces"]), reverse=True)
    return dossiers, corr


def census(conn):
    dossiers, corr = build_dossiers(conn)
    cells = [{"habitat": h, "page": p, "agents": a, "n": n}
             for h, p, a, n in store.page_cells(conn)]
    return {
        "n_corroborated": sum(1 for d in dossiers if d["confidence"] in ("high", "medium")),
        "n_candidates": sum(1 for d in dossiers if d["confidence"] == "candidate"),
        "n_live": sum(1 for d in dossiers if d["recent"]),
        "n_dossiers": len(dossiers),
        "coordinated_clusters": corr["coordinated_clusters"],
        "coordination_cells": cells,
        "dossiers": dossiers,
    }


def main():
    ap = argparse.ArgumentParser(description="Agent census: fused dossiers from all evidence")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    store.init()
    conn = store.connect()
    rep = census(conn)
    conn.close()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rep, ensure_ascii=False, indent=2))
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return
    print(f"AGENT CENSUS — {rep['n_corroborated']} corroborated, {rep['n_candidates']} candidates, "
          f"{rep['n_live']} LIVE (<=21d), {len(rep['coordinated_clusters'])} cross-surface clusters, "
          f"{len(rep['coordination_cells'])} page-level cells\n")
    for c in rep["coordination_cells"]:
        print(f"  ⚑ CELL: {c['n']} agents co-edit {c['habitat']}/{c['page']} — {', '.join(c['agents'][:6])}")
    if rep["coordination_cells"]:
        print()
    for d in rep["dossiers"]:
        flag = " ⚑ARMY" if d["in_army"] else ""
        live = "LIVE" if d["recent"] else "arch"
        print(f"[{d['confidence']:>6}|{live}] {d['identity']}  ({d['classification']}, "
              f"{d['n_surfaces']} surface{'s' if d['n_surfaces'] != 1 else ''}){flag}")
        for e in d["evidence"]:
            print(f"         - {e}")
    if not rep["dossiers"]:
        print("(no agents in the current evidence — run monitor.py / collectors.py to populate)")
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
