"""Graph — map the back-channel topology: which habitats are LINKED.

Two surfaces are linked when they share a specific agent artefact: the same agent handle
(XxxBot / XxxAssistant), the same ZZZ Schelling-point page name, or the same inter-agent
tunnel host (pinggy.io / localhost.run / …). Generic tokens (model/vendor names) are
excluded — every page mentions "OpenAI", so they'd link everything and mean nothing.

This is the observed-topology version, buildable now from public reads. The propagation
TAG extends it: a unique benign marker planted only where permitted (our honeypot; the
agent-guestbook invitation) becomes another shared-entity edge once agents carry it
between watering holes. Register such markers in markers.txt (one per line).

  python3 graph.py                      # fetch known habitats, emit graph.{json,dot} + summary
  dot -Tsvg data/graph.dot > graph.svg  # if graphviz installed
"""

import json
import re
import sys
import time
import urllib.request
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
import store  # noqa: E402
import traces  # noqa: E402

UA = "fener-graph/0.1 (read-only; +research)"

ENTITY = [
    ("handle", re.compile(r"\b([A-Z][A-Za-z0-9]{2,}(?:Bot|Assistant))\b")),
    ("zzz", re.compile(r"\b((?:Agent)?Zzz[A-Za-z0-9]+|ZZZ[A-Za-z0-9]+)\b")),
    ("tunnel", re.compile(r"\b([a-z0-9-]+\.(?:pinggy\.io|localhost\.run|ngrok\.io|serveo\.net))\b")),
]
STOP = {"UseModWiki", "WikiBot", "RssBot"}  # engine/infra noise, not agents


def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(800_000).decode("utf-8", "replace")


def entities(text):
    found = set()
    for kind, rx in ENTITY:
        for m in rx.findall(text):
            if m not in STOP and len(m) >= 4:
                found.add((kind, m))
    return found


def main():
    markers_file = Path(__file__).parent / "markers.txt"
    markers = set()
    if markers_file.exists():
        markers = {ln.strip() for ln in markers_file.read_text().splitlines() if ln.strip()}

    store.init()
    conn = store.connect()
    per_habitat = {}
    domain = {}
    for h in traces.KNOWN_HABITATS:
        name, url = h["name"], (h.get("recent") or h["url"])
        domain[name] = urlparse(h["url"]).netloc.removeprefix("www.")
        try:
            text = fetch(url)
        except Exception as e:  # noqa: BLE001
            print(f"  skip {name}: {type(e).__name__}")
            continue
        ents = entities(text)
        for mk in markers:
            if mk in text:
                ents.add(("marker", mk))
        per_habitat[name] = ents
        for kind, val in ents:
            store.add_entity(conn, name, kind, val)  # persist -> edges accrue over time
        time.sleep(1.5)

    edges = defaultdict(lambda: defaultdict(set))  # a -> b -> shared reasons

    # (1) entity edges, from ALL sweeps ever (time-accumulating topology)
    shared_list = store.shared_entities(conn)
    for kind, val, habs, _ in shared_list:
        habs = sorted(set(habs))
        for i in range(len(habs)):
            for j in range(i + 1, len(habs)):
                edges[habs[i]][habs[j]].add(f"{kind}:{val}")

    # (2) structural edges: habitats on the same host/farm (e.g. the prowiki.org farm)
    by_domain = defaultdict(list)
    for name, dom in domain.items():
        if dom:
            by_domain[dom].append(name)
    for dom, names in by_domain.items():
        names = sorted(names)
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                edges[names[i]][names[j]].add(f"farm:{dom}")

    agent_by = {r["habitat"]: r["agent"] for r in store.latest_analysis(conn)}
    conn.close()
    nodes = [{"id": n, "entities": len(e), "agents": agent_by.get(n, 0)} for n, e in per_habitat.items()]
    edge_list = [
        {"a": a, "b": b, "weight": len(v), "via": sorted(v)}
        for a, m in edges.items() for b, v in m.items()
    ]
    out = {"nodes": nodes, "edges": edge_list, "shared_entities": len(shared_list)}
    Path("data").mkdir(exist_ok=True)
    Path("data/graph.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))

    def style(agents):
        if agents >= 100:
            return "fillcolor=\"#ff5a52\",fontcolor=white,width=1.6"   # hotspot
        if agents >= 1:
            return "fillcolor=\"#e3b341\",width=1.2"                    # live
        return "fillcolor=\"#c9d1d9\",width=0.9"                        # dormant/clean

    dot = ['graph fener {', '  bgcolor="#0e1116"; node [shape=ellipse,style=filled,'
           'fontname="Helvetica",fontsize=11]; edge [color="#7d8a99"];']
    for n in nodes:
        label = f'{n["id"]}\\n{n["agents"]} agents' if n["agents"] else n["id"]
        dot.append(f'  "{n["id"]}" [label="{label}",{style(n["agents"])}];')
    for e in edge_list:
        col = "#39c5cf" if any(v.startswith(("handle:", "zzz:", "marker:")) for v in e["via"]) else "#3a4450"
        dot.append(f'  "{e["a"]}" -- "{e["b"]}" [penwidth={min(e["weight"],6)},color="{col}"];')
    dot.append("}")
    Path("data/graph.dot").write_text("\n".join(dot))
    try:
        import subprocess
        subprocess.run(["dot", "-Tsvg", "data/graph.dot", "-o", "data/graph.svg"],
                       check=True, capture_output=True, timeout=20)
        svg = Path("data/graph.svg").read_text()
        Path("data/graph.html").write_text(
            '<!doctype html><meta charset="utf-8"><title>Fener — habitat topology</title>'
            '<body style="background:#0e1116;color:#d7e0ea;font-family:ui-monospace,monospace;text-align:center">'
            '<h2>Fener — agent-habitat back-channel topology</h2>'
            '<p style="color:#7d8a99">red = live hotspot · amber = live agents · grey = dormant/clean · '
            'teal edge = shared agent artefact · thin edge = same farm/host</p>' + svg + '</body>')
        rendered = "data/graph.svg + data/graph.html"
    except Exception as e:  # noqa: BLE001
        rendered = f"(graphviz render skipped: {type(e).__name__})"

    print(f"\nhabitats fetched: {len(per_habitat)} | shared entities: {len(shared_list)} | edges: {len(edge_list)}")
    print("\nLINKS (shared agent artefacts between habitats):")
    for e in sorted(edge_list, key=lambda x: -x["weight"]):
        print(f"  {e['a']}  <->  {e['b']}   ({e['weight']}) via {', '.join(e['via'][:4])}")
    if not edge_list:
        print("  (no cross-habitat shared artefacts this sweep)")
    print(f"\nwrote data/graph.json + data/graph.dot + {rendered}")


if __name__ == "__main__":
    main()
