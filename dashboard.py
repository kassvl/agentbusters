"""Fener control room — a localhost dashboard for the agent-habitat hunt.

Shows, live: what stage the hunt is at, every mapped habitat with its text-trace score AND
its edit-level live-agent count (the honest signal), the ProWiki-farm cluster, recent
sightings and alerts. "Sweep now" runs a background hunt+analyze and the page updates.

  python3 dashboard.py            # http://127.0.0.1:8033
  python3 dashboard.py --sweep    # sweep once on startup, then serve

Read-only reconnaissance; binds 127.0.0.1 only.
"""

import argparse
import html
import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import analyze
import store
import traces

ALERTS = Path(__file__).parent / "data" / "alerts.log"
UA = "fener-dashboard/0.1 (read-only; +research)"
STATUS = {"running": False, "phase": "idle", "done": 0, "total": 0, "current": None, "last": None}


def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(800_000).decode("utf-8", "replace")


def sweep():
    if STATUS["running"]:
        return
    STATUS.update(running=True, phase="sweeping", done=0, total=len(traces.KNOWN_HABITATS))
    conn = store.connect()
    store.init()
    for h in traces.KNOWN_HABITATS:
        name = h["name"]
        url = h.get("recent") or h["url"]
        STATUS["current"] = name
        try:
            text = fetch(url)
            score, hits = traces.scan(text)
            import hashlib
            excerpt = " ".join(text.split())[:500]
            store.add_sighting(conn, name, url, score, hits, excerpt,
                               hashlib.sha256(excerpt.encode()).hexdigest()[:16], "dashboard")
            if "wiki.cgi" in url or "wiki.pl" in url:
                a = analyze.analyze(name, url)
                if not a.get("error"):
                    store.add_analysis(conn, name, a["edits"], a["agent"], a["anon"],
                                       a["human"], a["verdict"], a["agent_authors"])
        except Exception as e:  # noqa: BLE001
            store.add_sighting(conn, name, url, 0, [{"signal": f"error:{type(e).__name__}"}],
                               "", "", "dashboard")
        STATUS["done"] += 1
        time.sleep(1.0)
    conn.close()
    STATUS.update(running=False, phase="idle", current=None, last=time.strftime("%H:%M:%SZ", time.gmtime()))


def clusters():
    by_dom = {}
    for h in traces.KNOWN_HABITATS:
        dom = urlparse(h["url"]).netloc.removeprefix("www.")
        by_dom.setdefault(dom, []).append(h["name"])
    return {d: n for d, n in by_dom.items() if len(n) > 1}


def state():
    conn = store.connect()
    store.init()
    analysis = {r["habitat"]: r for r in store.latest_analysis(conn)}
    sightings = store.recent_sightings(conn, 400)
    latest_score = {}
    for s in sightings:
        latest_score.setdefault(s["habitat"], s)
    shared = store.shared_entities(conn)
    conn.close()
    rows = []
    for h in traces.KNOWN_HABITATS:
        n = h["name"]
        s = latest_score.get(n)
        a = analysis.get(n)
        rows.append({
            "habitat": n, "engine": h.get("engine", ""), "url": h.get("recent") or h["url"],
            "score": s["score"] if s else None,
            "agent": a["agent"] if a else None, "human": a["human"] if a else None,
            "verdict": a["verdict"] if a else None,
            "authors": (json.loads(a["agent_authors"]) if a and a["agent_authors"] else []),
        })
    rows.sort(key=lambda r: (r["agent"] or -1, r["score"] or -1), reverse=True)
    alerts = []
    if ALERTS.exists():
        alerts = ALERTS.read_text().splitlines()[-12:][::-1]
    return {"rows": rows, "shared": [(k, v, hs) for k, v, hs, _ in shared][:20],
            "clusters": clusters(), "alerts": alerts,
            "recent": [{"habitat": s["habitat"], "score": s["score"], "at": s["observed_at"][:19]}
                       for s in sightings[:12]]}


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Fener control room</title>
<meta http-equiv="refresh" content="12">
<style>
:root{{--bg:#0e1116;--card:#161b22;--line:#232b36;--ink:#d7e0ea;--dim:#7d8a99;--hot:#ff5a52;--warm:#e3b341;--ok:#3fb950;--teal:#39c5cf}}
*{{box-sizing:border-box}} body{{font:14px/1.5 ui-monospace,Menlo,monospace;background:var(--bg);color:var(--ink);margin:0;padding:24px;max-width:1100px;margin:auto}}
h1{{font-size:17px;margin:0 0 2px}} .sub{{color:var(--dim);font-size:12px;margin-bottom:18px}}
.tiles{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:130px}}
.tile b{{font-size:22px;display:block}} .tile span{{color:var(--dim);font-size:11px}}
.status{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin-bottom:18px;display:flex;justify-content:space-between;align-items:center}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden;margin-bottom:18px}}
th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);font-size:13px}} th{{color:var(--dim);font-weight:normal;font-size:11px;text-transform:uppercase}}
tr:last-child td{{border-bottom:0}} .hot{{color:var(--hot);font-weight:bold}} .ok{{color:var(--ok)}} .warm{{color:var(--warm)}} .dim{{color:var(--dim)}}
a.btn{{background:var(--teal);color:#04252a;padding:7px 14px;border-radius:6px;text-decoration:none;font-weight:bold}}
h2{{font-size:12px;color:var(--dim);text-transform:uppercase;margin:18px 0 8px}} code{{color:var(--teal)}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px}} .box{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;font-size:12px}}
.box div{{padding:3px 0;border-bottom:1px solid var(--line)}} .box div:last-child{{border:0}}
</style></head><body>
<h1>🔦 Fener — agent-habitat control room</h1>
<div class="sub">where autonomous agents already live · read-only reconnaissance · auto-refresh 12s</div>
<div class="status"><div>{status}</div><div><a class="btn" href="/graph" style="background:#39c5cf;margin-right:8px">🕸 Topology</a><a class="btn" href="/sweep">▶ Sweep now</a></div></div>
<div class="tiles">{tiles}</div>
<h2>Habitats — text-trace score vs LIVE agent edits (the honest signal)</h2>
<table><tr><th>habitat</th><th>engine</th><th>score</th><th>live agents</th><th>humans</th><th>verdict</th></tr>
{table}</table>
<div class="grid">
<div><h2>ProWiki farm cluster & shared artefacts</h2><div class="box">{clusters}</div></div>
<div><h2>Alerts &amp; recent sightings</h2><div class="box">{alerts}</div></div>
</div>
</body></html>"""


def render():
    st = state()
    live = [r for r in st["rows"] if (r["agent"] or 0) > 0]
    total_agent = sum((r["agent"] or 0) for r in st["rows"])
    hotspot = max(st["rows"], key=lambda r: (r["agent"] or 0))
    if STATUS["running"]:
        status = f'⏳ sweeping {STATUS["done"]}/{STATUS["total"]} — {html.escape(str(STATUS["current"]))}'
    else:
        status = f'✔ idle · last sweep {STATUS["last"] or "—"} · {len(traces.KNOWN_HABITATS)} habitats mapped'
    tiles = "".join([
        f'<div class="tile"><b>{len(traces.KNOWN_HABITATS)}</b><span>HABITATS MAPPED</span></div>',
        f'<div class="tile"><b class="hot">{len(live)}</b><span>LIVE-AGENT SITES</span></div>',
        f'<div class="tile"><b class="hot">{total_agent}</b><span>LIVE AGENT EDITS</span></div>',
        f'<div class="tile"><b class="warm">{hotspot["agent"] or 0}</b><span>HOTSPOT: {html.escape(hotspot["habitat"])}</span></div>',
    ])
    trows = []
    for r in st["rows"]:
        sc = "—" if r["score"] is None else str(r["score"])
        ag = r["agent"]
        agc = "hot" if (ag or 0) > 0 else "dim"
        verdict = r["verdict"] or "—"
        vc = "hot" if verdict == "LIVE-AGENTS" else ("dim" if verdict.startswith("dormant") else "")
        trows.append(
            f'<tr><td><a href="{html.escape(r["url"])}" style="color:var(--teal)">{html.escape(r["habitat"])}</a></td>'
            f'<td class="dim">{html.escape(r["engine"])[:26]}</td><td>{sc}</td>'
            f'<td class="{agc}">{"—" if ag is None else ag}</td><td class="dim">{"—" if r["human"] is None else r["human"]}</td>'
            f'<td class="{vc}">{html.escape(verdict)}</td></tr>'
        )
    cl = "".join(f'<div><b class="teal">{html.escape(d)}</b>: {html.escape(", ".join(n))}</div>'
                 for d, n in st["clusters"].items())
    cl += "".join(f'<div class="dim">shared {html.escape(k)}: {html.escape(v)} @ {html.escape(",".join(hs))}</div>'
                  for k, v, hs in st["shared"][:6]) or ""
    al = "".join(f'<div class="warm">{html.escape(a[:90])}</div>' for a in st["alerts"]) or '<div class="dim">no alerts yet</div>'
    al += "".join(f'<div class="dim">{html.escape(s["at"])} {html.escape(s["habitat"])} ({s["score"]})</div>' for s in st["recent"][:6])
    return PAGE.format(status=status, tiles=tiles, table="".join(trows), clusters=cl or "—", alerts=al)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/traversal"):
            conn = store.connect()
            store.init()
            rows = [dict(r) for r in store.traversal_path(conn)]
            conn.close()
            self._send(200, json.dumps({"latest_gps_track": rows}, ensure_ascii=False, indent=2),
                       "application/json; charset=utf-8")
            return
        if self.path.startswith("/graph"):
            f = Path(__file__).parent / "data" / "graph.html"
            if f.exists():
                self._send(200, f.read_text())
            else:
                self._send(200, "<body style='background:#0e1116;color:#d7e0ea;font-family:monospace'>"
                                "No graph yet — run <code>python3 graph.py</code>. <a href='/' style='color:#39c5cf'>back</a></body>")
            return
        if self.path.startswith("/sweep"):
            if not STATUS["running"]:
                threading.Thread(target=sweep, daemon=True).start()
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            return
        if self.path.startswith("/api/state"):
            self._send(200, json.dumps({"status": STATUS, **state()}, ensure_ascii=False),
                       "application/json; charset=utf-8")
            return
        self._send(200, render())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8033)
    ap.add_argument("--sweep", action="store_true", help="sweep once on startup")
    args = ap.parse_args()
    store.init()
    if args.sweep:
        threading.Thread(target=sweep, daemon=True).start()
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Fener control room: http://127.0.0.1:{args.port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
