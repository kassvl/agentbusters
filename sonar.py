"""Passive sonar — fold existing web-server access logs into the Fener store.

Your live sites already receive agent traffic. This imports their logs so the same
classifier and provenance discipline apply to data you already hold. Supports the
Combined Log Format (Apache/nginx) and JSON lines (Caddy). Imported events carry
source='imported'. Reverse-DNS is done unless --no-dns (historical IPs may have
changed owners since; the raw line is always preserved).

Usage:
  python3 sonar.py access.log                 # auto-detect format
  python3 sonar.py caddy.log --format json
  python3 sonar.py access.log --no-dns --limit 5000
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import enrich  # noqa: E402
import store  # noqa: E402

import re

CLF = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]+)"'
    r' (?P<status>\d+) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_clf_time(s):
    try:
        return datetime.strptime(s.split()[0], "%d/%b/%Y:%H:%M:%S").timestamp()
    except Exception:
        return time.time()


def rows_from_clf(text):
    for line in text.splitlines():
        m = CLF.match(line)
        if not m:
            continue
        d = m.groupdict()
        path = d["path"]
        query = None
        if "?" in path:
            path, query = path.split("?", 1)
        yield {
            "ts": parse_clf_time(d["ts"]),
            "method": d["method"],
            "path": path,
            "query": query,
            "http_version": d["proto"],
            "remote_ip": d["ip"],
            "user_agent": d.get("ua") or None,
            "headers": [["User-Agent", d.get("ua") or ""], ["Referer", d.get("referer") or ""]],
            "raw": line,
        }


def rows_from_json(text):
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        # Vercel log-drain / `vercel logs --json`: HTTP details live under "proxy".
        px = j.get("proxy")
        if isinstance(px, dict):
            ua = px.get("userAgent")
            if isinstance(ua, list):
                ua = ua[0] if ua else None
            uri = px.get("path") or "/"
            path, _, query = uri.partition("?")
            ts = j.get("timestamp") or px.get("timestamp") or time.time() * 1000
            yield {
                "ts": (ts / 1000.0) if ts and ts > 1e12 else (ts or time.time()),
                "method": px.get("method", "GET"),
                "path": path,
                "query": query or None,
                "http_version": None,
                "remote_ip": px.get("clientIp") or "0.0.0.0",
                "user_agent": ua,
                "headers": [["User-Agent", ua or ""], ["Referer", px.get("referer") or ""]],
                "raw": line,
            }
            continue
        req = j.get("request", j)
        headers = req.get("headers", {}) or {}
        ua = headers.get("User-Agent")
        if isinstance(ua, list):
            ua = ua[0] if ua else None
        uri = req.get("uri") or req.get("url") or j.get("path") or "/"
        path, _, query = uri.partition("?")
        hlist = []
        for k, v in headers.items():
            hlist.append([k, v[0] if isinstance(v, list) and v else v])
        yield {
            "ts": j.get("ts", time.time()),
            "method": req.get("method", "GET"),
            "path": path,
            "query": query or None,
            "http_version": req.get("proto"),
            "remote_ip": req.get("remote_ip") or req.get("client_ip") or req.get("remote_addr") or "0.0.0.0",
            "user_agent": ua,
            "headers": hlist or [["User-Agent", ua or ""]],
            "raw": line,
        }


def main():
    ap = argparse.ArgumentParser(description="Import access logs into the Fener store")
    ap.add_argument("logfile")
    ap.add_argument("--format", choices=["clf", "json", "auto"], default="auto")
    ap.add_argument("--no-dns", action="store_true", help="skip reverse-DNS (faster; use for big/old logs)")
    ap.add_argument("--limit", type=int, default=0, help="stop after N parsed rows (0 = all)")
    args = ap.parse_args()

    text = Path(args.logfile).read_text(errors="replace")
    fmt = args.format
    if fmt == "auto":
        fmt = "json" if text.lstrip()[:1] == "{" else "clf"
    rows = rows_from_json(text) if fmt == "json" else rows_from_clf(text)

    store.init()
    conn = store.connect()
    n = 0
    by_class = {}
    for r in rows:
        eid = store.insert_event(
            conn,
            ts=r["ts"],
            received_at=datetime.fromtimestamp(r["ts"], timezone.utc).isoformat(),
            method=r["method"],
            path=r["path"],
            query=r["query"],
            http_version=r["http_version"],
            remote_ip=r["remote_ip"],
            remote_port=None,
            user_agent=r["user_agent"],
            headers_json=json.dumps(r["headers"], ensure_ascii=False),
            body=None,
            token=None,
            source="imported",
        )
        if args.no_dns:
            cls, name, verified, reasons = _classify_no_dns(r)
            rdns, fc = None, None
        else:
            cls, name, verified, reasons, rdns, fc = enrich.classify(
                method=r["method"], path=r["path"], query=r["query"],
                headers=r["headers"], remote_ip=r["remote_ip"], user_agent=r["user_agent"],
            )
        store.insert_enrichment(conn, eid, rdns, fc, name, cls, verified, reasons)
        by_class[cls] = by_class.get(cls, 0) + 1
        n += 1
        if args.limit and n >= args.limit:
            break
    conn.close()
    print(f"imported {n} events from {args.logfile} ({fmt})")
    for k, v in sorted(by_class.items(), key=lambda x: -x[1]):
        print(f"  {v:>6}  {k}")


def _classify_no_dns(r):
    """UA-only classification when reverse DNS is skipped."""
    agent = enrich.match_agent(r["user_agent"] or "")
    if agent:
        return ("claimed_agent_unconfirmed", agent["name"], False,
                [f"UA matches {agent['name']} ({agent['kind']})", "rdns skipped (--no-dns)"])
    ua = (r["user_agent"] or "").lower()
    if "mozilla" in ua and any(t in ua for t in enrich.BROWSER_TOKENS):
        return ("likely_human", None, False, ["browser UA", "rdns skipped"])
    return ("unknown", None, False, ["no UA match", "rdns skipped"])


if __name__ == "__main__":
    main()
