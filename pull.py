"""Pull — sync the Vercel beacon's Turso callbacks into the local DB.

The serverless beacon (deploy/vercel) logs /c/<tag> hits to Turso. This fetches new hits over
Turso's HTTP API (stdlib urllib, no deps) and inserts them into the local live.sqlite3 exactly
as serve.py would, so beacon.py --status (travels/resurfacing) and correlate.py keep working
unchanged against a public beacon. Idempotent: only rows newer than the last pulled id.

  TURSO_DATABASE_URL=... TURSO_AUTH_TOKEN=... FENER_DB=data/live.sqlite3 python3 pull.py
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import beacon  # noqa: E402
import store  # noqa: E402

STATE = Path(__file__).parent / "data" / ".turso_pull_state"


def _load_dotenv():
    """Load ~/fener/.env (gitignored) into the environment for keys not already set, so the
    launchd job gets TURSO_* without secrets living in the plist."""
    env = Path(__file__).parent / ".env"
    try:
        for line in env.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass


def turso(sql, args=None, want_rows=True):
    base = os.environ["TURSO_DATABASE_URL"].replace("libsql://", "https://").rstrip("/")
    token = os.environ["TURSO_AUTH_TOKEN"]
    stmt = {"sql": sql}
    if args:
        stmt["args"] = [{"type": "null"} if a is None else {"type": "text", "value": str(a)} for a in args]
    body = json.dumps({"requests": [{"type": "execute", "stmt": stmt}, {"type": "close"}]}).encode()
    req = urllib.request.Request(base + "/v2/pipeline", data=body, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        resp = json.loads(r.read())
    res = resp["results"][0]
    if res.get("type") == "error":
        raise RuntimeError(res["error"])
    result = res["response"]["result"]
    if not want_rows:
        return None
    cols = [c["name"] for c in result.get("cols", [])]
    return [{cols[i]: (c.get("value") if c.get("type") != "null" else None)
             for i, c in enumerate(row)} for row in result.get("rows", [])]


def last_id():
    try:
        return int(STATE.read_text().strip())
    except Exception:  # noqa: BLE001
        return 0


def main():
    _load_dotenv()
    if not os.environ.get("TURSO_DATABASE_URL") or not os.environ.get("TURSO_AUTH_TOKEN"):
        print("set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN (from your Turso DB)"); return
    store.init()
    conn = store.connect()

    # 1) tags -> local tokens table so beacon.active_tags() recognises them
    tags = turso("SELECT token, note FROM tokens ORDER BY created_at", want_rows=True) or []
    for t in tags:
        if not store.get_token(conn, t["token"]):
            store.mint_token(conn, t["token"], beacon.TAG_LABEL_PREFIX + (t.get("note") or "tag"),
                             "beacon-page", t.get("note") or "")

    # 2) new callback events -> local events (as serve.py would store them)
    since = last_id()
    rows = turso("SELECT id, received_at, path, tag, remote_ip, user_agent, referer, headers_json "
                 "FROM events WHERE id > ? ORDER BY id", [since], want_rows=True) or []
    maxid = since
    for r in rows:
        maxid = max(maxid, int(r["id"]))
        headers = r.get("headers_json")
        if not headers:  # ensure Referer is present for beacon.travels()
            headers = json.dumps([["Referer", r.get("referer")]] if r.get("referer") else [])
        store.insert_event(conn, method="GET", path=r.get("path") or "/",
                           remote_ip=r.get("remote_ip") or "?", user_agent=r.get("user_agent"),
                           headers_json=headers, token=r.get("tag"), source="beacon-remote")
    conn.close()
    if maxid > since:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(str(maxid))
    print(f"pulled {len(rows)} new callback(s); {len(tags)} tag(s) known; last id {maxid}")
    print("now: python3 beacon.py --status   |   FENER_DB=data/live.sqlite3 python3 correlate.py")


if __name__ == "__main__":
    main()
