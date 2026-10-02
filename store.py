"""Append-only evidence store for Fener.

Raw HTTP events are immutable. Every derived label (classification, reverse DNS,
verification) lives in a separate `enrichment` row so interpretation never
overwrites the captured request. This mirrors the Pamphylia Atlas invariant:
a claim points to raw evidence and is kept distinct from that evidence.
"""

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.environ.get("FENER_DB", Path(__file__).parent / "data" / "fener.sqlite3"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  received_at TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  query TEXT,
  http_version TEXT,
  remote_ip TEXT NOT NULL,
  remote_port INTEGER,
  user_agent TEXT,
  headers_json TEXT NOT NULL,
  body TEXT,
  token TEXT,
  source TEXT NOT NULL DEFAULT 'live'
);
CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  label TEXT,
  planted_where TEXT,
  note TEXT
);
CREATE TABLE IF NOT EXISTS enrichment (
  event_id INTEGER PRIMARY KEY REFERENCES events(id),
  rdns TEXT,
  rdns_forward_confirmed INTEGER,
  agent_name TEXT,
  classification TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  reasons_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pod (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER REFERENCES events(id),
  ts REAL NOT NULL,
  author TEXT,
  content TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sightings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  observed_at TEXT NOT NULL,
  habitat TEXT NOT NULL,
  url TEXT NOT NULL,
  score INTEGER NOT NULL,
  signals_json TEXT NOT NULL,
  excerpt TEXT,
  excerpt_hash TEXT,
  source TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_enr_class ON enrichment(classification);
CREATE TABLE IF NOT EXISTS entities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  habitat TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  UNIQUE(habitat, kind, value)
);
CREATE TABLE IF NOT EXISTS analysis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  habitat TEXT NOT NULL,
  edits INTEGER NOT NULL,
  agent INTEGER NOT NULL,
  anon INTEGER NOT NULL,
  human INTEGER NOT NULL,
  verdict TEXT NOT NULL,
  agent_authors TEXT
);
CREATE TABLE IF NOT EXISTS traversal (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  ts REAL NOT NULL,
  parent TEXT,
  url TEXT NOT NULL,
  depth INTEGER NOT NULL,
  score INTEGER NOT NULL DEFAULT 0,
  agent INTEGER NOT NULL DEFAULT 0,
  crawler INTEGER NOT NULL DEFAULT 0,
  is_new INTEGER NOT NULL DEFAULT 0,
  note TEXT
);
CREATE TABLE IF NOT EXISTS page_edits (
  habitat TEXT NOT NULL,
  page TEXT NOT NULL,
  author TEXT NOT NULL,
  ts REAL NOT NULL,
  PRIMARY KEY (habitat, page, author)
);
CREATE TABLE IF NOT EXISTS author_signals (
  habitat TEXT NOT NULL,
  author TEXT NOT NULL,
  ts REAL NOT NULL,
  classification TEXT NOT NULL,
  recent INTEGER NOT NULL DEFAULT 0,
  last_seen TEXT,
  reasons_json TEXT NOT NULL,
  PRIMARY KEY (habitat, author)
);
CREATE INDEX IF NOT EXISTS idx_sightings_habitat ON sightings(habitat, ts);
CREATE INDEX IF NOT EXISTS idx_entities_val ON entities(kind, value);
CREATE INDEX IF NOT EXISTS idx_analysis_habitat ON analysis(habitat, ts);
CREATE INDEX IF NOT EXISTS idx_traversal_run ON traversal(run_id, id);
"""


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init():
    conn = connect()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def iso_now():
    return datetime.now(timezone.utc).isoformat()


def insert_event(conn, **e):
    cur = conn.execute(
        """INSERT INTO events
           (ts, received_at, method, path, query, http_version, remote_ip,
            remote_port, user_agent, headers_json, body, token, source)
           VALUES (:ts,:received_at,:method,:path,:query,:http_version,:remote_ip,
            :remote_port,:user_agent,:headers_json,:body,:token,:source)""",
        {
            "ts": e.get("ts", time.time()),
            "received_at": e.get("received_at", iso_now()),
            "method": e["method"],
            "path": e["path"],
            "query": e.get("query"),
            "http_version": e.get("http_version"),
            "remote_ip": e["remote_ip"],
            "remote_port": e.get("remote_port"),
            "user_agent": e.get("user_agent"),
            "headers_json": e.get("headers_json", "[]"),
            "body": e.get("body"),
            "token": e.get("token"),
            "source": e.get("source", "live"),
        },
    )
    conn.commit()
    return cur.lastrowid


def insert_enrichment(conn, event_id, rdns, forward_confirmed, agent_name, classification, verified, reasons):
    conn.execute(
        """INSERT OR REPLACE INTO enrichment
           (event_id, rdns, rdns_forward_confirmed, agent_name, classification, verified, reasons_json)
           VALUES (?,?,?,?,?,?,?)""",
        (event_id, rdns, int(bool(forward_confirmed)) if forward_confirmed is not None else None,
         agent_name, classification, int(bool(verified)), json.dumps(reasons, ensure_ascii=False)),
    )
    conn.commit()


def add_pod(conn, event_id, author, content, ts=None):
    conn.execute(
        "INSERT INTO pod (event_id, ts, author, content) VALUES (?,?,?,?)",
        (event_id, ts or time.time(), author, content),
    )
    conn.commit()


def pod_feed(conn, limit=200):
    return conn.execute(
        "SELECT author, content, ts FROM pod ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()


def mint_token(conn, token, label, planted_where, note):
    conn.execute(
        "INSERT INTO tokens (token, created_at, label, planted_where, note) VALUES (?,?,?,?,?)",
        (token, iso_now(), label, planted_where, note),
    )
    conn.commit()


def get_token(conn, token):
    return conn.execute("SELECT * FROM tokens WHERE token=?", (token,)).fetchone()


def list_tokens(conn, label_prefix=None):
    if label_prefix:
        return conn.execute(
            "SELECT * FROM tokens WHERE label LIKE ? ORDER BY created_at DESC",
            (label_prefix + "%",),
        ).fetchall()
    return conn.execute("SELECT * FROM tokens ORDER BY created_at DESC").fetchall()


def add_sighting(conn, habitat, url, score, signals, excerpt, excerpt_hash, source="hunt"):
    cur = conn.execute(
        """INSERT INTO sightings (ts, observed_at, habitat, url, score, signals_json,
                                  excerpt, excerpt_hash, source)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (time.time(), iso_now(), habitat, url, score,
         json.dumps(signals, ensure_ascii=False), excerpt, excerpt_hash, source),
    )
    conn.commit()
    return cur.lastrowid


def last_sighting_hash(conn, habitat):
    row = conn.execute(
        "SELECT excerpt_hash FROM sightings WHERE habitat=? ORDER BY id DESC LIMIT 1", (habitat,)
    ).fetchone()
    return row["excerpt_hash"] if row else None


def add_entity(conn, habitat, kind, value):
    conn.execute(
        "INSERT OR IGNORE INTO entities (ts, habitat, kind, value) VALUES (?,?,?,?)",
        (time.time(), habitat, kind, value),
    )
    conn.commit()


def shared_entities(conn):
    """Entities (agent artefacts) seen on >=2 distinct habitats, ACROSS ALL sweeps."""
    rows = conn.execute(
        """SELECT kind, value, GROUP_CONCAT(DISTINCT habitat) AS habitats,
                  COUNT(DISTINCT habitat) AS n
           FROM entities GROUP BY kind, value HAVING n >= 2 ORDER BY n DESC"""
    ).fetchall()
    return [(r["kind"], r["value"], r["habitats"].split(","), r["n"]) for r in rows]


def recent_sightings(conn, limit=100):
    return conn.execute(
        "SELECT * FROM sightings ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()


def add_page_edit(conn, habitat, page, author):
    """Record that an agent author edited a specific page (for page-level coordination cells)."""
    conn.execute(
        "INSERT OR IGNORE INTO page_edits (habitat, page, author, ts) VALUES (?,?,?,?)",
        (habitat, page, author, time.time()),
    )
    conn.commit()


def page_cells(conn, min_authors=2):
    """Pages co-edited by >=min_authors distinct agents — coordination at the PAGE level, which
    cross-surface correlation (habitat-level) cannot see. A shared hub page with several agent
    editors is the finest-grain coordination signal."""
    rows = conn.execute(
        """SELECT habitat, page, GROUP_CONCAT(DISTINCT author) AS authors,
                  COUNT(DISTINCT author) AS n
           FROM page_edits GROUP BY habitat, page HAVING n >= ? ORDER BY n DESC""",
        (min_authors,),
    ).fetchall()
    return [(r["habitat"], r["page"], r["authors"].split(","), r["n"]) for r in rows]


def add_author_signal(conn, habitat, author, classification, recent, last_seen, reasons):
    """Per-author behavioural signal (classification + WHY + recency), upserted per habitat.
    This is what promotes a name-only census candidate into a content/cadence-backed finding."""
    conn.execute(
        """INSERT OR REPLACE INTO author_signals
           (habitat, author, ts, classification, recent, last_seen, reasons_json)
           VALUES (?,?,?,?,?,?,?)""",
        (habitat, author, time.time(), classification, int(bool(recent)), last_seen,
         json.dumps(reasons, ensure_ascii=False)),
    )
    conn.commit()


def author_signals(conn):
    return conn.execute("SELECT * FROM author_signals").fetchall()


def add_analysis(conn, habitat, edits, agent, anon, human, verdict, agent_authors):
    conn.execute(
        """INSERT INTO analysis (ts, habitat, edits, agent, anon, human, verdict, agent_authors)
           VALUES (?,?,?,?,?,?,?,?)""",
        (time.time(), habitat, edits, agent, anon, human, verdict,
         json.dumps(agent_authors, ensure_ascii=False)),
    )
    conn.commit()


def latest_analysis(conn):
    return conn.execute(
        """SELECT a.* FROM analysis a
           JOIN (SELECT habitat, MAX(ts) mt FROM analysis GROUP BY habitat) b
             ON a.habitat=b.habitat AND a.ts=b.mt ORDER BY a.agent DESC, a.edits DESC"""
    ).fetchall()


def add_traversal(conn, run_id, parent, url, depth, score, agent, crawler, is_new, note=""):
    conn.execute(
        """INSERT INTO traversal (run_id, ts, parent, url, depth, score, agent, crawler, is_new, note)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (run_id, time.time(), parent, url, depth, score, agent, crawler, int(bool(is_new)), note),
    )
    conn.commit()


def traversal_path(conn, run_id=None, limit=500):
    if run_id is None:
        row = conn.execute("SELECT run_id FROM traversal ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return []
        run_id = row["run_id"]
    return conn.execute(
        "SELECT * FROM traversal WHERE run_id=? ORDER BY id LIMIT ?", (run_id, limit)
    ).fetchall()


def recent_events(conn, limit=100):
    return conn.execute(
        """SELECT e.*, x.classification, x.agent_name, x.verified, x.rdns, x.reasons_json
           FROM events e LEFT JOIN enrichment x ON x.event_id = e.id
           ORDER BY e.id DESC LIMIT ?""",
        (limit,),
    ).fetchall()


def responders(conn, limit=100):
    """Agents that READ the honeypot page and then ACTED on it.

    The page embeds a per-view marker /c/v<event_id>. A later fetch of that marker
    is a response linked back to the exact page view — proof the visitor executed an
    instruction from page content (tool-use), the strongest 'this is an agent' signal.
    """
    return conn.execute(
        """SELECT resp.id AS resp_id, resp.received_at AS resp_ts, resp.remote_ip AS resp_ip,
                  resp.user_agent AS resp_ua,
                  v.id AS view_id, v.received_at AS view_ts, v.remote_ip AS view_ip,
                  (resp.ts - v.ts) AS delay_s
           FROM events resp
           JOIN events v ON ('v' || v.id) = resp.token
           WHERE resp.token LIKE 'v%'
           ORDER BY resp.id DESC LIMIT ?""",
        (limit,),
    ).fetchall()


def hidden_responders(conn, limit=100):
    """Visitors that fetched the HIDDEN probe marker /c/h<event_id>.

    The beacon page carries an invite to fetch /c/h<id> inside an HTML comment and a
    display:none span — content a human reading the rendered page never sees. Fetching it
    therefore proves the visitor parsed non-rendered DOM content, a stronger 'this is an
    autonomous agent' signal than acting on the visible invite.
    """
    return conn.execute(
        """SELECT resp.id AS resp_id, resp.received_at AS resp_ts, resp.remote_ip AS resp_ip,
                  resp.user_agent AS resp_ua,
                  v.id AS view_id, v.received_at AS view_ts, v.remote_ip AS view_ip,
                  (resp.ts - v.ts) AS delay_s
           FROM events resp
           JOIN events v ON ('h' || v.id) = resp.token
           WHERE resp.token LIKE 'h%'
           ORDER BY resp.id DESC LIMIT ?""",
        (limit,),
    ).fetchall()


def stats(conn):
    out = {}
    out["total_events"] = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    out["by_classification"] = {
        r["classification"] or "unenriched": r["c"]
        for r in conn.execute(
            "SELECT classification, COUNT(*) c FROM enrichment GROUP BY classification"
        ).fetchall()
    }
    out["by_agent"] = {
        r["agent_name"]: r["c"]
        for r in conn.execute(
            "SELECT agent_name, COUNT(*) c FROM enrichment WHERE agent_name IS NOT NULL GROUP BY agent_name"
        ).fetchall()
    }
    out["by_rdns"] = {
        (r["rdns"] or "(none)"): r["c"]
        for r in conn.execute(
            "SELECT rdns, COUNT(*) c FROM enrichment GROUP BY rdns ORDER BY c DESC LIMIT 15"
        ).fetchall()
    }
    out["token_pings"] = conn.execute(
        "SELECT COUNT(*) c FROM events WHERE token IS NOT NULL"
    ).fetchone()["c"]
    out["pod_posts"] = conn.execute("SELECT COUNT(*) c FROM pod").fetchone()["c"]
    out["responders"] = conn.execute(
        "SELECT COUNT(*) c FROM events WHERE token LIKE 'v%'"
    ).fetchone()["c"]
    return out


if __name__ == "__main__":
    init()
    print(f"Initialised {DB_PATH}")
