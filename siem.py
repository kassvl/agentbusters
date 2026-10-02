"""SIEM export — emit Fener findings as CEF and JSON lines for a security platform.

A sensor nobody can pipe into a SIEM stays a toy. This turns Fener's findings — an agent that
read the beacon then acted, a dolphin tag that surfaced on a surface we do not scan, a tag
re-emitted where we do, and a coordinated cross-surface cluster — into ArcSight CEF or
JSON-lines that Splunk/Elastic/Sentinel ingest directly. Read-only over the evidence store.

  python3 siem.py                 # CEF lines for every current finding
  python3 siem.py --json          # JSON lines instead
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import beacon  # noqa: E402
import correlate  # noqa: E402
import store  # noqa: E402

VENDOR = "Fener"
PRODUCT = "beacon"
VERSION = "0.2"

# Signature IDs + severities (0-10) for each finding class.
SIG = {
    "responder": ("FENER-100", "Agent read beacon then acted on its content", 7),
    "hidden_responder": ("FENER-101", "Agent parsed non-rendered content a human never sees", 8),
    "travel": ("FENER-200", "Beacon tag surfaced on an UNSCANNED surface", 9),
    "resurfacing": ("FENER-201", "Beacon tag re-emitted on a scanned surface", 8),
    "cluster": ("FENER-300", "Coordinated cross-surface agent cluster", 9),
}


def _cef_escape(v):
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def _hdr_escape(v):
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def to_cef(finding):
    """Render one finding dict (kind + ext) as a single CEF line."""
    sig, name, sev = SIG[finding["kind"]]
    ext = " ".join(f"{k}={_cef_escape(v)}" for k, v in finding["ext"].items() if v not in (None, ""))
    return (f"CEF:0|{_hdr_escape(VENDOR)}|{_hdr_escape(PRODUCT)}|{VERSION}|"
            f"{sig}|{_hdr_escape(name)}|{sev}|{ext}")


def collect_findings(conn):
    """Gather every current finding as a list of {kind, ext} dicts (newest signals first)."""
    findings = []

    for r in store.responders(conn, 200):
        findings.append({"kind": "responder", "ext": {
            "src": r["resp_ip"], "suser": r["resp_ua"], "rt": r["resp_ts"],
            "cs1Label": "readEvent", "cs1": r["view_id"],
            "cn1Label": "delaySeconds",
            "cn1": round(r["delay_s"], 1) if r["delay_s"] is not None else None,
            "cs2Label": "sameIP", "cs2": r["resp_ip"] == r["view_ip"]}})

    for r in store.hidden_responders(conn, 200):
        findings.append({"kind": "hidden_responder", "ext": {
            "src": r["resp_ip"], "suser": r["resp_ua"], "rt": r["resp_ts"],
            "cs1Label": "readEvent", "cs1": r["view_id"],
            "cn1Label": "delaySeconds",
            "cn1": round(r["delay_s"], 1) if r["delay_s"] is not None else None}})

    for t in beacon.travels(conn):
        if t["off_beacon"]:
            findings.append({"kind": "travel", "ext": {
                "src": t["ip"], "requestClientApplication": t["ua"],
                "request": t["referer"], "cs1Label": "tag", "cs1": t["tag"], "rt": t["seen"]}})

    for x in beacon.resurfacing(conn):
        findings.append({"kind": "resurfacing", "ext": {
            "cs1Label": "tag", "cs1": x["tag"], "cs2Label": "surface", "cs2": x["surface"],
            "request": x["url"], "rt": x["seen"]}})

    res = correlate.analyse(conn)
    for c in res["coordinated_clusters"]:
        findings.append({"kind": "cluster", "ext": {
            "cs1Label": "habitats", "cs1": ",".join(c["habitats"]),
            "cn1Label": "surfaceCount", "cn1": c["n_habitats"],
            "cs2Label": "sharedSignals", "cs2": ",".join(c["signals"][:8])}})
    return findings


def export(conn, fmt="cef"):
    findings = collect_findings(conn)
    if fmt == "json":
        out = []
        for f in findings:
            sig, name, sev = SIG[f["kind"]]
            out.append(json.dumps({"vendor": VENDOR, "product": PRODUCT, "sig": sig,
                                   "name": name, "severity": sev, "kind": f["kind"],
                                   **f["ext"]}, ensure_ascii=False))
        return out
    return [to_cef(f) for f in findings]


def main():
    ap = argparse.ArgumentParser(description="Export Fener findings as CEF/JSON for a SIEM")
    ap.add_argument("--json", action="store_true", help="JSON lines instead of CEF")
    args = ap.parse_args()
    store.init()
    conn = store.connect()
    lines = export(conn, "json" if args.json else "cef")
    conn.close()
    if not lines:
        sys.stderr.write("# no findings yet (no responders, tag travel, or clusters)\n")
    for ln in lines:
        print(ln)


if __name__ == "__main__":
    main()
