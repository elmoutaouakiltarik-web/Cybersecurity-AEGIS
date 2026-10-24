"""
AEGIS-OMNI DFIR Case Management & Timeline
Incident cases, evidence links, timeline entries, and chain of custody.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DATA_DIR = Path(os.environ.get("DFIR_DATA_DIR", "./dfir_data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "dfir.db"

CASE_STATUS = ["open", "investigating", "contained", "resolved", "closed", "archived"]
CASE_SEVERITY = ["critical", "high", "medium", "low", "informational"]


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _init_db():
    conn = _get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'open',
        severity TEXT DEFAULT 'medium',
        assigned_to TEXT,
        tags TEXT,
        source_refs TEXT,
        created_at TEXT,
        updated_at TEXT,
        resolved_at TEXT,
        it_ot_domain TEXT DEFAULT 'IT',
        safety_gate_approved INTEGER DEFAULT 0,
        playbook_id TEXT,
        artifacts TEXT
    );
    CREATE TABLE IF NOT EXISTS timeline (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        ts TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        actor TEXT,
        source TEXT,
        entity_type TEXT,
        entity_id TEXT,
        raw_event TEXT,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        filename TEXT,
        storage_path TEXT,
        hash_sha256 TEXT,
        size_bytes INTEGER,
        collected_by TEXT,
        collected_at TEXT,
        chain_of_custody TEXT,
        immutable INTEGER DEFAULT 0,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
    CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);
    CREATE INDEX IF NOT EXISTS idx_timeline_case ON timeline(case_id);
    CREATE INDEX IF NOT EXISTS idx_timeline_ts ON timeline(ts);
    """)
    conn.commit()
    conn.close()


_init_db()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    for k in ("tags", "source_refs", "artifacts", "chain_of_custody"):
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except Exception:
                pass
    for k in ("safety_gate_approved", "immutable"):
        if k in d:
            d[k] = bool(d[k])
    return d


# ============== CASES ==============

@app.route("/health", methods=["GET", "OPTIONS"])
def health():
    return jsonify({"status": "ok", "module": "dfir", "ts": _now()})


@app.route("/cases", methods=["GET", "OPTIONS"])
def list_cases():
    status = request.args.get("status", "")
    severity = request.args.get("severity", "")
    domain = request.args.get("domain", "")
    q = request.args.get("q", "").lower()
    conn = _get_db()
    cur = conn.cursor()
    sql = "SELECT * FROM cases WHERE 1=1"
    params = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if domain:
        sql += " AND it_ot_domain = ?"
        params.append(domain)
    sql += " ORDER BY created_at DESC"
    cur.execute(sql, params)
    rows = [_to_dict(r) for r in cur.fetchall()]
    if q:
        rows = [r for r in rows if q in json.dumps(r).lower()]
    conn.close()
    return jsonify({"cases": rows, "count": len(rows)})


@app.route("/cases/<case_id>", methods=["GET", "OPTIONS"])
def get_case(case_id: str):
    conn = _get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "not found"}), 404
    case = _to_dict(row)
    cur.execute("SELECT * FROM timeline WHERE case_id = ? ORDER BY ts ASC", (case_id,))
    case["timeline"] = [_to_dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY collected_at DESC", (case_id,))
    case["evidence"] = [_to_dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(case)


@app.route("/cases", methods=["POST", "OPTIONS"])
def create_case():
    data = request.get_json(force=True, silent=True) or {}
    case_id = data.get("id", f"CASE-{uuid.uuid4().hex[:12].upper()}")
    now = _now()
    conn = _get_db()
    conn.execute("""
    INSERT INTO cases (id, title, description, status, severity, assigned_to, tags, source_refs, created_at, updated_at, it_ot_domain, safety_gate_approved, playbook_id, artifacts)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        case_id, data.get("title", "Untitled"), data.get("description", ""),
        data.get("status", "open") if data.get("status", "open") in CASE_STATUS else "open",
        data.get("severity", "medium") if data.get("severity", "medium") in CASE_SEVERITY else "medium",
        data.get("assigned_to", ""), json.dumps(data.get("tags", [])),
        json.dumps(data.get("source_refs", [])), now, now, None,
        data.get("it_ot_domain", "IT"), 1 if data.get("safety_gate_approved") else 0,
        data.get("playbook_id", ""), json.dumps(data.get("artifacts", []))
    ))
    conn.commit()
    conn.close()
    return jsonify({"id": case_id, "created": True}), 201


@app.route("/cases/<case_id>", methods=["PUT", "OPTIONS"])
def update_case(case_id: str):
    data = request.get_json(force=True, silent=True) or {}
    allowed = {"title", "description", "status", "severity", "assigned_to", "tags", "source_refs", "it_ot_domain", "safety_gate_approved", "playbook_id", "artifacts"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify({"error": "no valid fields"}), 400
    if "status" in updates and updates["status"] not in CASE_STATUS:
        return jsonify({"error": f"invalid status"}), 400
    if "severity" in updates and updates["severity"] not in CASE_SEVERITY:
        return jsonify({"error": f"invalid severity"}), 400
    sets = ", ".join(f"{k} = ?" for k in updates.keys())
    values = list(updates.values())
    # JSON-serialize lists
    for i, k in enumerate(updates.keys()):
        if k in ("tags", "source_refs", "artifacts") and isinstance(values[i], list):
            values[i] = json.dumps(values[i])
        if k == "safety_gate_approved":
            values[i] = 1 if values[i] else 0
    values.append(_now())
    values.append(case_id)
    conn = _get_db()
    conn.execute(f"UPDATE cases SET {sets}, updated_at = ? WHERE id = ?", values)
    conn.commit()
    conn.close()
    return jsonify({"updated": case_id})


@app.route("/cases/<case_id>/timeline", methods=["POST", "OPTIONS"])
def add_timeline_entry(case_id: str):
    data = request.get_json(force=True, silent=True) or {}
    entry_id = data.get("id", f"TL-{uuid.uuid4().hex[:12].upper()}")
    conn = _get_db()
    conn.execute("""
    INSERT INTO timeline (id, case_id, ts, title, description, actor, source, entity_type, entity_id, raw_event)
    VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        entry_id, case_id, data.get("ts", _now()), data.get("title", "Event"),
        data.get("description", ""), data.get("actor", ""), data.get("source", ""),
        data.get("entity_type", ""), data.get("entity_id", ""),
        json.dumps(data.get("raw_event", {})) if data.get("raw_event") else None
    ))
    conn.commit()
    conn.close()
    return jsonify({"id": entry_id, "added": True}), 201


@app.route("/cases/<case_id>/evidence", methods=["POST", "OPTIONS"])
def add_evidence(case_id: str):
    data = request.get_json(force=True, silent=True) or {}
    ev_id = data.get("id", f"EV-{uuid.uuid4().hex[:12].upper()}")
    conn = _get_db()
    conn.execute("""
    INSERT INTO evidence (id, case_id, filename, storage_path, hash_sha256, size_bytes, collected_by, collected_at, chain_of_custody, immutable)
    VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        ev_id, case_id, data.get("filename", ""), data.get("storage_path", ""),
        data.get("hash_sha256", ""), data.get("size_bytes", 0),
        data.get("collected_by", ""), data.get("collected_at", _now()),
        json.dumps(data.get("chain_of_custody", [])), 1 if data.get("immutable") else 0
    ))
    conn.commit()
    conn.close()
    return jsonify({"id": ev_id, "added": True}), 201


@app.route("/timeline", methods=["GET", "OPTIONS"])
def global_timeline():
    case_id = request.args.get("case_id", "")
    entity_type = request.args.get("entity_type", "")
    from_ts = request.args.get("from", "")
    to_ts = request.args.get("to", "")
    conn = _get_db()
    cur = conn.cursor()
    sql = "SELECT * FROM timeline WHERE 1=1"
    params = []
    if case_id:
        sql += " AND case_id = ?"
        params.append(case_id)
    if entity_type:
        sql += " AND entity_type = ?"
        params.append(entity_type)
    if from_ts:
        sql += " AND ts >= ?"
        params.append(from_ts)
    if to_ts:
        sql += " AND ts <= ?"
        params.append(to_ts)
    sql += " ORDER BY ts DESC LIMIT 500"
    cur.execute(sql, params)
    rows = [_to_dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"entries": rows, "count": len(rows)})


@app.route("/stats", methods=["GET", "OPTIONS"])
def stats():
    conn = _get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, COUNT(*) FROM cases GROUP BY status")
    by_status = {r["status"]: r[1] for r in cur.fetchall()}
    cur.execute("SELECT severity, COUNT(*) FROM cases GROUP BY severity")
    by_severity = {r["severity"]: r[1] for r in cur.fetchall()}
    cur.execute("SELECT it_ot_domain, COUNT(*) FROM cases GROUP BY it_ot_domain")
    by_domain = {r["it_ot_domain"]: r[1] for r in cur.fetchall()}
    cur.execute("SELECT COUNT(*) FROM timeline")
    timeline_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM evidence")
    evidence_count = cur.fetchone()[0]
    conn.close()
    return jsonify({
        "cases_by_status": by_status,
        "cases_by_severity": by_severity,
        "cases_by_domain": by_domain,
        "timeline_entries": timeline_count,
        "evidence_items": evidence_count,
    })


if __name__ == "__main__":
    port = int(os.environ.get("DFIR_PORT", "8093"))
    BIND_HOST = os.environ.get("DFIR_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, threaded=True, use_reloader=False)
