"""
AEGIS-OMNI Evidence Store
Immutable/WORM evidence storage with SHA-256 verification and chain of custody.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

STORE_DIR = Path(os.environ.get("EVIDENCE_STORE_DIR", "./evidence_store"))
STORE_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = STORE_DIR / "evidence.db"


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _init_db():
    conn = _get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS artifacts (
        id TEXT PRIMARY KEY,
        case_id TEXT,
        filename TEXT NOT NULL,
        storage_path TEXT NOT NULL,
        hash_sha256 TEXT NOT NULL,
        size_bytes INTEGER,
        mime_type TEXT,
        source TEXT,
        collected_by TEXT,
        collected_at TEXT,
        tags TEXT,
        description TEXT,
        immutable INTEGER DEFAULT 1,
        retention_days INTEGER,
        expires_at TEXT,
        chain_of_custody TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
    CREATE INDEX IF NOT EXISTS idx_artifacts_hash ON artifacts(hash_sha256);
    """)
    conn.commit()
    conn.close()


_init_db()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


@app.route("/health", methods=["GET", "OPTIONS"])
def health():
    total = sum(1 for _ in STORE_DIR.iterdir() if _.is_file())
    return jsonify({"status": "ok", "module": "evidence", "stored_files": total, "store_dir": str(STORE_DIR), "ts": _now()})


@app.route("/upload", methods=["POST", "OPTIONS"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "empty filename"}), 400

    case_id = request.form.get("case_id", "")
    description = request.form.get("description", "")
    source = request.form.get("source", "")
    collected_by = request.form.get("collected_by", "")
    tags = [t.strip() for t in request.form.get("tags", "").split(",") if t.strip()]
    retention_days = int(request.form.get("retention_days", "2555"))  # ~7 years default
    immutable = request.form.get("immutable", "1") == "1"

    ev_id = f"EV-{uuid.uuid4().hex[:16].upper()}"
    ext = Path(f.filename).suffix
    store_name = f"{ev_id}{ext}"
    dest = STORE_DIR / store_name
    f.save(dest)
    sha = _compute_sha256(dest)
    size = dest.stat().st_size
    now = _now()
    expires = (datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) + __import__('datetime').timedelta(days=retention_days)).isoformat()

    chain = [{"actor": collected_by or "system", "action": "upload", "ts": now, "hash": sha}]

    conn = _get_db()
    conn.execute("""
    INSERT INTO artifacts (id, case_id, filename, storage_path, hash_sha256, size_bytes, mime_type, source, collected_by, collected_at, tags, description, immutable, retention_days, expires_at, chain_of_custody)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        ev_id, case_id, f.filename, str(dest), sha, size, f.content_type or "application/octet-stream",
        source, collected_by, now, json.dumps(tags), description, 1 if immutable else 0,
        retention_days, expires, json.dumps(chain)
    ))
    conn.commit()
    conn.close()

    return jsonify({
        "id": ev_id,
        "filename": f.filename,
        "hash_sha256": sha,
        "size_bytes": size,
        "immutable": immutable,
        "expires_at": expires,
    }), 201


@app.route("/artifacts", methods=["GET", "OPTIONS"])
def list_artifacts():
    case_id = request.args.get("case_id", "")
    q = request.args.get("q", "").lower()
    conn = _get_db()
    cur = conn.cursor()
    sql = "SELECT * FROM artifacts WHERE 1=1"
    params = []
    if case_id:
        sql += " AND case_id = ?"
        params.append(case_id)
    sql += " ORDER BY collected_at DESC"
    cur.execute(sql, params)
    rows = []
    for r in cur.fetchall():
        d = dict(r)
        for k in ("tags", "chain_of_custody"):
            try:
                d[k] = json.loads(d[k])
            except Exception:
                pass
        d["immutable"] = bool(d["immutable"])
        if q and q not in json.dumps(d).lower():
            continue
        rows.append(d)
    conn.close()
    return jsonify({"artifacts": rows, "count": len(rows)})


@app.route("/artifacts/<ev_id>", methods=["GET", "OPTIONS"])
def get_artifact(ev_id: str):
    conn = _get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM artifacts WHERE id = ?", (ev_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    d = dict(row)
    for k in ("tags", "chain_of_custody"):
        try:
            d[k] = json.loads(d[k])
        except Exception:
            pass
    d["immutable"] = bool(d["immutable"])
    # Verify hash
    path = Path(d["storage_path"])
    if path.exists():
        current_hash = _compute_sha256(path)
        d["hash_verified"] = current_hash == d["hash_sha256"]
        d["hash_current"] = current_hash
    else:
        d["hash_verified"] = False
        d["missing"] = True
    return jsonify(d)


@app.route("/artifacts/<ev_id>/download", methods=["GET", "OPTIONS"])
def download_artifact(ev_id: str):
    conn = _get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM artifacts WHERE id = ?", (ev_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    path = Path(row["storage_path"])
    if not path.exists():
        return jsonify({"error": "file missing from store"}), 404
    return send_file(path, as_attachment=True, download_name=row["filename"])


@app.route("/artifacts/<ev_id>/chain", methods=["POST", "OPTIONS"])
def add_chain_entry(ev_id: str):
    data = request.get_json(force=True, silent=True) or {}
    conn = _get_db()
    cur = conn.cursor()
    cur.execute("SELECT chain_of_custody, immutable FROM artifacts WHERE id = ?", (ev_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "not found"}), 404
    chain = json.loads(row["chain_of_custody"] or "[]")
    chain.append({
        "actor": data.get("actor", "system"),
        "action": data.get("action", "access"),
        "ts": _now(),
        "note": data.get("note", ""),
    })
    conn.execute("UPDATE artifacts SET chain_of_custody = ? WHERE id = ?", (json.dumps(chain), ev_id))
    conn.commit()
    conn.close()
    return jsonify({"id": ev_id, "chain_length": len(chain)})


@app.route("/verify", methods=["GET", "OPTIONS"])
def verify_all():
    conn = _get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, storage_path, hash_sha256 FROM artifacts")
    rows = cur.fetchall()
    results = []
    for r in rows:
        path = Path(r["storage_path"])
        if path.exists():
            ok = _compute_sha256(path) == r["hash_sha256"]
            results.append({"id": r["id"], "verified": ok})
        else:
            results.append({"id": r["id"], "verified": False, "missing": True})
    conn.close()
    all_ok = all(r["verified"] for r in results)
    return jsonify({"all_verified": all_ok, "results": results, "count": len(results)})


if __name__ == "__main__":
    port = int(os.environ.get("EVIDENCE_PORT", "8095"))
    BIND_HOST = os.environ.get("EVIDENCE_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, threaded=True, use_reloader=False)
