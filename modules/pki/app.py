"""
AEGIS-OMNI PKI / Certificate Management Module
Integrates with step-ca or local OpenSSL for mTLS, host certs, and SSH certs.
Read-only and issuance where configured. No private key exposure via API.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DATA_DIR = Path(os.environ.get("PKI_DATA_DIR", "./pki_data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "pki.db"

# step-ca integration settings
STEP_CA_URL = os.environ.get("STEP_CA_URL", "")
STEP_CA_FINGERPRINT = os.environ.get("STEP_CA_FINGERPRINT", "")


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _init_db():
    conn = _get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS certs (
        id TEXT PRIMARY KEY,
        cn TEXT NOT NULL,
        san TEXT,
        cert_type TEXT DEFAULT 'x509',
        issuer TEXT,
        not_before TEXT,
        not_after TEXT,
        serial TEXT,
        fingerprint_sha256 TEXT,
        storage_path TEXT,
        status TEXT DEFAULT 'active',
        tags TEXT,
        created_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_certs_cn ON certs(cn);
    CREATE INDEX IF NOT EXISTS idx_certs_status ON certs(status);
    """)
    conn.commit()
    conn.close()


_init_db()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd: List[str], timeout: float = 10.0) -> Optional[str]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


@app.route("/health", methods=["GET", "OPTIONS"])
def health():
    step_ca_present = bool(shutil.which("step-ca") or shutil.which("step"))
    openssl_present = bool(shutil.which("openssl"))
    return jsonify({
        "status": "ok",
        "module": "pki",
        "step_ca_available": step_ca_present,
        "openssl_available": openssl_present,
        "step_ca_url": STEP_CA_URL or None,
        "ts": _now(),
    })


@app.route("/tools/step-ca/status", methods=["GET", "OPTIONS"])
def step_ca_status():
    if not shutil.which("step"):
        return jsonify({"error": "step-cli not installed"}), 503
    # Try health via step-cli if URL configured
    if STEP_CA_URL and STEP_CA_FINGERPRINT:
        out = _run(["step", "ca", "health", "--ca-url", STEP_CA_URL], 5.0)
        return jsonify({"healthy": out is not None, "output": out, "url": STEP_CA_URL})
    return jsonify({"configured": False, "note": "Set STEP_CA_URL and STEP_CA_FINGERPRINT"})


@app.route("/tools/openssl/version", methods=["GET", "OPTIONS"])
def openssl_version():
    if not shutil.which("openssl"):
        return jsonify({"error": "openssl not installed"}), 503
    out = _run(["openssl", "version"], 3.0)
    return jsonify({"version": out})


@app.route("/certs", methods=["GET", "OPTIONS"])
def list_certs():
    status = request.args.get("status", "")
    cn = request.args.get("cn", "")
    conn = _get_db()
    cur = conn.cursor()
    sql = "SELECT * FROM certs WHERE 1=1"
    params = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    if cn:
        sql += " AND cn LIKE ?"
        params.append(f"%{cn}%")
    sql += " ORDER BY created_at DESC"
    cur.execute(sql, params)
    rows = []
    for r in cur.fetchall():
        d = dict(r)
        try:
            d["tags"] = json.loads(d["tags"])
        except Exception:
            pass
        rows.append(d)
    conn.close()
    return jsonify({"certs": rows, "count": len(rows)})


@app.route("/certs", methods=["POST", "OPTIONS"])
def add_cert():
    """Register an existing certificate into the PKI inventory (not issuance)."""
    data = request.get_json(force=True, silent=True) or {}
    cid = data.get("id", f"CERT-{uuid.uuid4().hex[:12].upper()}")
    conn = _get_db()
    conn.execute("""
    INSERT INTO certs (id, cn, san, cert_type, issuer, not_before, not_after, serial, fingerprint_sha256, storage_path, status, tags, created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        cid, data.get("cn", ""), json.dumps(data.get("san", [])),
        data.get("cert_type", "x509"), data.get("issuer", ""),
        data.get("not_before", ""), data.get("not_after", ""),
        data.get("serial", ""), data.get("fingerprint_sha256", ""),
        data.get("storage_path", ""), data.get("status", "active"),
        json.dumps(data.get("tags", [])), _now()
    ))
    conn.commit()
    conn.close()
    return jsonify({"id": cid, "registered": True}), 201


@app.route("/certs/<cid>/renew", methods=["POST", "OPTIONS"])
def renew_cert(cid: str):
    """Mark a certificate for renewal workflow. Does not perform actual renewal."""
    conn = _get_db()
    conn.execute("UPDATE certs SET status = 'pending_renewal' WHERE id = ?", (cid,))
    conn.commit()
    conn.close()
    return jsonify({"id": cid, "status": "pending_renewal"})


@app.route("/certs/<cid>/revoke", methods=["POST", "OPTIONS"])
def revoke_cert(cid: str):
    conn = _get_db()
    conn.execute("UPDATE certs SET status = 'revoked' WHERE id = ?", (cid,))
    conn.commit()
    conn.close()
    return jsonify({"id": cid, "status": "revoked"})


@app.route("/check-expiry", methods=["GET", "OPTIONS"])
def check_expiry():
    days = int(request.args.get("days", "30"))
    now = datetime.now(timezone.utc)
    conn = _get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM certs WHERE status = 'active'")
    expiring = []
    for r in cur.fetchall():
        try:
            nb = datetime.fromisoformat(r["not_after"].replace("Z", "+00:00"))
            delta = (nb - now).days
            if delta <= days:
                expiring.append({"id": r["id"], "cn": r["cn"], "not_after": r["not_after"], "days_left": delta})
        except Exception:
            pass
    conn.close()
    return jsonify({"expiring": expiring, "count": len(expiring), "window_days": days})


@app.route("/mTLS/policy", methods=["GET", "OPTIONS"])
def mtls_policy():
    return jsonify({
        "policy": {
            "enabled": bool(STEP_CA_URL),
            "ca_url": STEP_CA_URL or None,
            "required_for": [
                "orchestrator-to-module",
                "edge-collector-to-core",
                "module-to-module"
            ],
            "client_cert_required": True,
            "verify_depth": 2,
            "crl_check": True,
            "ocsp_check": False,
            "note": "Configure step-ca bootstrap and certificate issuance per service identity."
        }
    })


if __name__ == "__main__":
    port = int(os.environ.get("PKI_PORT", "8096"))
    BIND_HOST = os.environ.get("PKI_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, threaded=True, use_reloader=False)
