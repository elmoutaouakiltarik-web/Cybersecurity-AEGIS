"""
AEGIS-OMNI Compliance Module
GDPR, NIS2, and OT security readiness checks.
Read-only assessment; no configuration changes.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DATA_DIR = Path(os.environ.get("COMPLIANCE_DATA_DIR", "./compliance_data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "compliance.db"


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _init_db():
    conn = _get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS assessments (
        id TEXT PRIMARY KEY,
        framework TEXT NOT NULL,
        version TEXT,
        score INTEGER,
        max_score INTEGER,
        findings TEXT,
        passed INTEGER,
        failed INTEGER,
        warnings INTEGER,
        created_at TEXT,
        site TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_assessments_framework ON assessments(framework);
    """)
    conn.commit()
    conn.close()


_init_db()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============== GDPR CHECKS ==============

def assess_gdpr(context: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    score = 0
    max_score = 100

    # Art. 5 principles
    checks = [
        ("lawfulness_fairness_transparency", "Data processing is lawful, fair and transparent", 10),
        ("purpose_limitation", "Data collected for specified, explicit and legitimate purposes", 10),
        ("data_minimization", "Adequate, relevant and limited to what is necessary", 10),
        ("accuracy", "Accurate and kept up to date", 5),
        ("storage_limitation", "Kept no longer than necessary", 10),
        ("integrity_confidentiality", "Appropriate security (pseudonymization, encryption)", 15),
        ("accountability", "Controller demonstrates compliance", 10),
    ]
    for key, desc, weight in checks:
        ok = context.get(key, False)
        findings.append({
            "id": f"gdpr_art5_{key}",
            "requirement": desc,
            "weight": weight,
            "status": "pass" if ok else "fail",
            "article": "Art. 5",
            "recommendation": None if ok else f"Implement {key.replace('_', ' ')} controls."
        })
        if ok:
            score += weight

    # Art. 25 privacy by design/default
    ok = context.get("privacy_by_design", False)
    findings.append({
        "id": "gdpr_art25_design",
        "requirement": "Privacy by design and by default (Art. 25)",
        "weight": 10,
        "status": "pass" if ok else "fail",
        "article": "Art. 25",
        "recommendation": None if ok else "Apply PbD/PbD to systems and processing activities."
    })
    if ok:
        score += 10

    # Art. 32 security of processing
    ok = context.get("security_of_processing", False)
    findings.append({
        "id": "gdpr_art32_security",
        "requirement": "Security of processing (Art. 32)",
        "weight": 10,
        "status": "pass" if ok else "fail",
        "article": "Art. 32",
        "recommendation": None if ok else "Implement encryption, availability, resilience, testing."
    })
    if ok:
        score += 10

    # Art. 35 DPIA
    ok = context.get("dpia_conducted", False)
    findings.append({
        "id": "gdpr_art35_dpia",
        "requirement": "DPIA conducted where high risk (Art. 35)",
        "weight": 10,
        "status": "pass" if ok else "warn",
        "article": "Art. 35",
        "recommendation": None if ok else "Conduct DPIA for systematic monitoring or sensitive processing."
    })
    if ok:
        score += 10

    return {"framework": "GDPR", "regulation": "EU 2016/679", "score": score, "max_score": max_score, "findings": findings}


# ============== NIS2 CHECKS ==============

def assess_nis2(context: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    score = 0
    max_score = 100

    checks = [
        ("risk_analysis", "Risk analysis and information system security (Art. 21)", 15),
        ("incident_handling", "Incident handling, business continuity and crisis management", 15),
        ("supply_chain_security", "Supply chain security, including security of acquisition and development", 10),
        ("access_control", "Policies and procedures for access control and identity management", 10),
        ("cryptography", "Use of cryptography and encryption where appropriate", 10),
        ("asset_management", "Asset management, including hardware and software", 10),
        ("cyber_hygiene", "Cyber hygiene and cybersecurity training", 10),
        ("multi_factor_auth", "Multi-factor authentication and secured communications", 10),
        ("reporting", "Incident reporting capability (24h early warning, 72h notification, 1 month final)", 10),
    ]
    for key, desc, weight in checks:
        ok = context.get(key, False)
        findings.append({
            "id": f"nis2_{key}",
            "requirement": desc,
            "weight": weight,
            "status": "pass" if ok else "fail",
            "article": "Art. 21",
            "recommendation": None if ok else f"Strengthen {key.replace('_', ' ')}."
        })
        if ok:
            score += weight

    return {"framework": "NIS2", "regulation": "EU 2022/2555", "score": score, "max_score": max_score, "findings": findings}


# ============== OT / NIST 800-82 CHECKS ==============

def assess_ot_nist(context: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    score = 0
    max_score = 100

    checks = [
        ("ot_inventory", "OT asset inventory complete and maintained", 10),
        ("network_segmentation", "Network segmentation between IT and OT (Purdue model)", 15),
        ("read_only_monitoring", "Read-only monitoring default for OT security tools", 15),
        ("maintenance_windows", "Patch/maintenance windows approved by plant engineering", 10),
        ("safety_gate", "Safety gate / human approval before OT containment actions", 15),
        ("backup_restore", "Backup and restore tested for OT controllers/HMIs", 10),
        ("physical_security", "Physical security of OT devices and consoles", 10),
        ("remote_access", "Remote access to OT restricted, logged, multi-factor", 10),
        ("incident_response_ot", "OT-specific incident response plan and tabletop exercises", 5),
    ]
    for key, desc, weight in checks:
        ok = context.get(key, False)
        findings.append({
            "id": f"nist82_{key}",
            "requirement": desc,
            "weight": weight,
            "status": "pass" if ok else "fail",
            "standard": "NIST SP 800-82 Rev. 3",
            "recommendation": None if ok else f"Address {key.replace('_', ' ')}."
        })
        if ok:
            score += weight

    return {"framework": "OT_NIST_800_82", "standard": "NIST SP 800-82 Rev. 3", "score": score, "max_score": max_score, "findings": findings}


# ============== API ==============

@app.route("/health", methods=["GET", "OPTIONS"])
def health():
    return jsonify({"status": "ok", "module": "compliance", "ts": _now()})


@app.route("/assess", methods=["POST", "OPTIONS"])
def run_assessment():
    data = request.get_json(force=True, silent=True) or {}
    framework = data.get("framework", "all").lower()
    context = data.get("context", {})
    results = []
    if framework in ("all", "gdpr"):
        results.append(assess_gdpr(context))
    if framework in ("all", "nis2"):
        results.append(assess_nis2(context))
    if framework in ("all", "ot", "nist", "nist_800_82"):
        results.append(assess_ot_nist(context))

    # Persist
    aid = f"ASSess-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    conn = _get_db()
    for r in results:
        passed = sum(1 for f in r["findings"] if f["status"] == "pass")
        failed = sum(1 for f in r["findings"] if f["status"] == "fail")
        warnings = sum(1 for f in r["findings"] if f["status"] == "warn")
        conn.execute("""
        INSERT INTO assessments (id, framework, version, score, max_score, findings, passed, failed, warnings, created_at, site)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            f"{aid}-{r['framework']}", r["framework"], r.get("regulation") or r.get("standard"),
            r["score"], r["max_score"], json.dumps(r["findings"]), passed, failed, warnings, _now(), data.get("site", "")
        ))
    conn.commit()
    conn.close()

    return jsonify({"assessment_id": aid, "results": results})


@app.route("/assessments", methods=["GET", "OPTIONS"])
def list_assessments():
    framework = request.args.get("framework", "")
    conn = _get_db()
    cur = conn.cursor()
    sql = "SELECT * FROM assessments WHERE 1=1"
    params = []
    if framework:
        sql += " AND framework = ?"
        params.append(framework)
    sql += " ORDER BY created_at DESC LIMIT 100"
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        try:
            r["findings"] = json.loads(r["findings"])
        except Exception:
            pass
    conn.close()
    return jsonify({"assessments": rows, "count": len(rows)})


@app.route("/frameworks", methods=["GET", "OPTIONS"])
def list_frameworks():
    return jsonify({
        "frameworks": [
            {"id": "gdpr", "name": "GDPR", "regulation": "EU 2016/679", "description": "General Data Protection Regulation"},
            {"id": "nis2", "name": "NIS2", "regulation": "EU 2022/2555", "description": "Network and Information Security Directive"},
            {"id": "ot_nist_800_82", "name": "NIST SP 800-82 Rev. 3", "standard": "NIST SP 800-82 Rev. 3", "description": "Guide to OT Security"},
        ]
    })


if __name__ == "__main__":
    port = int(os.environ.get("COMPLIANCE_PORT", "8094"))
    BIND_HOST = os.environ.get("COMPLIANCE_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, threaded=True, use_reloader=False)
