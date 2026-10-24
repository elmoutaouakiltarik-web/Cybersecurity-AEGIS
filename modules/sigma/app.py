"""
AEGIS-OMNI Sigma Detection-as-Code Engine
Parses Sigma rules, manages a local rule repository, and converts
to AEGIS-native JSON filters for the Shield engine.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

RULES_DIR = Path(os.environ.get("SIGMA_RULES_DIR", "./sigma_rules"))
RULES_DIR.mkdir(parents=True, exist_ok=True)

# Default OT-friendly rule per architecture document
DEFAULT_OT_RULE = """title: OT Unauthorized Modbus Write Attempt
id: 5a3f0f6c-ot-modbus-write
status: experimental
logsource:
  product: network
  service: modbus
detection:
  selection:
    event_type: modbus
    function_code:
      - 5
      - 6
      - 15
      - 16
    src_ip|cidr: "10.0.0.0/8"
  filter_allowlist:
    src_ip:
      - "10.20.1.10"
      - "10.20.1.11"
  condition: selection and not filter_allowlist
level: high
tags:
  - attack.ics
  - attack.execution
  - attack.ics.modify_program
"""


def _load_rule(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return None
        data["_filename"] = path.name
        data["_path"] = str(path)
        return data
    except Exception:
        return None


def _save_rule(rule: Dict[str, Any], filename: Optional[str] = None) -> Path:
    fname = filename or f"{rule.get('id', uuid.uuid4().hex)}.yml"
    if not fname.endswith((".yml", ".yaml")):
        fname += ".yml"
    path = RULES_DIR / fname
    # Strip internal keys
    clean = {k: v for k, v in rule.items() if not k.startswith("_")}
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(clean, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    return path


def _ensure_defaults():
    default_path = RULES_DIR / "ot_unauthorized_modbus_write.yml"
    if not default_path.exists():
        with open(default_path, "w", encoding="utf-8") as f:
            f.write(DEFAULT_OT_RULE)


def _convert_to_aegis(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Convert Sigma rule to AEGIS Shield JSON filter."""
    level = rule.get("level", "medium")
    severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
    detection = rule.get("detection", {})
    # Build simple keyword/field matchers
    keywords: List[str] = []
    field_match: Dict[str, Any] = {}
    for key, val in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(val, dict):
            for fk, fv in val.items():
                if isinstance(fv, list):
                    field_match[fk] = {"any_of": fv}
                else:
                    field_match[fk] = {"eq": fv}
        elif isinstance(val, list):
            keywords.extend(str(x) for x in val)
    condition = detection.get("condition", "selection")
    return {
        "id": rule.get("id", uuid.uuid4().hex),
        "name": rule.get("title", "Untitled"),
        "description": rule.get("description", ""),
        "severity": severity_map.get(level, level),
        "category": rule.get("logsource", {}).get("product", "generic"),
        "source": "sigma",
        "enabled": rule.get("status") not in ("deprecated", "unsupported"),
        "sigma_level": level,
        "tags": rule.get("tags", []),
        "condition": condition,
        "keywords": keywords,
        "field_match": field_match,
        "references": rule.get("references", []),
        "author": rule.get("author", ""),
        "date": rule.get("date", ""),
        "modified": rule.get("modified", ""),
    }


@app.route("/health", methods=["GET", "OPTIONS"])
def health():
    return jsonify({"status": "ok", "module": "sigma", "ts": datetime.now(timezone.utc).isoformat()})


@app.route("/rules", methods=["GET", "OPTIONS"])
def list_rules():
    _ensure_defaults()
    tags = request.args.get("tags", "").split(",") if request.args.get("tags") else []
    level = request.args.get("level", "")
    search = request.args.get("q", "").lower()
    rules: List[Dict[str, Any]] = []
    for path in sorted(RULES_DIR.glob("*.y*ml")):
        r = _load_rule(path)
        if not r:
            continue
        if tags and not any(t in r.get("tags", []) for t in tags):
            continue
        if level and r.get("level", "").lower() != level.lower():
            continue
        if search and search not in json.dumps(r).lower():
            continue
        rules.append(_convert_to_aegis(r))
    return jsonify({"rules": rules, "count": len(rules)})


@app.route("/rules/<rule_id>", methods=["GET", "OPTIONS"])
def get_rule(rule_id: str):
    _ensure_defaults()
    for path in RULES_DIR.glob("*.y*ml"):
        r = _load_rule(path)
        if r and r.get("id") == rule_id:
            return jsonify(_convert_to_aegis(r))
    return jsonify({"error": "not found"}), 404


@app.route("/rules", methods=["POST", "OPTIONS"])
def create_rule():
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("title"):
        return jsonify({"error": "title required"}), 400
    rid = data.get("id", uuid.uuid4().hex)
    data["id"] = rid
    path = _save_rule(data)
    return jsonify({"id": rid, "saved": str(path), "rule": _convert_to_aegis(data)}), 201


@app.route("/rules/<rule_id>", methods=["PUT", "OPTIONS"])
def update_rule(rule_id: str):
    data = request.get_json(force=True, silent=True) or {}
    for path in RULES_DIR.glob("*.y*ml"):
        r = _load_rule(path)
        if r and r.get("id") == rule_id:
            r.update(data)
            r["id"] = rule_id
            _save_rule(r, path.name)
            return jsonify(_convert_to_aegis(r))
    return jsonify({"error": "not found"}), 404


@app.route("/rules/<rule_id>", methods=["DELETE", "OPTIONS"])
def delete_rule(rule_id: str):
    for path in RULES_DIR.glob("*.y*ml"):
        r = _load_rule(path)
        if r and r.get("id") == rule_id:
            path.unlink()
            return jsonify({"deleted": rule_id})
    return jsonify({"error": "not found"}), 404


@app.route("/rules/import", methods=["POST", "OPTIONS"])
def import_rules():
    """Bulk import Sigma YAML text (single or multi-document)."""
    text = request.get_data(as_text=True)
    imported = 0
    errors = 0
    for doc in yaml.safe_load_all(text):
        if not isinstance(doc, dict) or not doc.get("title"):
            errors += 1
            continue
        if not doc.get("id"):
            doc["id"] = uuid.uuid4().hex
        _save_rule(doc)
        imported += 1
    return jsonify({"imported": imported, "errors": errors})


@app.route("/convert/aegis", methods=["POST", "OPTIONS"])
def convert_to_aegis():
    """Convert a Sigma rule JSON payload to AEGIS Shield filter."""
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("title"):
        return jsonify({"error": "title required"}), 400
    return jsonify({"aegis_filter": _convert_to_aegis(data)})


@app.route("/tags", methods=["GET", "OPTIONS"])
def list_tags():
    _ensure_defaults()
    tags: set = set()
    for path in RULES_DIR.glob("*.y*ml"):
        r = _load_rule(path)
        if r:
            tags.update(r.get("tags", []))
    return jsonify({"tags": sorted(tags)})


if __name__ == "__main__":
    port = int(os.environ.get("SIGMA_PORT", "8091"))
    BIND_HOST = os.environ.get("SIGMA_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, threaded=True, use_reloader=False)
