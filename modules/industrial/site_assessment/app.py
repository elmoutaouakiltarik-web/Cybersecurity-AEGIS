#!/usr/bin/env python3
"""API REST per l'assessment di siti industriali.

Gira su loopback (default ``127.0.0.1:8097``) e viene esposta dalla dashboard
tramite il proxy dell'orchestratore ``/api/v1/proxy/site-assessment/...``.

Endpoint principali::

    GET  /health
    GET  /preflight                     capacita', interfacce, regole
    GET  /interfaces
    GET  /zones/template                zone Purdue di esempio
    POST /analyze-pcap                  analisi rapida di un pcap (upload o path)
    POST /assess                        avvia un assessment completo
    GET  /assessments                   elenco job
    GET  /assess/<id>                   stato job
    POST /assess/<id>/cancel
    GET  /assess/<id>/result            risultato completo JSON
    GET  /assess/<id>/report?format=    report html/md/json
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_file

try:  # import relativi quando eseguito come modulo
    from .assessor import SiteAssessor
    from .models import utcnow_iso
    from .passive import PassiveAnalyzer
    from .report import build_html, build_json, build_markdown, write_reports
    from .safety import Engagement, ScopeViolation
except ImportError:  # pragma: no cover - esecuzione come script
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from site_assessment.assessor import SiteAssessor
    from site_assessment.models import utcnow_iso
    from site_assessment.passive import PassiveAnalyzer
    from site_assessment.report import build_html, build_json, build_markdown, write_reports
    from site_assessment.safety import Engagement, ScopeViolation

LOGGER = logging.getLogger("aegis.site.api")
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # pcap fino a 512 MB

assessor = SiteAssessor()
UPLOAD_DIR = assessor.data_dir / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _allowed_pcap_roots() -> list[Path]:
    """Directory da cui l'API puo' leggere un pcap gia' presente sul disco.

    Evita che un endpoint autenticato diventi un lettore arbitrario di file:
    si accettano solo upload, la data dir del modulo e le directory dichiarate
    in ``AEGIS_ASSESS_PCAP_DIRS`` (separate da ``os.pathsep``).
    """
    roots = [UPLOAD_DIR.resolve(), assessor.data_dir.resolve()]
    for extra in (os.getenv("AEGIS_ASSESS_PCAP_DIRS") or "").split(os.pathsep):
        if extra.strip():
            roots.append(Path(extra.strip()).resolve())
    return roots


def _is_allowed_file(path: Path, roots: list[Path]) -> bool:
    resolved = path.resolve()
    for root in roots:
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


@app.after_request
def _cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.route("/health", methods=["GET", "OPTIONS"])
def health() -> Any:
    info = assessor.preflight()
    return jsonify({
        "status": "healthy",
        "module": "site-assessment",
        "version": info.get("engine_version"),
        "scapy": info.get("scapy", False),
        "is_admin": info.get("is_admin", False),
        "data_dir": info.get("data_dir"),
        "ts": utcnow_iso(),
    })


@app.route("/preflight", methods=["GET", "OPTIONS"])
def preflight() -> Any:
    return jsonify(assessor.preflight())


@app.route("/interfaces", methods=["GET", "OPTIONS"])
def interfaces() -> Any:
    return jsonify({"interfaces": assessor.interfaces()})


@app.route("/zones/template", methods=["GET", "OPTIONS"])
def zones_template() -> Any:
    """Modello di zone Purdue da adattare al sito."""
    return jsonify({
        "zones": [
            {"name": "Livello 1 - Controllo", "purdue_level": 1,
             "cidrs": ["192.168.10.0/24"],
             "description": "PLC, RTU, drive e I/O remoti di linea"},
            {"name": "Livello 2 - Supervisione", "purdue_level": 2,
             "cidrs": ["192.168.20.0/24"],
             "description": "HMI, SCADA di cella, switch industriali"},
            {"name": "Livello 3 - Operations", "purdue_level": 3,
             "cidrs": ["192.168.30.0/24"],
             "description": "Server SCADA, historian, engineering workstation"},
            {"name": "Livello 4 - Enterprise", "purdue_level": 4,
             "cidrs": ["192.168.40.0/24"],
             "description": "Rete office, MES, ERP"},
        ]
    })


# ── analisi rapida pcap ──────────────────────────────────────────────────────
@app.route("/analyze-pcap", methods=["POST", "OPTIONS"])
def analyze_pcap() -> Any:
    """Analisi di sola lettura di un pcap: nessun pacchetto inviato in rete.

    Accetta sia ``multipart/form-data`` con campo ``file`` sia JSON con
    ``pcap_path`` (file gia' presente sulla macchina).
    """
    if request.method == "OPTIONS":
        return ("", 204)

    pcap_path = ""
    if "file" in request.files:
        upload = request.files["file"]
        if not upload.filename:
            return jsonify({"error": "file senza nome"}), 400
        safe_name = Path(upload.filename).name
        target = UPLOAD_DIR / f"{int(time.time())}-{safe_name}"
        upload.save(target)
        pcap_path = str(target)
    else:
        body = request.get_json(silent=True) or {}
        pcap_path = str(body.get("pcap_path", ""))
        if not pcap_path or not Path(pcap_path).is_file():
            return jsonify({"error": "serve un file pcap (upload o pcap_path esistente)"}), 400
        if not _is_allowed_file(Path(pcap_path), _allowed_pcap_roots()):
            return jsonify({
                "error": "pcap_path fuori dalle directory consentite: usare l'upload "
                         "oppure impostare AEGIS_ASSESS_PCAP_DIRS"
            }), 403

    max_packets = int((request.get_json(silent=True) or {}).get("max_packets", 500_000))
    engagement = Engagement(
        site="analisi pcap", operator="api", authorization_ref="pcap-offline",
        mode="passive", allowed_cidrs=["0.0.0.0/0"], max_hosts=65536, allow_public=True,
    )
    analyzer = PassiveAnalyzer(None, engagement)
    started = time.time()
    try:
        analyzer.feed_file(pcap_path, max_packets=max_packets)
    except Exception as exc:
        LOGGER.exception("analisi pcap fallita")
        return jsonify({"error": f"analisi fallita: {exc}"}), 400

    snapshot = analyzer.finalize()
    from .risk import RiskEngine

    findings = RiskEngine(engagement).evaluate(
        snapshot.assets, snapshot.conversations, snapshot.anomalies,
        broadcast_ratio=snapshot.broadcast_ratio, protocols=snapshot.protocol_counts,
    )
    return jsonify({
        "pcap": pcap_path,
        "duration_s": round(time.time() - started, 2),
        "packets": snapshot.packets,
        "bytes": snapshot.bytes,
        "assets": [a.to_dict() for a in snapshot.assets[:500]],
        "asset_count": len(snapshot.assets),
        "anomalies": [a.to_dict() for a in snapshot.anomalies],
        "protocols": snapshot.protocol_counts,
        "conversations": [c.to_dict() for c in snapshot.conversations[:300]],
        "flow_matrix": analyzer.flow_matrix(),
        "findings": [f.to_dict() for f in findings],
        "broadcast_ratio": snapshot.broadcast_ratio,
    })


# ── assessment ───────────────────────────────────────────────────────────────
@app.route("/assess", methods=["POST", "OPTIONS"])
def start_assessment() -> Any:
    if request.method == "OPTIONS":
        return ("", 204)
    body = request.get_json(silent=True) or {}
    raw_engagement = body.get("engagement") or body
    try:
        engagement = Engagement.from_dict(raw_engagement)
    except TypeError as exc:
        return jsonify({"error": f"engagement non valido: {exc}"}), 400

    targets = body.get("targets") or list(engagement.allowed_cidrs)
    if isinstance(targets, str):
        targets = [targets]

    try:
        job = assessor.start(
            engagement,
            targets=list(targets),
            profile=str(body.get("profile", "ot")),
            pcap=str(body.get("pcap", "")),
            interface=str(body.get("interface", "")),
            duration_s=float(body.get("duration_s", 0) or 0),
            deep=bool(body.get("deep", True)),
            baseline_path=str(body.get("baseline_path", "")),
        )
    except ScopeViolation as exc:
        return jsonify({"error": str(exc), "kind": "scope"}), 403
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"job_id": job.id, "status": job.status, "mode": engagement.mode}), 202


@app.route("/assessments", methods=["GET", "OPTIONS"])
def list_assessments() -> Any:
    return jsonify({"jobs": assessor.list()})


@app.route("/assess/<job_id>", methods=["GET", "OPTIONS"])
def job_status(job_id: str) -> Any:
    job = assessor.get(job_id)
    include = request.args.get("result") in ("1", "true", "yes")
    if job is None:
        result = assessor.load_result(job_id)
        if result is None:
            return jsonify({"error": "job non trovato"}), 404
        return jsonify({"id": job_id, "status": result.status, "result": result.to_dict()})
    return jsonify(job.to_dict(include_result=include))


@app.route("/assess/<job_id>/cancel", methods=["POST", "OPTIONS"])
def cancel_assessment(job_id: str) -> Any:
    if request.method == "OPTIONS":
        return ("", 204)
    ok = assessor.cancel(job_id)
    return (jsonify({"cancelled": True}), 200) if ok else (jsonify({"error": "job non trovato"}), 404)


@app.route("/assess/<job_id>/result", methods=["GET", "OPTIONS"])
def assessment_result(job_id: str) -> Any:
    result = assessor.load_result(job_id)
    if result is None:
        return jsonify({"error": "risultato non disponibile"}), 404
    return jsonify(result.to_dict())


@app.route("/assess/<job_id>/report", methods=["GET", "OPTIONS"])
def assessment_report(job_id: str) -> Any:
    result = assessor.load_result(job_id)
    if result is None:
        return jsonify({"error": "risultato non disponibile"}), 404
    fmt = str(request.args.get("format", "html")).lower()

    if fmt == "json":
        return app.response_class(build_json(result), mimetype="application/json")
    if fmt == "md":
        return app.response_class(build_markdown(result), mimetype="text/markdown; charset=utf-8")

    # HTML generato al volo: nessun file temporaneo esposto.
    html = build_html(result)
    return app.response_class(html, mimetype="text/html; charset=utf-8")


@app.route("/assess/<job_id>/reports", methods=["POST", "OPTIONS"])
def write_assessment_reports(job_id: str) -> Any:
    if request.method == "OPTIONS":
        return ("", 204)
    result = assessor.load_result(job_id)
    if result is None:
        return jsonify({"error": "risultato non disponibile"}), 404
    requested = str((request.get_json(silent=True) or {}).get("outdir") or "")
    outdir_path = Path(requested).resolve() if requested else (assessor.data_dir / "reports")
    try:
        outdir_path.relative_to(assessor.data_dir.resolve())
    except ValueError:
        return jsonify({"error": "outdir deve stare dentro la data dir del modulo"}), 403
    try:
        paths = write_reports(result, str(outdir_path))
    except OSError as exc:
        return jsonify({"error": f"scrittura fallita: {exc}"}), 500
    return jsonify({"paths": paths})


@app.route("/assess/<job_id>/download/<fmt>", methods=["GET", "OPTIONS"])
def download_report(job_id: str, fmt: str) -> Any:
    result = assessor.load_result(job_id)
    if result is None:
        return jsonify({"error": "risultato non disponibile"}), 404
    paths = write_reports(result, str(assessor.data_dir / "reports"))
    path = paths.get(fmt)
    if not path or not Path(path).is_file():
        return jsonify({"error": f"formato non disponibile: {fmt}"}), 404
    return send_file(path, as_attachment=True)


@app.errorhandler(413)
def too_large(_err) -> Any:
    return jsonify({"error": "file troppo grande (max 512 MB)"}), 413


def main() -> int:
    logging.basicConfig(
        level=os.getenv("AEGIS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    host = os.getenv("ASSESS_BIND_HOST", "127.0.0.1")
    port = int(os.getenv("ASSESS_API_PORT", "8097"))
    LOGGER.info("Site Assessment API su http://%s:%d", host, port)
    app.run(host=host, port=port, threaded=True, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
