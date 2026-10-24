"""
AEGIS-OMNI OT Protocol Collectors
Read-only telemetry for Modbus TCP and OPC UA.
Compliant with NIST SP 800-82 Rev. 3: monitoring is read-only by default.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Safety gate: all write operations are blocked by default
OT_SAFE_MODE = os.environ.get("OT_SAFE_MODE", "1").lower() in {"1", "true", "yes"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check_pymodbus() -> bool:
    try:
        import pymodbus
        return True
    except Exception:
        return False


def _check_open62541() -> bool:
    # open62541 is a C library; we check for Python wrappers or CLI tools
    try:
        import opcua  # python-opcua or asyncua fallback
        return True
    except Exception:
        pass
    try:
        import asyncua
        return True
    except Exception:
        pass
    return shutil.which("ua") is not None


@app.route("/health", methods=["GET", "OPTIONS"])
def health():
    return jsonify({
        "status": "ok",
        "module": "ot_protocols",
        "ot_safe_mode": OT_SAFE_MODE,
        "pymodbus_available": _check_pymodbus(),
        "opcua_available": _check_open62541(),
        "ts": _now(),
    })


# ============== MODBUS ==============

@app.route("/modbus/read", methods=["POST", "OPTIONS"])
def modbus_read():
    """Read holding registers from a Modbus TCP device. Read-only."""
    if not _check_pymodbus():
        return jsonify({"error": "pymodbus not installed. pip install pymodbus"}), 503
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host", "")
    port = int(data.get("port", 502))
    unit = int(data.get("unit_id", 1))
    reg_start = int(data.get("reg_start", 0))
    reg_count = int(data.get("reg_count", 8))
    max_regs = int(data.get("max_regs", 64))

    if reg_count > max_regs:
        return jsonify({"error": f"reg_count exceeds max_regs {max_regs}"}), 400

    try:
        from pymodbus.client import ModbusTcpClient
    except Exception as e:
        return jsonify({"error": f"pymodbus import failed: {e}"}), 503

    client = ModbusTcpClient(host, port=port, timeout=data.get("timeout", 3))
    connected = client.connect()
    event = {
        "ts": _now(),
        "level": "info" if connected else "error",
        "module": "ot-modbus",
        "asset_type": "plc",
        "transport": "modbus-tcp",
        "host": host,
        "port": port,
        "unit_id": unit,
        "reg_start": reg_start,
        "reg_count": reg_count,
        "mode": "read-only",
        "ot_safe": True,
    }
    if not connected:
        event["message"] = "connection_failed"
        return jsonify(event), 200

    try:
        result = client.read_holding_registers(address=reg_start, count=reg_count, slave=unit)
        client.close()
        if result.isError():
            event["level"] = "error"
            event["message"] = "read_failed"
            event["error_code"] = str(result)
        else:
            event["registers"] = result.registers if hasattr(result, "registers") else []
            event["message"] = "read_ok"
    except Exception as e:
        client.close()
        event["level"] = "error"
        event["message"] = str(e)

    return jsonify(event)


@app.route("/modbus/discover", methods=["POST", "OPTIONS"])
def modbus_discover():
    """Discover Modbus devices on a subnet by probing port 502. Read-only."""
    if not _check_pymodbus():
        return jsonify({"error": "pymodbus not installed"}), 503
    data = request.get_json(force=True, silent=True) or {}
    hosts = data.get("hosts", [])
    timeout = float(data.get("timeout", 2.0))
    port = int(data.get("port", 502))
    results: List[Dict[str, Any]] = []
    try:
        from pymodbus.client import ModbusTcpClient
    except Exception as e:
        return jsonify({"error": f"pymodbus import failed: {e}"}), 503
    for host in hosts:
        client = ModbusTcpClient(host, port=port, timeout=timeout)
        connected = client.connect()
        if connected:
            # Try a minimal read to confirm it's a real Modbus device
            try:
                result = client.read_holding_registers(address=0, count=1, slave=1)
                ok = not result.isError()
            except Exception:
                ok = False
            client.close()
            results.append({"host": host, "port": port, "reachable": True, "modbus_responsive": ok})
        else:
            results.append({"host": host, "port": port, "reachable": False, "modbus_responsive": False})
    return jsonify({"ts": _now(), "mode": "read-only", "results": results})


# ============== OPC UA ==============

@app.route("/opcua/browse", methods=["POST", "OPTIONS"])
def opcua_browse():
    """Browse OPC UA server nodes. Read-only."""
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "opc.tcp://localhost:4840")
    timeout = float(data.get("timeout", 5.0))

    # Try asyncua first, then python-opcua
    try:
        import asyncua
        from asyncua.sync import Client
        nodes: List[Dict[str, Any]] = []
        with Client(url, timeout=timeout) as client:
            root = client.get_root_node()
            objects = client.get_objects_node()
            # Basic server info
            server = client.get_server_node()
            endpoints = client.uaclient.find_servers()
            nodes.append({
                "node_id": str(root.nodeid),
                "name": "Root",
                "browse_name": str(root.get_browse_name()),
            })
            for child in objects.get_children():
                nodes.append({
                    "node_id": str(child.nodeid),
                    "name": child.get_display_name().Text if child.get_display_name() else "",
                    "browse_name": str(child.get_browse_name()),
                })
        return jsonify({
            "ts": _now(),
            "url": url,
            "mode": "read-only",
            "ot_safe": True,
            "nodes": nodes,
        })
    except Exception as e1:
        try:
            import opcua
            from opcua import Client
            nodes = []
            client = Client(url, timeout=timeout)
            client.connect()
            root = client.get_root_node()
            objects = client.get_objects_node()
            for child in objects.get_children():
                nodes.append({
                    "node_id": str(child.nodeid),
                    "name": child.get_display_name().Text if child.get_display_name() else "",
                    "browse_name": str(child.get_browse_name()),
                })
            client.disconnect()
            return jsonify({
                "ts": _now(),
                "url": url,
                "mode": "read-only",
                "ot_safe": True,
                "nodes": nodes,
            })
        except Exception as e2:
            return jsonify({
                "ts": _now(),
                "url": url,
                "mode": "read-only",
                "ot_safe": True,
                "error": f"asyncua: {e1}; opcua: {e2}",
                "hint": "pip install asyncua",
            }), 503


@app.route("/opcua/read", methods=["POST", "OPTIONS"])
def opcua_read():
    """Read an OPC UA node value. Read-only."""
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "opc.tcp://localhost:4840")
    node_id = data.get("node_id", "i=2256")  # Server_ServerStatus_State
    timeout = float(data.get("timeout", 5.0))
    try:
        import asyncua
        from asyncua.sync import Client
        with Client(url, timeout=timeout) as client:
            node = client.get_node(node_id)
            val = node.read_value()
            dtype = node.read_data_type()
        return jsonify({
            "ts": _now(),
            "url": url,
            "node_id": node_id,
            "value": str(val),
            "data_type": str(dtype),
            "mode": "read-only",
            "ot_safe": True,
        })
    except Exception as e1:
        try:
            import opcua
            from opcua import Client
            client = Client(url, timeout=timeout)
            client.connect()
            node = client.get_node(node_id)
            val = node.get_value()
            client.disconnect()
            return jsonify({
                "ts": _now(),
                "url": url,
                "node_id": node_id,
                "value": str(val),
                "mode": "read-only",
                "ot_safe": True,
            })
        except Exception as e2:
            return jsonify({
                "ts": _now(),
                "url": url,
                "node_id": node_id,
                "error": f"asyncua: {e1}; opcua: {e2}",
            }), 503


# ============== IEC 61850 placeholder ==============

@app.route("/iec61850/status", methods=["GET", "OPTIONS"])
def iec61850_status():
    """Placeholder for IEC 61850 via libiec61850. Read-only advisory."""
    return jsonify({
        "ts": _now(),
        "protocol": "iec61850",
        "status": "placeholder",
        "note": "libiec61850 is a C library (GPL-3.0). Use via external collector or wrapper. This endpoint is advisory-only.",
        "ot_safe": True,
        "mode": "read-only",
    })


if __name__ == "__main__":
    port = int(os.environ.get("OT_PROTOCOLS_PORT", "8092"))
    BIND_HOST = os.environ.get("OT_PROTOCOLS_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, threaded=True, use_reloader=False)
