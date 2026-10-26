#!/usr/bin/env python3
"""
AEGIS-OMNI Passive OT Monitor (Modbus)
Uses pymodbus to read holding registers and push events to the AEGIS Orchestrator.
"""

from __future__ import annotations
import os
import sys
import json
import time
import requests
from datetime import datetime, timezone
from pymodbus.client import ModbusTcpClient

# Shared secret for orchestrator ingest endpoints (must match AEGIS_INGEST_KEY).
_INGEST_HEADERS = {"X-AEGIS-INGEST-KEY": os.environ.get("AEGIS_INGEST_KEY", "")}

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8080")
HOST = os.getenv("MODBUS_HOST", "127.0.0.1")
PORT = int(os.getenv("MODBUS_PORT", "502"))
UNIT = int(os.getenv("MODBUS_UNIT", "1"))
REG_START = int(os.getenv("MODBUS_REG_START", "0"))
REG_COUNT = int(os.getenv("MODBUS_REG_COUNT", "8"))
INTERVAL = int(os.getenv("POLL_INTERVAL_SEC", "10"))

def send_event(payload: dict):
    try:
        requests.post(f"{ORCHESTRATOR_URL}/api/v1/ingest/ot", json=payload, timeout=5, headers=_INGEST_HEADERS)
    except Exception as e:
        print(f"[OT Monitor] Failed to send event to orchestrator: {e}", file=sys.stderr)

def main():
    print(f"[OT Monitor] Starting Modbus Poller. Target: {HOST}:{PORT}, Unit: {UNIT}")
    
    while True:
        client = ModbusTcpClient(HOST, port=PORT, timeout=3)
        try:
            if not client.connect():
                event = {
                    "source": "ot_monitor",
                    "severity": "high",
                    "title": "Modbus Connection Failed",
                    "description": f"Failed to connect to Modbus slave at {HOST}:{PORT}",
                    "protocol": "modbus-tcp",
                    "device_type": "plc",
                    "purdue_level": 1
                }
                print(f"[OT Monitor] Connection failed to {HOST}:{PORT}", file=sys.stderr)
                send_event(event)
            else:
                result = client.read_holding_registers(address=REG_START, count=REG_COUNT, slave=UNIT)
                if result.isError():
                    event = {
                        "source": "ot_monitor",
                        "severity": "medium",
                        "title": "Modbus Read Error",
                        "description": f"Error reading holding registers {REG_START}-{REG_START+REG_COUNT-1} from slave {UNIT}",
                        "protocol": "modbus-tcp",
                        "device_type": "plc",
                        "purdue_level": 1
                    }
                    print(f"[OT Monitor] Read error on {HOST}:{PORT}", file=sys.stderr)
                    send_event(event)
                else:
                    event = {
                        "source": "ot_monitor",
                        "severity": "info",
                        "title": f"Modbus Read Success: {HOST}",
                        "description": f"Successfully read {REG_COUNT} registers from {HOST}:{PORT}",
                        "protocol": "modbus-tcp",
                        "device_type": "plc",
                        "purdue_level": 1,
                        "raw_data": {
                            "registers": result.registers
                        }
                    }
                    print(f"[OT Monitor] Read success: {result.registers}")
                    send_event(event)
        except Exception as ex:
            print(f"[OT Monitor] Exception: {ex}", file=sys.stderr)
        finally:
            client.close()
        
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
