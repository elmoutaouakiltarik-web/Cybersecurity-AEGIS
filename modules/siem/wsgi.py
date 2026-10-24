#!/usr/bin/env python3
"""WSGI entrypoint for SIEM API (production servers)."""
from app import app as application  # noqa: F401
