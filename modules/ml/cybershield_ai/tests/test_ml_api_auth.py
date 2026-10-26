"""The prediction API must require the same shared secret as ingest."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

fastapi = pytest.importorskip("fastapi", reason="API dependencies not installed")

from fastapi import HTTPException  # noqa: E402

from api.app import require_ingest_key  # noqa: E402


def test_missing_key_is_rejected(monkeypatch):
    monkeypatch.setenv("AEGIS_INGEST_KEY", "shared-secret")
    with pytest.raises(HTTPException) as exc:
        require_ingest_key(x_aegis_ingest_key=None, authorization=None)
    assert exc.value.status_code == 401


def test_wrong_key_is_rejected(monkeypatch):
    monkeypatch.setenv("AEGIS_INGEST_KEY", "shared-secret")
    with pytest.raises(HTTPException) as exc:
        require_ingest_key(x_aegis_ingest_key="guess", authorization=None)
    assert exc.value.status_code == 401


def test_correct_header_is_accepted(monkeypatch):
    monkeypatch.setenv("AEGIS_INGEST_KEY", "shared-secret")
    assert require_ingest_key(x_aegis_ingest_key="shared-secret", authorization=None) is None


def test_bearer_token_is_accepted(monkeypatch):
    monkeypatch.setenv("AEGIS_INGEST_KEY", "shared-secret")
    assert require_ingest_key(x_aegis_ingest_key=None, authorization="Bearer shared-secret") is None


def test_unset_key_allows_local_use(monkeypatch):
    monkeypatch.delenv("AEGIS_INGEST_KEY", raising=False)
    assert require_ingest_key(x_aegis_ingest_key=None, authorization=None) is None
