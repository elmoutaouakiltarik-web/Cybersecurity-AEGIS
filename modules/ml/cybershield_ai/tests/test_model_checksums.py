"""Checksum gating for model artifacts.

The models are joblib pickles: loading a tampered file executes code with the
privileges of the service. These tests pin the gate that runs before
``joblib.load``.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybershield_pro.predict import (  # noqa: E402
    DEFAULT_ANOMALY_MODEL,
    DEFAULT_BINARY_MODEL,
    DEFAULT_FAMILY_MODEL,
    verify_model,
)


def _write_manifest(path: Path, name: str, digest: str) -> Path:
    manifest = path / "SHA256SUMS"
    manifest.write_text(f"{digest}  {name}\n", encoding="utf-8")
    return manifest


def test_registered_models_verify():
    for model in (DEFAULT_BINARY_MODEL, DEFAULT_FAMILY_MODEL, DEFAULT_ANOMALY_MODEL):
        resolved = verify_model(model)
        assert resolved.exists()


def test_modified_model_is_rejected(tmp_path, monkeypatch):
    model = tmp_path / "model.joblib"
    model.write_bytes(b"not-the-original-artifact")
    good = hashlib.sha256(b"the-original-artifact").hexdigest()
    manifest = _write_manifest(tmp_path, model.name, good)
    monkeypatch.setenv("CYBERSHIELD_MODEL_CHECKSUMS", str(manifest))
    monkeypatch.delenv("CYBERSHIELD_ALLOW_UNVERIFIED_MODELS", raising=False)

    with pytest.raises(RuntimeError, match="checksum mismatch"):
        verify_model(model)


def test_unregistered_model_is_rejected(tmp_path, monkeypatch):
    model = tmp_path / "unknown.joblib"
    model.write_bytes(b"whatever")
    manifest = _write_manifest(tmp_path, "some-other-model.joblib", "0" * 64)
    monkeypatch.setenv("CYBERSHIELD_MODEL_CHECKSUMS", str(manifest))
    monkeypatch.delenv("CYBERSHIELD_ALLOW_UNVERIFIED_MODELS", raising=False)

    with pytest.raises(RuntimeError, match="no entry"):
        verify_model(model)


def test_unregistered_model_allowed_with_explicit_override(tmp_path, monkeypatch):
    model = tmp_path / "custom.joblib"
    model.write_bytes(b"whatever")
    manifest = _write_manifest(tmp_path, "other.joblib", "0" * 64)
    monkeypatch.setenv("CYBERSHIELD_MODEL_CHECKSUMS", str(manifest))
    monkeypatch.setenv("CYBERSHIELD_ALLOW_UNVERIFIED_MODELS", "1")

    assert verify_model(model) == model
