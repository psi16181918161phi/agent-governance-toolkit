#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for scripts/governance_gate.py."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from governance_gate import (
    _canonical_json,
    _sha256_hex,
    append_audit_entry,
    check_policy,
    run_governance_gate,
    verify_deployment_receipt,
)

# Ed25519 support is required for receipt tests
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from governance_gate import generate_deployment_receipt
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write_yaml(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _passing_policy() -> str:
    return (
        "policy_id: test-policy\n"
        "version: '1.0.0'\n"
        "audit_enabled: true\n"
        "pii_scanning: true\n"
        "allowed_tools:\n"
        "  - web_search\n"
        "  - read_kb\n"
        "max_tool_calls: 50\n"
    )


def _passing_manifest() -> str:
    return (
        "agent_id: test-agent\n"
        "version: '1.2.3'\n"
        "team: platform-team\n"
    )


# ---------------------------------------------------------------------------
# check_policy tests
# ---------------------------------------------------------------------------

class TestCheckPolicy:
    def test_all_fields_pass(self):
        policy = {
            "audit_enabled": True,
            "pii_scanning": True,
            "allowed_tools": ["web_search"],
            "max_tool_calls": 10,
        }
        results = check_policy(policy)
        assert all(r.passed for r in results), [r for r in results if not r.passed]

    def test_audit_disabled_fails(self):
        policy = {
            "audit_enabled": False,
            "pii_scanning": True,
            "allowed_tools": ["web_search"],
            "max_tool_calls": 10,
        }
        results = check_policy(policy)
        failed = [r for r in results if not r.passed]
        assert len(failed) == 1
        assert failed[0].field == "audit_enabled"

    def test_pii_scanning_disabled_fails(self):
        policy = {
            "audit_enabled": True,
            "pii_scanning": False,
            "allowed_tools": ["web_search"],
            "max_tool_calls": 10,
        }
        results = check_policy(policy)
        failed = [r for r in results if not r.passed]
        assert len(failed) == 1
        assert failed[0].field == "pii_scanning"

    def test_empty_allowed_tools_fails(self):
        policy = {
            "audit_enabled": True,
            "pii_scanning": True,
            "allowed_tools": [],
            "max_tool_calls": 10,
        }
        results = check_policy(policy)
        failed = [r for r in results if not r.passed]
        assert any(r.field == "allowed_tools" for r in failed)

    def test_missing_allowed_tools_fails(self):
        policy = {
            "audit_enabled": True,
            "pii_scanning": True,
            "max_tool_calls": 10,
        }
        results = check_policy(policy)
        failed = [r for r in results if not r.passed]
        assert any(r.field == "allowed_tools" for r in failed)

    def test_zero_max_tool_calls_fails(self):
        policy = {
            "audit_enabled": True,
            "pii_scanning": True,
            "allowed_tools": ["web_search"],
            "max_tool_calls": 0,
        }
        results = check_policy(policy)
        failed = [r for r in results if not r.passed]
        assert any(r.field == "max_tool_calls" for r in failed)

    def test_negative_max_tool_calls_fails(self):
        policy = {
            "audit_enabled": True,
            "pii_scanning": True,
            "allowed_tools": ["web_search"],
            "max_tool_calls": -1,
        }
        results = check_policy(policy)
        failed = [r for r in results if not r.passed]
        assert any(r.field == "max_tool_calls" for r in failed)

    def test_multiple_failures(self):
        policy = {
            "audit_enabled": False,
            "pii_scanning": False,
            "allowed_tools": [],
            "max_tool_calls": 0,
        }
        results = check_policy(policy)
        assert all(not r.passed for r in results)

    def test_returns_four_results(self):
        results = check_policy({})
        assert len(results) == 4

    def test_allowed_tools_string_fails(self):
        """allowed_tools must be a list, not a string."""
        policy = {
            "audit_enabled": True,
            "pii_scanning": True,
            "allowed_tools": "web_search",
            "max_tool_calls": 10,
        }
        results = check_policy(policy)
        failed = [r for r in results if not r.passed]
        assert any(r.field == "allowed_tools" for r in failed)


# ---------------------------------------------------------------------------
# Receipt generation and verification tests
# ---------------------------------------------------------------------------

class TestReceiptGeneration:
    @pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
    def test_generate_receipt_fields(self):
        key = Ed25519PrivateKey.generate()
        receipt = generate_deployment_receipt(
            agent_id="test-agent",
            agent_version="1.0.0",
            commit_sha="abc1234",
            policy_id="test-policy",
            policy_hash="deadbeef",
            deployer="ci-bot",
            signing_key=key,
        )
        assert receipt.agent_id == "test-agent"
        assert receipt.commit_sha == "abc1234"
        assert receipt.event_type == "agent-deployment"
        assert receipt.signature_b64 != ""
        assert receipt.receipt_hash != ""

    @pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
    def test_verify_receipt_passes(self):
        from dataclasses import asdict
        key = Ed25519PrivateKey.generate()
        receipt = generate_deployment_receipt(
            agent_id="test-agent",
            agent_version="1.0.0",
            commit_sha="abc1234",
            policy_id="test-policy",
            policy_hash="deadbeef",
            deployer="ci-bot",
            signing_key=key,
        )
        ok, msg = verify_deployment_receipt(asdict(receipt))
        assert ok, msg

    @pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
    def test_tampered_receipt_fails(self):
        from dataclasses import asdict
        key = Ed25519PrivateKey.generate()
        receipt = generate_deployment_receipt(
            agent_id="test-agent",
            agent_version="1.0.0",
            commit_sha="abc1234",
            policy_id="test-policy",
            policy_hash="deadbeef",
            deployer="ci-bot",
            signing_key=key,
        )
        receipt_dict = asdict(receipt)
        receipt_dict["commit_sha"] = "tampered"
        ok, _ = verify_deployment_receipt(receipt_dict)
        assert not ok

    @pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
    def test_hash_chain_linkage(self):
        key = Ed25519PrivateKey.generate()
        r1 = generate_deployment_receipt(
            agent_id="agent-a",
            agent_version="1.0.0",
            commit_sha="aaa",
            policy_id="p1",
            policy_hash="h1",
            deployer="ci",
            signing_key=key,
        )
        r2 = generate_deployment_receipt(
            agent_id="agent-a",
            agent_version="1.0.1",
            commit_sha="bbb",
            policy_id="p1",
            policy_hash="h1",
            deployer="ci",
            signing_key=key,
            previous_receipt_hash=r1.receipt_hash,
        )
        assert r2.previous_receipt_hash == r1.receipt_hash

    def test_verify_missing_fields(self):
        ok, msg = verify_deployment_receipt({"receipt_id": "only-one-field"})
        assert not ok
        assert "missing" in msg


# ---------------------------------------------------------------------------
# Audit trail tests
# ---------------------------------------------------------------------------

class TestAuditTrail:
    def test_append_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sub" / "audit.jsonl"
            append_audit_entry(path, {"event": "test", "value": 1})
            assert path.exists()
            lines = path.read_text(encoding="utf-8").strip().splitlines()
            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["event"] == "test"

    def test_append_multiple_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            for i in range(3):
                append_audit_entry(path, {"seq": i})
            lines = path.read_text(encoding="utf-8").strip().splitlines()
            assert len(lines) == 3
            assert json.loads(lines[2])["seq"] == 2


# ---------------------------------------------------------------------------
# End-to-end run_governance_gate tests
# ---------------------------------------------------------------------------

class TestRunGovernanceGate:
    def test_passing_gate_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "security.yaml"
            manifest_path = Path(tmpdir) / "agents.yaml"
            audit_path = Path(tmpdir) / "audit.jsonl"
            _write_yaml(policy_path, _passing_policy())
            _write_yaml(manifest_path, _passing_manifest())
            rc = run_governance_gate(
                policy_file=policy_path,
                agent_manifest=manifest_path,
                commit_sha="abc1234def",
                require_receipt=False,
                audit_file=audit_path,
                deployer="test-ci",
            )
            assert rc == 0

    def test_failing_gate_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "security.yaml"
            manifest_path = Path(tmpdir) / "agents.yaml"
            audit_path = Path(tmpdir) / "audit.jsonl"
            _write_yaml(policy_path, (
                "policy_id: bad-policy\n"
                "audit_enabled: false\n"
                "pii_scanning: false\n"
                "allowed_tools: []\n"
                "max_tool_calls: 0\n"
            ))
            _write_yaml(manifest_path, _passing_manifest())
            rc = run_governance_gate(
                policy_file=policy_path,
                agent_manifest=manifest_path,
                commit_sha="abc1234def",
                require_receipt=False,
                audit_file=audit_path,
                deployer="test-ci",
            )
            assert rc == 1

    def test_missing_policy_file_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.jsonl"
            manifest_path = Path(tmpdir) / "agents.yaml"
            _write_yaml(manifest_path, _passing_manifest())
            rc = run_governance_gate(
                policy_file=Path(tmpdir) / "nonexistent.yaml",
                agent_manifest=manifest_path,
                commit_sha="abc1234",
                require_receipt=False,
                audit_file=audit_path,
                deployer="test-ci",
            )
            assert rc == 1

    def test_missing_manifest_file_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "security.yaml"
            audit_path = Path(tmpdir) / "audit.jsonl"
            _write_yaml(policy_path, _passing_policy())
            rc = run_governance_gate(
                policy_file=policy_path,
                agent_manifest=Path(tmpdir) / "nonexistent.yaml",
                commit_sha="abc1234",
                require_receipt=False,
                audit_file=audit_path,
                deployer="test-ci",
            )
            assert rc == 1

    def test_audit_trail_written_on_pass(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "security.yaml"
            manifest_path = Path(tmpdir) / "agents.yaml"
            audit_path = Path(tmpdir) / "audit.jsonl"
            _write_yaml(policy_path, _passing_policy())
            _write_yaml(manifest_path, _passing_manifest())
            run_governance_gate(
                policy_file=policy_path,
                agent_manifest=manifest_path,
                commit_sha="abc1234",
                require_receipt=False,
                audit_file=audit_path,
                deployer="test-ci",
            )
            assert audit_path.exists()
            lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
            assert len(lines) >= 1
            entry = json.loads(lines[0])
            assert entry["agent_id"] == "test-agent"

    def test_audit_trail_written_on_fail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "security.yaml"
            manifest_path = Path(tmpdir) / "agents.yaml"
            audit_path = Path(tmpdir) / "audit.jsonl"
            _write_yaml(policy_path, (
                "policy_id: bad-policy\n"
                "audit_enabled: false\n"
                "pii_scanning: true\n"
                "allowed_tools: [web_search]\n"
                "max_tool_calls: 10\n"
            ))
            _write_yaml(manifest_path, _passing_manifest())
            run_governance_gate(
                policy_file=policy_path,
                agent_manifest=manifest_path,
                commit_sha="abc1234",
                require_receipt=False,
                audit_file=audit_path,
                deployer="test-ci",
            )
            assert audit_path.exists()
            entry = json.loads(audit_path.read_text(encoding="utf-8").strip().splitlines()[0])
            assert entry["gate_result"] == "FAILED"

    @pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
    def test_receipt_generated_and_written_to_audit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "security.yaml"
            manifest_path = Path(tmpdir) / "agents.yaml"
            audit_path = Path(tmpdir) / "audit.jsonl"
            _write_yaml(policy_path, _passing_policy())
            _write_yaml(manifest_path, _passing_manifest())
            rc = run_governance_gate(
                policy_file=policy_path,
                agent_manifest=manifest_path,
                commit_sha="abc1234def",
                require_receipt=True,
                audit_file=audit_path,
                deployer="test-ci",
            )
            assert rc == 0
            assert audit_path.exists()
            lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
            assert len(lines) >= 1
            entry = json.loads(lines[0])
            # The receipt in the audit trail should be verifiable
            ok, msg = verify_deployment_receipt(entry)
            assert ok, msg


# ---------------------------------------------------------------------------
# Canonical JSON helper tests
# ---------------------------------------------------------------------------

class TestCanonicalJson:
    def test_deterministic_ordering(self):
        data1 = {"b": 2, "a": 1}
        data2 = {"a": 1, "b": 2}
        assert _canonical_json(data1) == _canonical_json(data2)

    def test_sha256_hex_length(self):
        h = _sha256_hex(b"hello")
        assert len(h) == 64
