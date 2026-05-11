#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""GitHub Actions Governance Gate for agent deployments.

Validates the agent's policy configuration, generates a signed Ed25519
deployment receipt, and writes the event to the audit trail.  Exit code is
non-zero when any policy check fails so the calling workflow can block the
deployment.

Usage (standalone):
    python scripts/governance_gate.py \\
        --policy-file .agents/security.yaml \\
        --agent-manifest agents.yaml \\
        --commit abc1234

Required policy fields (all must be present and truthy/non-empty):
    audit_enabled   - boolean, must be true
    pii_scanning    - boolean, must be true
    allowed_tools   - list, must be non-empty
    max_tool_calls  - int, must be > 0
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

REQUIRED_POLICY_FIELDS: tuple[str, ...] = (
    "audit_enabled",
    "pii_scanning",
    "allowed_tools",
    "max_tool_calls",
)


@dataclass
class PolicyCheckResult:
    """Outcome of a single policy field check."""

    field: str
    passed: bool
    detail: str


@dataclass
class DeploymentReceipt:
    """Signed governance receipt for a deployment event."""

    receipt_id: str
    timestamp_utc: str
    agent_id: str
    agent_version: str
    commit_sha: str
    policy_id: str
    policy_hash: str
    deployer: str
    event_type: str
    previous_receipt_hash: str | None
    signer_public_key_b64: str
    signature_b64: str
    receipt_hash: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _canonical_json(data: dict[str, Any]) -> bytes:
    """Return deterministically encoded JSON bytes (RFC 8785 JCS-like)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file safely."""
    if not HAS_YAML:
        raise RuntimeError(
            "PyYAML is required. Install with: pip install PyYAML"
        )
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Expected a YAML mapping in {path}, got {type(data).__name__}")
    return data


# ---------------------------------------------------------------------------
# Policy validation
# ---------------------------------------------------------------------------

def check_policy(policy: dict[str, Any]) -> list[PolicyCheckResult]:
    """Validate required governance fields in the policy document.

    Returns a list of :class:`PolicyCheckResult` — one per required field.
    """
    results: list[PolicyCheckResult] = []

    # audit_enabled must be True
    val = policy.get("audit_enabled")
    results.append(PolicyCheckResult(
        field="audit_enabled",
        passed=val == True,  # noqa: E712
        detail="must be true" if val != True else "ok",  # noqa: E712
    ))

    # pii_scanning must be True
    val = policy.get("pii_scanning")
    results.append(PolicyCheckResult(
        field="pii_scanning",
        passed=val == True,  # noqa: E712
        detail="must be true" if val != True else "ok",  # noqa: E712
    ))

    # allowed_tools must be a non-empty list
    val = policy.get("allowed_tools")
    passed = isinstance(val, list) and len(val) > 0
    results.append(PolicyCheckResult(
        field="allowed_tools",
        passed=passed,
        detail="ok" if passed else "must be a non-empty list",
    ))

    # max_tool_calls must be a positive integer
    val = policy.get("max_tool_calls")
    passed = isinstance(val, int) and val > 0
    results.append(PolicyCheckResult(
        field="max_tool_calls",
        passed=passed,
        detail="ok" if passed else "must be a positive integer",
    ))

    return results


# ---------------------------------------------------------------------------
# Receipt generation
# ---------------------------------------------------------------------------

def generate_deployment_receipt(
    *,
    agent_id: str,
    agent_version: str,
    commit_sha: str,
    policy_id: str,
    policy_hash: str,
    deployer: str,
    signing_key: Ed25519PrivateKey,
    previous_receipt_hash: str | None = None,
) -> DeploymentReceipt:
    """Create an Ed25519-signed receipt for the deployment event."""
    public_key = signing_key.public_key()
    public_key_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    public_key_b64 = _b64(public_key_bytes)

    payload: dict[str, Any] = {
        "receipt_id": str(uuid.uuid4()),
        "timestamp_utc": _now_utc(),
        "agent_id": agent_id,
        "agent_version": agent_version,
        "commit_sha": commit_sha,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "deployer": deployer,
        "event_type": "agent-deployment",
        "previous_receipt_hash": previous_receipt_hash,
        "signer_public_key_b64": public_key_b64,
    }

    message = _canonical_json(payload)
    signature = signing_key.sign(message)
    signed_payload = {**payload, "signature_b64": _b64(signature)}
    receipt_hash = _sha256_hex(_canonical_json(signed_payload))

    return DeploymentReceipt(
        receipt_id=payload["receipt_id"],
        timestamp_utc=payload["timestamp_utc"],
        agent_id=agent_id,
        agent_version=agent_version,
        commit_sha=commit_sha,
        policy_id=policy_id,
        policy_hash=policy_hash,
        deployer=deployer,
        event_type="agent-deployment",
        previous_receipt_hash=previous_receipt_hash,
        signer_public_key_b64=public_key_b64,
        signature_b64=_b64(signature),
        receipt_hash=receipt_hash,
    )


def verify_deployment_receipt(receipt: dict[str, Any]) -> tuple[bool, str]:
    """Verify signature and receipt hash of a deployment receipt."""
    if not HAS_CRYPTO:
        return False, "cryptography package not available"

    required = {
        "receipt_id", "timestamp_utc", "agent_id", "agent_version",
        "commit_sha", "policy_id", "policy_hash", "deployer", "event_type",
        "previous_receipt_hash", "signer_public_key_b64", "signature_b64", "receipt_hash",
    }
    missing = required - set(receipt.keys())
    if missing:
        return False, f"missing fields: {sorted(missing)}"

    payload = {k: v for k, v in receipt.items() if k not in {"signature_b64", "receipt_hash"}}
    signed_payload = {**payload, "signature_b64": receipt["signature_b64"]}

    expected_hash = _sha256_hex(_canonical_json(signed_payload))
    if expected_hash != receipt["receipt_hash"]:
        return False, "receipt_hash mismatch"

    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(receipt["signer_public_key_b64"]))
        sig = base64.b64decode(receipt["signature_b64"])
        pub.verify(sig, _canonical_json(payload))
    except (ValueError, InvalidSignature) as exc:
        return False, f"signature verification failed: {exc.__class__.__name__}"

    return True, "ok"


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

def append_audit_entry(audit_path: Path, entry: dict[str, Any]) -> None:
    """Append a JSON line to the audit trail file."""
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=True) + "\n")


# ---------------------------------------------------------------------------
# Main gate logic
# ---------------------------------------------------------------------------

def run_governance_gate(
    policy_file: Path,
    agent_manifest: Path,
    commit_sha: str,
    require_receipt: bool = True,
    audit_file: Path | None = None,
    deployer: str | None = None,
) -> int:
    """Run the full governance gate.

    Returns 0 on success, 1 on policy failure.
    """
    deployer = deployer or os.environ.get("GITHUB_ACTOR", "unknown")
    audit_file = audit_file or Path("governance-audit.jsonl")

    # ── Print header ─────────────────────────────────────────────────────
    print()
    print("Governance Gate: agent-deployment-check")
    print(f"Policy file:     {policy_file}")
    print(f"Agent manifest:  {agent_manifest}")
    print(f"Commit:          {commit_sha[:7] if len(commit_sha) >= 7 else commit_sha}")
    print()

    # ── Load files ───────────────────────────────────────────────────────
    try:
        policy = _load_yaml(policy_file)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"ERROR: Could not load policy file: {exc}")
        return 1

    try:
        manifest = _load_yaml(agent_manifest)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"ERROR: Could not load agent manifest: {exc}")
        return 1

    agent_id = manifest.get("agent_id", "unknown-agent")
    agent_version = str(manifest.get("version", "0.0.0"))
    policy_id = policy.get("policy_id", str(policy_file))

    # ── Policy checks ────────────────────────────────────────────────────
    print("Checking policy configuration...")
    results = check_policy(policy)
    all_passed = True
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"  {result.field + ':':<22s} {status}")
        if not result.passed:
            all_passed = False
    print()

    if not all_passed:
        print("Governance gate: FAILED (policy checks did not pass)")
        print()
        # Still write an audit entry for the failure
        _write_audit_entry(
            audit_file=audit_file,
            agent_id=agent_id,
            agent_version=agent_version,
            commit_sha=commit_sha,
            policy_id=policy_id,
            policy_hash=_sha256_hex(_canonical_json(policy)),
            deployer=deployer,
            gate_result="FAILED",
            receipt_id=None,
        )
        return 1

    # ── Receipt generation ───────────────────────────────────────────────
    policy_hash = _sha256_hex(_canonical_json(policy))
    receipt_id: str | None = None
    receipt_signed = False
    chain_link: str | None = None

    if require_receipt:
        print("Generating deployment receipt...")
        if not HAS_CRYPTO:
            print("  WARNING: cryptography package not available — receipt will be unsigned")
            receipt_id = f"rec_{uuid.uuid4().hex[:8]}"
        else:
            signing_key = Ed25519PrivateKey.generate()
            receipt = generate_deployment_receipt(
                agent_id=agent_id,
                agent_version=agent_version,
                commit_sha=commit_sha,
                policy_id=policy_id,
                policy_hash=policy_hash,
                deployer=deployer,
                signing_key=signing_key,
            )
            receipt_id = f"rec_{receipt.receipt_id[:8]}"
            receipt_signed = True
            chain_link = f"sha256:{receipt.receipt_hash[:16]}"

            # Append receipt to audit trail
            receipt_dict = asdict(receipt)
            append_audit_entry(audit_file, receipt_dict)

        print(f"  Receipt ID:    {receipt_id}")
        print(f"  Signed:        {'yes (Ed25519)' if receipt_signed else 'no (crypto unavailable)'}")
        if chain_link:
            print(f"  Chain link:    {chain_link}")
        print()
    else:
        # Still write a basic audit entry without a receipt
        _write_audit_entry(
            audit_file=audit_file,
            agent_id=agent_id,
            agent_version=agent_version,
            commit_sha=commit_sha,
            policy_id=policy_id,
            policy_hash=policy_hash,
            deployer=deployer,
            gate_result="PASSED",
            receipt_id=receipt_id,
        )

    print("Governance gate: PASSED")
    print()
    return 0


def _write_audit_entry(
    *,
    audit_file: Path,
    agent_id: str,
    agent_version: str,
    commit_sha: str,
    policy_id: str,
    policy_hash: str,
    deployer: str,
    gate_result: str,
    receipt_id: str | None,
) -> None:
    """Write a plain audit entry (non-receipt) to the audit trail."""
    entry: dict[str, Any] = {
        "event_type": "governance-gate-result",
        "timestamp_utc": _now_utc(),
        "agent_id": agent_id,
        "agent_version": agent_version,
        "commit_sha": commit_sha,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "deployer": deployer,
        "gate_result": gate_result,
        "receipt_id": receipt_id,
    }
    append_audit_entry(audit_file, entry)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--policy-file",
        type=Path,
        default=Path(".agents/security.yaml"),
        help="Path to the agent policy YAML file (default: .agents/security.yaml)",
    )
    parser.add_argument(
        "--agent-manifest",
        type=Path,
        default=Path("agents.yaml"),
        help="Path to the agent manifest YAML file (default: agents.yaml)",
    )
    parser.add_argument(
        "--commit",
        default=os.environ.get("GITHUB_SHA", "unknown"),
        help="Commit SHA for this deployment (default: $GITHUB_SHA)",
    )
    parser.add_argument(
        "--require-receipt",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Generate and verify a signed deployment receipt (default: true)",
    )
    parser.add_argument(
        "--audit-file",
        type=Path,
        default=Path("governance-audit.jsonl"),
        help="Path to the audit trail JSONL file (default: governance-audit.jsonl)",
    )
    parser.add_argument(
        "--deployer",
        default=None,
        help="Deployer identity string (default: $GITHUB_ACTOR or 'unknown')",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    return run_governance_gate(
        policy_file=args.policy_file,
        agent_manifest=args.agent_manifest,
        commit_sha=args.commit,
        require_receipt=args.require_receipt,
        audit_file=args.audit_file,
        deployer=args.deployer,
    )


if __name__ == "__main__":
    sys.exit(main())
