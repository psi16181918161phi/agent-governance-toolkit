# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The observability audit sink.

Turns a decision into a signed governance event and emits it through the
Observability component. The signing key is an Ed25519 seed, base64 encoded, the
same form Observability uses. A convenience builds that seed from an Identity
private key so the audit signer is itself an identity.

The event's ``signer_did`` is derived from the signing key, never supplied, so a
verifier that resolves ``signer_did`` to a public key gets the exact key the
event was signed with. The Ed25519 signature covers the whole event including
``attributes`` (the decision body), so a recorded decision is tamper-evident.
"""

from __future__ import annotations

import base64
import time
import uuid
from typing import Any

from identity_engine import IdentityManager
from observability_engine import ObservabilityManager

from .ports import Snapshot, Verdict


def signing_key_from_identity_hex(private_key_hex: str) -> str:
    """Map an Identity private key (hex) to the base64 seed Observability signs with."""
    return base64.b64encode(bytes.fromhex(private_key_hex)).decode("ascii")


def signer_did_from_signing_key(signing_key_b64: str) -> str:
    """Derive the signer DID that corresponds to an audit signing key.

    The signing key is the base64 Ed25519 seed Observability signs with. The
    audit signer's DID must be the ``did:mesh`` of the public key derived from
    that seed, so a verifier can resolve ``signer_did`` to the exact key the
    event was signed with. Derivation goes through the Identity core, so it
    matches the DID scheme every other component uses.
    """
    seed_hex = base64.b64decode(signing_key_b64).hex()
    return IdentityManager().generate_identity(seed_hex)["did"]


class ObservabilityAuditSink:
    """Records decisions as signed governance events."""

    def __init__(
        self,
        observability: ObservabilityManager,
        signing_key_b64: str,
        *,
        source: str = "agt-governance",
    ) -> None:
        self._observability = observability
        self._signing_key_b64 = signing_key_b64
        self._signer_did = signer_did_from_signing_key(signing_key_b64)
        self._source = source

    def record(self, snapshot: Snapshot, verdict: Verdict) -> dict[str, Any]:
        now_ms = int(time.time() * 1000)
        event = {
            "specversion": "1.0",
            "id": f"evt:{uuid.uuid4().hex}",
            "source": self._source,
            "type": "com.microsoft.agent.policy",
            "kind": "policy_check",
            "time_ms": now_ms,
            "severity": "info" if verdict.allowed else "warn",
            "agent_id": snapshot["agent"]["agent_id"],
            "attributes": {
                "effect": verdict.effect,
                "reason": verdict.reason,
                "intervention_point": snapshot.get("intervention_point"),
                "action": snapshot.get("target", {}).get("action"),
                "resource": snapshot.get("target", {}).get("resource"),
                "enrichment": snapshot.get("enrichment", {}),
                "signer_did": self._signer_did,
            },
        }
        signed = self._observability.sign_event(event, self._signing_key_b64)
        signature = str(signed["signature"]) if isinstance(signed, dict) else str(signed)
        self._observability.emit(event)
        return {
            "event_id": event["id"],
            "signature": signature,
            "signer_did": self._signer_did,
            "event": event,
        }
