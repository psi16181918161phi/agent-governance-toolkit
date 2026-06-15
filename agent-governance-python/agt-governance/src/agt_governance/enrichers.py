# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Snapshot enrichers, one per source standalone.

Each enricher reads its own source and writes its reserved key in
``snapshot["enrichment"]`` per `governance-contracts/spec/SNAPSHOT.md`. The host
passes per-request inputs under ``snapshot["request"]`` so an enricher can verify
a presented credential or evaluate a sandbox request. Enrichers do not read each
other's keys, so they are order independent.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any

from identity_engine import IdentityError, IdentityManager
from lifecycle_engine import LifecycleManager
from sandbox_engine import SandboxEngine

from .ports import Snapshot


class IdentityEnricher:
    """Adds ``enrichment.identity`` from the Identity component.

    Verifies a presented credential and projects the verified DID, credential
    status, and trust level into the snapshot. Two bindings the Identity core
    deliberately leaves to the caller are enforced here:

    * **Subject binding.** ``Credential.verify`` only checks the issuer
      signature, expiry, and revocation; it does not check who the credential
      was issued to. This enricher requires ``credential.subject_did`` to equal
      the governed ``agent_id``, so an agent cannot present another agent's
      credential and be verified as itself.
    * **Issuer anchoring.** A credential's ``trust_score`` is an assertion made
      by its issuer. It is honored only when the issuer DID is in the host's
      configured ``trusted_issuers``. Without an anchor a credential's trust is
      not honored, so an agent cannot mint itself a high-trust credential.
    """

    def __init__(
        self,
        identity: IdentityManager,
        *,
        trusted_issuers: Iterable[str] | None = None,
    ) -> None:
        self._identity = identity
        self._trusted_issuers = (
            frozenset(trusted_issuers) if trusted_issuers is not None else None
        )

    def domain(self) -> str:
        return "identity"

    def enrich(self, snapshot: Snapshot, intervention_point: str) -> Snapshot:
        agent_id = snapshot["agent"]["agent_id"]
        credential = snapshot.get("request", {}).get("credential")
        verified = False
        credential_status = "none"
        trust_level = "untrusted"
        issuer_did: str | None = None
        if credential is not None:
            if not isinstance(credential, dict):
                # A malformed credential is a deny, never a crash.
                credential_status = "malformed"
            else:
                issuer_did = credential.get("issuer_did")
                subject_did = credential.get("subject_did")
                try:
                    authentic = bool(self._identity.verify_credential(credential))
                except IdentityError:
                    authentic = False
                if not authentic:
                    credential_status = self._invalid_status(credential)
                elif subject_did != agent_id:
                    # Authentic, but issued to a different subject. Presenting
                    # another agent's credential must not verify this caller.
                    credential_status = "subject_mismatch"
                else:
                    verified = True
                    credential_status = "active"
                    trust_level = self._trust_level(credential, issuer_did)
        snapshot.setdefault("enrichment", {})["identity"] = {
            "did": agent_id,
            "verified": verified,
            "credential_status": credential_status,
            "trust_level": trust_level,
            "issuer_did": issuer_did,
        }
        return snapshot

    def _trust_level(self, credential: dict[str, Any], issuer_did: Any) -> str:
        """Map a verified credential's trust assertion to a trust level.

        Returns ``untrusted`` unless the issuer is anchored and the asserted
        score is a valid integer the Identity core accepts. Missing, malformed,
        or out-of-range scores never upgrade trust.
        """
        if self._trusted_issuers is None or issuer_did not in self._trusted_issuers:
            return "untrusted"
        claims = credential.get("claims")
        if not isinstance(claims, dict) or "trust_score" not in claims:
            return "untrusted"
        try:
            return self._identity.trust_level(int(claims["trust_score"]))
        except (IdentityError, TypeError, ValueError):
            return "untrusted"

    @staticmethod
    def _invalid_status(credential: dict[str, Any]) -> str:
        expires = credential.get("expires_at_ms")
        if isinstance(expires, int) and expires < int(time.time() * 1000):
            return "expired"
        return "invalid"


class LifecycleEnricher:
    """Adds ``enrichment.lifecycle`` from the Lifecycle component."""

    def __init__(self, lifecycle: LifecycleManager) -> None:
        self._lifecycle = lifecycle

    def domain(self) -> str:
        return "lifecycle"

    def enrich(self, snapshot: Snapshot, intervention_point: str) -> Snapshot:
        agent_id = snapshot["agent"]["agent_id"]
        agent = self._lifecycle.get(agent_id)
        if agent is None:
            data: dict[str, Any] = {"state": "unknown", "is_active": False}
        else:
            state = agent["state"]
            data = {"state": state, "is_active": state in ("active", "rotating_credentials")}
        snapshot.setdefault("enrichment", {})["lifecycle"] = data
        return snapshot


class SandboxEnricher:
    """Adds ``enrichment.sandbox`` from the Sandbox component.

    When the host supplies a sandbox spec and request, evaluates whether the
    requested execution is permitted under the isolation policy.
    """

    def __init__(self, sandbox: SandboxEngine) -> None:
        self._sandbox = sandbox

    def domain(self) -> str:
        return "sandbox"

    def enrich(self, snapshot: Snapshot, intervention_point: str) -> Snapshot:
        request_inputs = snapshot.get("request", {})
        spec = request_inputs.get("sandbox_spec")
        request = request_inputs.get("sandbox_request")
        if spec is None or request is None:
            return snapshot
        decision = self._sandbox.evaluate(spec, request)
        violations = decision.get("violations", []) or []
        snapshot.setdefault("enrichment", {})["sandbox"] = {
            "spec_id": spec.get("id"),
            "allowed": bool(decision.get("allowed", False)),
            "violations": [v.get("kind") for v in violations],
        }
        return snapshot


class DriftEnricher:
    """Adds ``enrichment.drift`` from the Drift primitive.

    At an output intervention point, scores how far a candidate output drifts
    from a reference output. The host supplies both under ``request``.
    """

    def __init__(self) -> None:
        from cmvk import verify

        self._verify = verify

    def domain(self) -> str:
        return "drift"

    def enrich(self, snapshot: Snapshot, intervention_point: str) -> Snapshot:
        request_inputs = snapshot.get("request", {})
        reference = request_inputs.get("reference_output")
        candidate = request_inputs.get("candidate_output")
        if reference is None or candidate is None:
            return snapshot
        score = self._verify(reference, candidate)
        snapshot.setdefault("enrichment", {})["drift"] = {
            "score": getattr(score, "drift_score", None),
            "confidence": getattr(score, "confidence", None),
            "drift_type": getattr(getattr(score, "drift_type", None), "value", None),
        }
        return snapshot


class ContextEnricher:
    """Adds ``enrichment.context`` from the Context primitive.

    Routes a context query into a tier so a policy can reason about the working
    set a model is about to see. The host supplies the query under ``request``.
    """

    def __init__(self) -> None:
        from caas.routing.heuristic_router import HeuristicRouter

        self._router = HeuristicRouter()

    def domain(self) -> str:
        return "context"

    def enrich(self, snapshot: Snapshot, intervention_point: str) -> Snapshot:
        query = snapshot.get("request", {}).get("context_query")
        if query is None:
            return snapshot
        decision = self._router.route(query)
        tier = getattr(decision, "model_tier", None)
        tier_value = getattr(tier, "value", tier)
        snapshot.setdefault("enrichment", {})["context"] = {
            "tier": str(tier_value) if tier_value is not None else None,
            "suggested_model": getattr(decision, "suggested_model", None),
            "reason": getattr(decision, "reason", None),
        }
        return snapshot
