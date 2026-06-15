# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The governance pipeline, the adapter host realized.

A host calls :meth:`GovernancePipeline.govern` at an intervention point. The
pipeline builds a snapshot, runs the enrichers that feed it from Identity,
Lifecycle, and Sandbox, asks the policy for a verdict, and records the decision
through the Observability audit sink. Each component is an ordinary published
dependency wired only through the snapshot and the ports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

from identity_engine import IdentityManager
from lifecycle_engine import LifecycleManager
from observability_engine import ObservabilityManager
from sandbox_engine import SandboxEngine

from .enrichers import (
    ContextEnricher,
    DriftEnricher,
    IdentityEnricher,
    LifecycleEnricher,
    SandboxEnricher,
)
from .policy import RulePolicy
from .ports import Enricher, PolicyPort, Snapshot, Verdict
from .sinks import ObservabilityAuditSink


@dataclass(frozen=True)
class GovernanceResult:
    """The outcome of one governance decision."""

    allowed: bool
    verdict: Verdict
    snapshot: Snapshot
    audit_event_id: str
    audit_signature: str


class GovernancePipeline:
    """Composes the standalone governance components into one decision flow."""

    def __init__(
        self,
        *,
        identity: IdentityManager,
        lifecycle: LifecycleManager,
        observability: ObservabilityManager,
        audit_signing_key_b64: str,
        sandbox: Optional[SandboxEngine] = None,
        policy: Optional[PolicyPort] = None,
        enrichers: Optional[Sequence[Enricher]] = None,
        trusted_issuers: Optional[Iterable[str]] = None,
    ) -> None:
        self.identity = identity
        self.lifecycle = lifecycle
        self.observability = observability
        self._has_sandbox = sandbox is not None
        if enrichers is not None:
            self.enrichers: list[Enricher] = list(enrichers)
        else:
            self.enrichers = [
                IdentityEnricher(identity, trusted_issuers=trusted_issuers),
                LifecycleEnricher(lifecycle),
                DriftEnricher(),
                ContextEnricher(),
            ]
            if sandbox is not None:
                self.enrichers.append(SandboxEnricher(sandbox))
        self.policy = policy or RulePolicy()
        self.sink = ObservabilityAuditSink(observability, audit_signing_key_b64)

    def govern(
        self,
        agent_id: str,
        action: str,
        resource: str,
        *,
        intervention_point: str = "pre_tool_call",
        target_value: Any = None,
        credential: Optional[dict[str, Any]] = None,
        sandbox_spec: Optional[dict[str, Any]] = None,
        sandbox_request: Optional[dict[str, Any]] = None,
        reference_output: Optional[str] = None,
        candidate_output: Optional[str] = None,
        context_query: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> GovernanceResult:
        """Govern one agent action end to end."""
        snapshot: Snapshot = {
            "intervention_point": intervention_point,
            "agent": {"agent_id": agent_id, "session_id": session_id},
            "target": {
                "kind": "tool_args",
                "action": action,
                "resource": resource,
                "value": target_value,
            },
            "request": {
                "credential": credential,
                "sandbox_spec": sandbox_spec,
                "sandbox_request": sandbox_request,
                "reference_output": reference_output,
                "candidate_output": candidate_output,
                "context_query": context_query,
            },
            "enrichment": {},
        }

        for enricher in self.enrichers:
            snapshot = enricher.enrich(snapshot, intervention_point)

        # Fail closed if execution isolation was requested but never enforced.
        # ``govern`` advertises sandbox parameters, so a host that passes a
        # sandbox spec/request to a pipeline built without a SandboxEngine (or
        # with a custom enricher list that drops it) must not be silently
        # allowed. An absent ``sandbox`` enrichment under these inputs is a deny.
        if (sandbox_spec is not None or sandbox_request is not None) and (
            "sandbox" not in snapshot["enrichment"]
        ):
            snapshot["enrichment"]["sandbox"] = {
                "spec_id": (sandbox_spec or {}).get("id"),
                "allowed": False,
                "violations": ["sandbox_not_enforced"],
            }

        verdict = self.policy.decide(snapshot)
        audit = self.sink.record(snapshot, verdict)

        public_snapshot = {k: v for k, v in snapshot.items() if k != "request"}
        return GovernanceResult(
            allowed=verdict.allowed,
            verdict=verdict,
            snapshot=public_snapshot,
            audit_event_id=audit["event_id"],
            audit_signature=audit["signature"],
        )
