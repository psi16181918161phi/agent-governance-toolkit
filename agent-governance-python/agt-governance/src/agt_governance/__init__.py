# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT host wiring for the standalone governance components.

``agt_governance`` is the bridge layer. It re-imports the Identity, Lifecycle,
Observability, and Sandbox standalones as ordinary dependencies and composes them
into one :class:`GovernancePipeline` through the governance contracts. The policy
decision is a :class:`PolicyPort`, defaulting to :class:`RulePolicy`, with the
ACS standalone as the production provider.
"""

from __future__ import annotations

from .enrichers import (
    ContextEnricher,
    DriftEnricher,
    IdentityEnricher,
    LifecycleEnricher,
    SandboxEnricher,
)
from .pipeline import GovernancePipeline, GovernanceResult
from .policy import RulePolicy
from .ports import Enricher, PolicyPort, Sink, Snapshot, Verdict
from .sinks import (
    ObservabilityAuditSink,
    signer_did_from_signing_key,
    signing_key_from_identity_hex,
)
from .transport import MeshTransport

__all__ = [
    "GovernancePipeline",
    "GovernanceResult",
    "IdentityEnricher",
    "LifecycleEnricher",
    "SandboxEnricher",
    "DriftEnricher",
    "ContextEnricher",
    "MeshTransport",
    "ObservabilityAuditSink",
    "signing_key_from_identity_hex",
    "signer_did_from_signing_key",
    "RulePolicy",
    "Enricher",
    "PolicyPort",
    "Sink",
    "Snapshot",
    "Verdict",
]

__version__ = "0.1.0"
