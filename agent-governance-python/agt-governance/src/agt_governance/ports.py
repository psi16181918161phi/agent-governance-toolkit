# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Capability ports realized as Python protocols.

These mirror the language-neutral ports in `governance-contracts/spec/PORTS.md`.
The host owns the port shape, a source standalone provides the implementation,
and the pipeline wires them. This keeps each component free of its siblings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

Snapshot = dict[str, Any]


@dataclass(frozen=True)
class Verdict:
    """A policy decision. ``effect`` is one of allow, warn, deny, escalate."""

    effect: str
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        """Whether the action may proceed. ``warn`` proceeds, ``deny`` does not."""
        return self.effect in ("allow", "warn")


@runtime_checkable
class Enricher(Protocol):
    """Adds one source domain's data to the snapshot under its reserved key."""

    def domain(self) -> str: ...

    def enrich(self, snapshot: Snapshot, intervention_point: str) -> Snapshot: ...


@runtime_checkable
class PolicyPort(Protocol):
    """Decides a verdict from an enriched snapshot. ACS is the production impl."""

    def decide(self, snapshot: Snapshot) -> Verdict: ...


@runtime_checkable
class Sink(Protocol):
    """Records a decision as a signed governance event."""

    def record(self, snapshot: Snapshot, verdict: Verdict) -> dict[str, Any]: ...
