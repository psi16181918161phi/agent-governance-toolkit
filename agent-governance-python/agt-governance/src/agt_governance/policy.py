# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Policy ports.

The production policy provider is the ACS standalone. It is wired through an
adapter that satisfies :class:`PolicyPort`; that adapter, ``AcsPolicy``, lives in
the ``mcp_governance`` package, not here. ``RulePolicy`` below is a
dependency-light default that reads the enriched snapshot directly, which keeps
the pipeline runnable without building the ACS engine.
"""

from __future__ import annotations

from collections.abc import Iterable

from .ports import PolicyPort, Snapshot, Verdict


class RulePolicy(PolicyPort):
    """A small, explicit policy over the snapshot enrichment.

    Denies when identity is unverified, when the agent is not active, when the
    trust level is below the required floor, when the action is on the deny
    list, when output drift exceeds ``max_drift_score``, or when the sandbox
    isolation is violated. The ``context`` enrichment is advisory (it informs
    downstream model routing) and is intentionally not a deny signal here.
    """

    _TRUST_ORDER = {
        "untrusted": 0,
        "probationary": 1,
        "standard": 2,
        "trusted": 3,
        "verified_partner": 4,
    }

    def __init__(
        self,
        *,
        denied_actions: Iterable[str] = (),
        require_verified: bool = True,
        require_active: bool = True,
        min_trust_level: str | None = None,
        max_drift_score: float | None = None,
    ) -> None:
        if min_trust_level is not None and min_trust_level not in self._TRUST_ORDER:
            # A misspelled floor must not silently disable the trust check.
            raise ValueError(
                f"unknown min_trust_level {min_trust_level!r}; "
                f"expected one of {sorted(self._TRUST_ORDER)}"
            )
        self._denied = frozenset(denied_actions)
        self._require_verified = require_verified
        self._require_active = require_active
        self._min_trust = min_trust_level
        self._max_drift = max_drift_score

    def decide(self, snapshot: Snapshot) -> Verdict:
        enrichment = snapshot.get("enrichment", {})
        identity = enrichment.get("identity", {})
        lifecycle = enrichment.get("lifecycle", {})
        sandbox = enrichment.get("sandbox")
        drift = enrichment.get("drift")
        action = snapshot.get("target", {}).get("action")

        if self._require_verified and not identity.get("verified", False):
            return Verdict("deny", "caller identity is not verified")

        if self._require_active and not lifecycle.get("is_active", False):
            return Verdict("deny", f"agent is not active (state {lifecycle.get('state')})")

        if self._min_trust is not None:
            have = self._TRUST_ORDER.get(identity.get("trust_level", "untrusted"), 0)
            need = self._TRUST_ORDER[self._min_trust]
            if have < need:
                return Verdict(
                    "deny",
                    f"trust level {identity.get('trust_level')} is below required {self._min_trust}",
                )

        if action in self._denied:
            return Verdict("deny", f"action {action} is denied by policy")

        if self._max_drift is not None and drift is not None:
            score = drift.get("score")
            if isinstance(score, (int, float)) and score > self._max_drift:
                return Verdict(
                    "deny",
                    f"output drift {score} exceeds maximum {self._max_drift}",
                )

        if sandbox is not None and not sandbox.get("allowed", True):
            return Verdict("deny", f"sandbox isolation violated: {sandbox.get('violations')}")

        return Verdict("allow", "all governance checks passed")
