# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Fault attribution.

Distributes saga-failure liability across the agents on the causal chain
leading to the failure, weighted by failed actions and an optional caller
``risk_weights`` policy. Falls back to full liability on the direct cause when
no action graph or weights are available.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class FaultAttribution:
    """Fault attribution for an agent."""

    agent_did: str
    liability_score: float
    causal_contribution: float
    is_direct_cause: bool = False
    reason: str = ""


@dataclass
class AttributionResult:
    """Attribution result for a saga failure."""

    attribution_id: str = field(default_factory=lambda: f"attr:{uuid.uuid4().hex[:8]}")
    saga_id: str = ""
    session_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    attributions: list[FaultAttribution] = field(default_factory=list)
    causal_chain_length: int = 0
    root_cause_agent: str | None = None

    @property
    def agents_involved(self) -> list[str]:
        return [a.agent_did for a in self.attributions]

    def get_liability(self, agent_did: str) -> float:
        for a in self.attributions:
            if a.agent_did == agent_did:
                return a.liability_score
        return 0.0


class CausalAttributor:
    """Distributes fault liability across the causal chain of a saga failure."""

    DIRECT_CAUSE_BONUS = 1.0

    def __init__(self) -> None:
        self._history: list[AttributionResult] = []

    def attribute(
        self,
        saga_id: str,
        session_id: str,
        agent_actions: dict[str, list[dict]],
        failure_step_id: str,
        failure_agent_did: str,
        risk_weights: dict[str, float] | None = None,
    ) -> AttributionResult:
        """Attribute liability for a saga failure.

        Walks ``agent_actions`` to the action that failed
        (``failure_agent_did`` at ``failure_step_id``) and shares liability
        across agents whose actions on that causal chain failed, plus a bonus
        for the direct cause. If ``risk_weights`` keyed by agent DID are
        provided, they override the causal split and distribute liability
        normalized across the participating agents. With neither an action
        graph nor matching weights, full liability goes to the direct cause.
        """
        agents = list(agent_actions.keys())

        if not agents:
            result = AttributionResult(
                saga_id=saga_id,
                session_id=session_id,
                attributions=[],
                causal_chain_length=0,
                root_cause_agent=failure_agent_did,
            )
            self._history.append(result)
            return result

        chain = self._causal_chain(agent_actions, failure_step_id, failure_agent_did)

        # Causal contribution: failed actions on the chain, plus direct-cause bonus.
        causal_raw: dict[str, float] = dict.fromkeys(agents, 0.0)
        for agent_did, action in chain:
            if not action.get("success", True):
                causal_raw[agent_did] += 1.0
        if failure_agent_did in causal_raw:
            causal_raw[failure_agent_did] += self.DIRECT_CAUSE_BONUS
        causal_total = sum(causal_raw.values())
        causal_contribution = {
            a: (causal_raw[a] / causal_total if causal_total else 0.0) for a in agents
        }

        use_weights = risk_weights is not None and any(
            risk_weights.get(a, 0.0) > 0.0 for a in agents
        )
        if use_weights:
            weight_raw = {a: max(0.0, risk_weights.get(a, 0.0)) for a in agents}
            weight_total = sum(weight_raw.values())
            liability = {a: weight_raw[a] / weight_total for a in agents}
            mode = "risk-weighted"
        elif causal_total > 0:
            liability = dict(causal_contribution)
            mode = "causal-chain"
        else:
            # Fallback: no failed actions on the chain and no weights.
            liability = {a: (1.0 if a == failure_agent_did else 0.0) for a in agents}
            mode = "direct-cause-fallback"

        attributions = []
        for agent_did in agents:
            is_direct = agent_did == failure_agent_did
            score = liability[agent_did]
            if is_direct:
                reason = f"Direct cause ({mode})"
            elif score > 0:
                reason = f"Causal contributor ({mode})"
            else:
                reason = "No causal contribution"
            attributions.append(
                FaultAttribution(
                    agent_did=agent_did,
                    liability_score=score,
                    causal_contribution=causal_contribution[agent_did],
                    is_direct_cause=is_direct,
                    reason=reason,
                )
            )

        result = AttributionResult(
            saga_id=saga_id,
            session_id=session_id,
            attributions=attributions,
            causal_chain_length=len(chain),
            root_cause_agent=failure_agent_did,
        )
        self._history.append(result)
        return result

    @staticmethod
    def _causal_chain(
        agent_actions: dict[str, list[dict]],
        failure_step_id: str,
        failure_agent_did: str,
    ) -> list[tuple[str, dict]]:
        """Flatten actions in iteration order and truncate at the failure action.

        The chain is every action up to and including the failure (matched by
        ``failure_agent_did`` + ``failure_step_id``, falling back to the first
        action with ``failure_step_id``). Post-failure actions are cascade
        effects, not causes, so they are excluded. If the failure action is not
        found, the whole flattened list is treated as the chain.
        """
        flat: list[tuple[str, dict]] = [
            (agent_did, action)
            for agent_did, actions in agent_actions.items()
            for action in actions
        ]

        fail_idx = None
        for idx, (agent_did, action) in enumerate(flat):
            if agent_did == failure_agent_did and action.get("step_id") == failure_step_id:
                fail_idx = idx
                break
        if fail_idx is None:
            for idx, (_, action) in enumerate(flat):
                if action.get("step_id") == failure_step_id:
                    fail_idx = idx
                    break

        if fail_idx is None:
            return flat
        return flat[: fail_idx + 1]

    @property
    def attribution_history(self) -> list[AttributionResult]:
        return list(self._history)
