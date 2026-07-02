# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for finite snapshot budget counters."""

from __future__ import annotations

import json

import pytest

from agt.policies.snapshot import SnapshotBuilder, _validate_budget_counter, input_snapshot


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_validate_budget_counter_rejects_non_finite_cost(value: float) -> None:
    with pytest.raises(ValueError, match="cost_usd"):
        _validate_budget_counter("cost_usd", value)


def test_record_cost_rejects_infinity_without_mutating() -> None:
    builder = SnapshotBuilder(agent_id="bot", cost_usd=1.25)

    with pytest.raises(ValueError, match="usd"):
        builder.record_cost(float("inf"))

    assert builder.cost_usd == pytest.approx(1.25)


def test_record_elapsed_rejects_nan_without_mutating() -> None:
    builder = SnapshotBuilder(agent_id="bot", elapsed_seconds=2.5)

    with pytest.raises(ValueError, match="seconds"):
        builder.record_elapsed(float("nan"))

    assert builder.elapsed_seconds == pytest.approx(2.5)


def test_envelope_rejects_non_finite_float_budget() -> None:
    with pytest.raises(ValueError, match="elapsed_seconds"):
        input_snapshot(agent_id="bot", body="hi", elapsed_seconds=float("inf"))


def test_finite_cost_and_elapsed_serialize_without_non_standard_floats() -> None:
    builder = SnapshotBuilder(agent_id="bot")

    builder.record_cost(0.25)
    builder.record_elapsed(1.5)

    envelope = builder.envelope("input")
    encoded = json.dumps(envelope)

    assert "NaN" not in encoded
    assert "Infinity" not in encoded
    assert json.loads(encoded)["budgets"] == {
        "tool_call_count": 0,
        "token_count": 0,
        "elapsed_seconds": 1.5,
        "cost_usd": 0.25,
    }
