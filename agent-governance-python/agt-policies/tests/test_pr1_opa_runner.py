# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for OPA verdict decoding."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agt._harness.opa_runner import _decode_opa_verdict  # noqa: E402


def _opa_response(verdict: dict[str, object]) -> dict[str, object]:
    return {"result": [{"expressions": [{"value": verdict}]}]}


def test_decode_missing_decision_fails_closed() -> None:
    verdict = {"reason": "policy:missing_decision"}

    result = _decode_opa_verdict(_opa_response(verdict))

    assert result.decision == "deny"
    assert result.reason == "runtime_error:engine_invalid_verdict"
    assert result.message == (
        "opa returned verdict without recognized decision: "
        "{'reason': 'policy:missing_decision'}"
    )
    assert result.raw == verdict


def test_decode_unknown_decision_fails_closed() -> None:
    verdict = {"decision": "maybe", "reason": "policy:unknown_decision"}

    result = _decode_opa_verdict(_opa_response(verdict))

    assert result.decision == "deny"
    assert result.reason == "runtime_error:engine_invalid_verdict"
    assert result.message == (
        "opa returned verdict without recognized decision: "
        "{'decision': 'maybe', 'reason': 'policy:unknown_decision'}"
    )
    assert result.raw == verdict


def test_decode_empty_result_raises_runtime_error() -> None:
    with pytest.raises(RuntimeError, match="opa eval produced no result"):
        _decode_opa_verdict({"result": []})


def test_decode_valid_deny_verdict_is_preserved() -> None:
    verdict = {
        "decision": "deny",
        "reason": "policy:blocked",
        "message": "blocked by policy",
        "evidence": {"rule": "deny_tools"},
        "result_labels": ["blocked"],
    }

    result = _decode_opa_verdict(_opa_response(verdict))

    assert result.decision == "deny"
    assert result.reason == "policy:blocked"
    assert result.message == "blocked by policy"
    assert result.evidence == {"rule": "deny_tools"}
    assert result.result_labels == ["blocked"]
    assert result.raw == verdict


def test_decode_valid_allow_verdict_is_preserved() -> None:
    verdict = {
        "decision": "allow",
        "reason": "policy:ok",
        "message": "allowed by policy",
    }

    result = _decode_opa_verdict(_opa_response(verdict))

    assert result.decision == "allow"
    assert result.reason == "policy:ok"
    assert result.message == "allowed by policy"
    assert result.raw == verdict
