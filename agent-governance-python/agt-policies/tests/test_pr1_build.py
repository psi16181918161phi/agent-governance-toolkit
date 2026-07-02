# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for manifest-resolution Rego rendering."""

from __future__ import annotations

from datetime import date
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from agt.manifest_resolution import ResolutionError, ResolutionReason, resolve_manifest


OPA = Path("/home/liamcrumm/.local/bin/opa")


def _legacy_binding() -> dict[str, dict[str, Any]]:
    return {
        "pre_tool_call": {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "tool_name_from": "$.tool_call.name",
            "policy": {"id": "agt_legacy_rules"},
        }
    }


def _rule_with_condition(name: str, condition: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "condition": condition,
        "action": "deny",
        "priority": 10,
        "message": "blocked",
    }


def _write_governance(root: Path, rules: list[dict[str, Any]]) -> None:
    (root / "governance.yaml").write_text(
        yaml.safe_dump(
            {
                "rules": rules,
                "intervention_points": _legacy_binding(),
            }
        ),
        encoding="utf-8",
    )


def _assert_invalid_governance(exc: pytest.ExceptionInfo[ResolutionError]) -> None:
    assert exc.value.reason == ResolutionReason.INVALID_GOVERNANCE


def test_regex_lookbehind_rejected_before_render(tmp_path: Path) -> None:
    root = tmp_path
    _write_governance(
        root,
        [
            _rule_with_condition(
                "bad-regex",
                {"field": "tool_call.args.q", "operator": "matches", "value": "(?<=a)b"},
            )
        ],
    )

    with pytest.raises(ResolutionError) as exc:
        resolve_manifest(root, root)

    _assert_invalid_governance(exc)


def test_opa_treats_python_valid_lookbehind_as_undefined() -> None:
    if not OPA.exists():
        pytest.skip("OPA binary not available at /home/liamcrumm/.local/bin/opa")

    proc = subprocess.run(  # noqa: S603 — trusted checked-in test harness
        [str(OPA), "eval", "-f", "json", 'regex.match("(?<=a)b", "ab")'],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert json.loads(proc.stdout) == {}


def test_unknown_operator_rejected_before_render(tmp_path: Path) -> None:
    root = tmp_path
    _write_governance(
        root,
        [
            _rule_with_condition(
                "unknown-op",
                {"field": "tool_call.args.q", "operator": "glob", "value": "secret*"},
            )
        ],
    )

    with pytest.raises(ResolutionError) as exc:
        resolve_manifest(root, root)

    _assert_invalid_governance(exc)


def test_date_condition_value_raises_resolution_error_not_type_error(tmp_path: Path) -> None:
    root = tmp_path
    _write_governance(
        root,
        [
            _rule_with_condition(
                "date-value",
                {"field": "tool_call.args.q", "operator": "eq", "value": date(2026, 7, 2)},
            )
        ],
    )

    with pytest.raises(ResolutionError) as exc:
        resolve_manifest(root, root)

    _assert_invalid_governance(exc)


def test_valid_regex_deny_rule_renders_and_denies_with_opa(tmp_path: Path) -> None:
    root = tmp_path
    _write_governance(
        root,
        [
            _rule_with_condition(
                "valid-regex",
                {"field": "tool_call.args.q", "operator": "regex", "value": "sec.*"},
            )
        ],
    )

    manifest = resolve_manifest(root, root)
    bundle = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])
    rego = (bundle / "agt_legacy.rego").read_text(encoding="utf-8")
    assert 'regex.match("sec.*", _v)' in rego

    if not OPA.exists():
        pytest.skip("OPA binary not available at /home/liamcrumm/.local/bin/opa")

    policy_input = {"snapshot": {"tool_call": {"args": {"q": "secret"}}}}
    proc = subprocess.run(  # noqa: S603 — trusted checked-in test harness
        [
            str(OPA),
            "eval",
            "--format",
            "json",
            "--stdin-input",
            "--data",
            str(bundle),
            "data.agt.legacy.verdict",
        ],
        input=json.dumps(policy_input),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    body = json.loads(proc.stdout)
    verdict = body["result"][0]["expressions"][0]["value"]
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "valid-regex"
