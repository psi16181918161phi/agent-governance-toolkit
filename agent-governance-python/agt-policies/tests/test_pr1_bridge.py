# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for bridge GLOB translation and threshold rendering."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

_PACKAGE_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_SRC))

pytest.importorskip("agent_os")

from agent_os.integrations.base import GovernancePolicy, PatternType  # noqa: E402

from agt.policies.bridge import _pattern_to_regex, governance_to_acs_manifest  # noqa: E402


class _PolicyFixture:
    name = "non_finite_threshold"
    max_tokens = 4096
    max_tool_calls = 10
    allowed_tools: list[str] = []
    blocked_patterns: list[Any] = []
    require_human_approval = False
    confidence_threshold = float("inf")
    version = "1.0.0"


def _opa() -> Path:
    return Path.home() / ".local" / "bin" / "opa"


def test_glob_pattern_to_regex_is_re2_safe() -> None:
    pattern = _pattern_to_regex(("*.txt", PatternType.GLOB))

    assert "\\Z" not in pattern
    assert "\\z" not in pattern
    assert "(?s:" not in pattern
    re.compile(pattern)
    assert re.fullmatch(pattern, "a.txt")
    assert re.fullmatch(pattern, "dir/a.txt")
    assert not re.fullmatch(pattern, "a.tx")
    assert not re.fullmatch(pattern, "a.txt.bak")

    opa = _opa()
    if not opa.exists():
        pytest.skip("opa binary required for RE2 regex validation")

    expression = (
        f"[regex.match({json.dumps(pattern)}, {json.dumps('a.txt')}), "
        f"regex.match({json.dumps(pattern)}, {json.dumps('dir/a.txt')}), "
        f"regex.match({json.dumps(pattern)}, {json.dumps('a.tx')}), "
        f"regex.match({json.dumps(pattern)}, {json.dumps('a.txt.bak')})]"
    )
    completed = subprocess.run(
        [str(opa), "eval", "-f", "values", expression],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout)[0] == [True, True, False, False]


def test_glob_blocked_pattern_denies_through_generated_rego(tmp_path: Path) -> None:
    opa = _opa()
    if not opa.exists():
        pytest.skip("opa binary required for bridge Rego validation")

    manifest = governance_to_acs_manifest(
        GovernancePolicy(
            blocked_patterns=[("*.txt", PatternType.GLOB)],
            confidence_threshold=0.0,
        ),
        bundle_dir=tmp_path / "bundle",
    )
    bundle = Path(manifest["policies"]["agt_governance_policy"]["bundle"])
    input_path = tmp_path / "input.json"
    input_path.write_text(
        json.dumps({"policy_target": {"value": "a.txt"}}),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            str(opa),
            "eval",
            "-f",
            "values",
            "-d",
            str(bundle),
            "-i",
            str(input_path),
            "data.agt.governance_policy.verdict",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    verdict = json.loads(completed.stdout)[0]
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "blocked_pattern_input"


def test_non_finite_confidence_threshold_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(
        ValueError,
        match=r"confidence_threshold must be finite, got inf",
    ):
        governance_to_acs_manifest(_PolicyFixture(), bundle_dir=tmp_path / "bundle")
