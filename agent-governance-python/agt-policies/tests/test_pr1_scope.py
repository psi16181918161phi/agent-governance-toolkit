# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for fail-closed scope containment errors."""

from __future__ import annotations

from pathlib import Path

import pytest

from agt.manifest_resolution import ResolutionError, ResolutionReason, filter_by_scope


def test_filter_by_scope_rejects_action_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    action = tmp_path / "outside" / "main.py"
    action.parent.mkdir()
    action.write_text("# code\n", encoding="utf-8")

    with pytest.raises(ResolutionError) as exc_info:
        filter_by_scope(root / "governance.yaml", "**/*.py", action, root)

    assert exc_info.value.reason == ResolutionReason.PATH_TRAVERSAL
