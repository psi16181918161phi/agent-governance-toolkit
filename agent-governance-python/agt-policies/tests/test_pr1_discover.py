# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for fail-closed governance discovery errors."""

from __future__ import annotations

from pathlib import Path

import pytest

from agt.manifest_resolution import ResolutionError, ResolutionReason, discover_policies


def test_discover_wraps_resolve_oserror(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path
    action = root / "main.py"
    action.write_text("# code\n", encoding="utf-8")
    original_resolve = Path.resolve

    def flaky_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self == action:
            raise OSError("simulated resolve failure")
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", flaky_resolve)

    with pytest.raises(ResolutionError) as exc_info:
        discover_policies(action, root)

    assert exc_info.value.reason == ResolutionReason.PATH_TRAVERSAL


def test_discover_rejects_nonexistent_action_path(tmp_path: Path) -> None:
    root = tmp_path
    (root / "governance.yaml").write_text("rules: []\n", encoding="utf-8")
    missing_action = root / "missing" / "action.py"

    with pytest.raises(ResolutionError) as exc_info:
        discover_policies(missing_action, root)

    assert exc_info.value.reason == ResolutionReason.PATH_TRAVERSAL
