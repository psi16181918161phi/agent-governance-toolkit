# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for chain-root-local v4 governance backups."""

from __future__ import annotations

from pathlib import Path

import yaml

from agt.cli import migrate as migrate_mod


def _write_governance(path: Path, rule_name: str) -> None:
    doc = {
        "rules": [
            {
                "name": rule_name,
                "condition": {
                    "field": "tool_call.name",
                    "operator": "eq",
                    "value": "rm",
                },
                "action": "deny",
                "priority": 10,
                "message": "rm is blocked",
            }
        ],
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    }
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def test_write_migration_backs_up_only_chain_root_local_governance(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "workspace"
    chain_root = project_root / "service"
    chain_root.mkdir(parents=True)
    parent_governance = project_root / "governance.yaml"
    local_governance = chain_root / "governance.yaml"
    _write_governance(parent_governance, "deny_parent")
    _write_governance(local_governance, "deny_local")
    parent_original = parent_governance.read_text(encoding="utf-8")

    finding = migrate_mod._migrate_governance_chain(
        chain_root,
        project_root,
        write=True,
    )

    assert finding.error is None
    assert parent_governance.is_file()
    assert parent_governance.read_text(encoding="utf-8") == parent_original
    assert not (project_root / ".governance.yaml.v4-backup").exists()
    assert not local_governance.exists()
    assert (chain_root / ".governance.yaml.v4-backup").is_file()
    assert finding.backups == [chain_root / ".governance.yaml.v4-backup"]
