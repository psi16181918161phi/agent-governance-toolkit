# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

from agt.manifest_resolution import merge_documents


def test_parent_deny_empty_or_drops_child_allow() -> None:
    merged = merge_documents(
        [
            {
                "rules": [
                    {
                        "name": "org-deny",
                        "action": "deny",
                        "condition": {"or": []},
                        "priority": 100,
                    }
                ]
            },
            {
                "rules": [
                    {
                        "name": "child-allow",
                        "action": "allow",
                        "condition": {
                            "field": "tool",
                            "operator": "eq",
                            "value": "shell",
                        },
                        "priority": 1,
                    }
                ]
            },
        ]
    )

    assert [rule["name"] for rule in merged] == ["org-deny"]


def test_parent_deny_unrecognized_condition_shape_drops_child_allow() -> None:
    merged = merge_documents(
        [
            {
                "rules": [
                    {
                        "name": "org-deny",
                        "action": "deny",
                        "condition": {"unknown": "shape"},
                        "priority": 100,
                    }
                ]
            },
            {
                "rules": [
                    {
                        "name": "child-allow",
                        "action": "allow",
                        "condition": {
                            "field": "tool",
                            "operator": "eq",
                            "value": "shell",
                        },
                        "priority": 1,
                    }
                ]
            },
        ]
    )

    assert [rule["name"] for rule in merged] == ["org-deny"]


def test_parent_deny_provably_disjoint_from_child_allow_keeps_child() -> None:
    merged = merge_documents(
        [
            {
                "rules": [
                    {
                        "name": "org-deny",
                        "action": "deny",
                        "condition": {
                            "field": "tool",
                            "operator": "eq",
                            "value": "delete",
                        },
                        "priority": 100,
                    }
                ]
            },
            {
                "rules": [
                    {
                        "name": "child-allow",
                        "action": "allow",
                        "condition": {
                            "field": "tool",
                            "operator": "eq",
                            "value": "shell",
                        },
                        "priority": 1,
                    }
                ]
            },
        ]
    )

    assert [rule["name"] for rule in merged] == ["org-deny", "child-allow"]
