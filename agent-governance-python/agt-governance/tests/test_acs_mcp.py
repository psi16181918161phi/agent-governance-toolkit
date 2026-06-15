# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Wiring test for ACS and the mcp-governance composite in the AGT host.

These prove that the ACS standalone and the mcp-governance composite are
reachable and usable from AGT host code. They reuse the proven live-ACS path of
the mcp-governance composite, which itself wires ACS, Identity, and
Observability. The tests skip when the optional ``acs`` extra is not installed,
since the ACS runtime is a heavier dependency.
"""

from __future__ import annotations

import base64
import secrets

import pytest

pytest.importorskip("mcp_governance")
pytest.importorskip("agent_control_specification")

from identity_engine import IdentityManager  # noqa: E402
from mcp_governance import AcsPolicy, MCPGovernor, ToolCallRequest  # noqa: E402
from observability_engine import ObservabilityManager  # noqa: E402

ACS_MANIFEST = """agent_control_specification_version: 0.3.1-beta
metadata:
  name: agt-governance-acs
policies:
  mcp_policy:
    type: custom
    adapter: agt_governance
intervention_points:
  pre_tool_call:
    policy_target_kind: tool_args
    policy:
      id: mcp_policy
    policy_target: $.mcp.target
"""


class ToolNameAcsDispatcher:
    """A custom ACS policy dispatcher that blocks one tool name."""

    def evaluate(self, invocation):
        if "blocked_tool" in repr(invocation):
            return {"decision": "deny", "reason": "blocked_by_live_acs"}
        return {"decision": "allow", "reason": "allowed_by_live_acs"}


def _governor(policy):
    identity = IdentityManager()
    observability = ObservabilityManager()
    grantor_seed = secrets.token_hex(32)
    caller_seed = secrets.token_hex(32)
    grantor = identity.generate_identity(grantor_seed)
    caller = identity.generate_identity(caller_seed)
    grant = identity.issue_capability(
        "grant:allowed-tool",
        "call:*",
        caller["did"],
        grantor["did"],
        grantor_seed,
        resource_ids=["tool:allowed_tool"],
        conditions={"trust_score": 900},
    )
    audit_key = base64.b64encode(bytes.fromhex(secrets.token_hex(32))).decode("ascii")
    governor = MCPGovernor(
        identity=identity,
        observability=observability,
        policy=policy,
        audit_signing_key_b64=audit_key,
    )
    return governor, caller, grantor, grant


def test_acs_policy_allows_through_mcp_governance():
    policy = AcsPolicy(ACS_MANIFEST, policy_dispatcher=ToolNameAcsDispatcher())
    governor, caller, grantor, grant = _governor(policy)
    decision = governor.evaluate(
        ToolCallRequest(
            caller_did=caller["did"],
            tool_name="allowed_tool",
            capability_grant=grant,
            grantor_public_key_hex=grantor["public_key"],
        )
    )
    assert decision.verdict.effect == "allow"
    assert decision.verdict.metadata["acs_decision"] == "allow"


def test_acs_policy_denies_through_mcp_governance():
    policy = AcsPolicy(ACS_MANIFEST, policy_dispatcher=ToolNameAcsDispatcher())
    governor, caller, grantor, grant = _governor(policy)
    decision = governor.evaluate(
        ToolCallRequest(
            caller_did=caller["did"],
            tool_name="allowed_tool",
            args={"requested_tool": "blocked_tool"},
            capability_grant=grant,
            grantor_public_key_hex=grantor["public_key"],
        )
    )
    assert decision.verdict.effect == "deny"
    assert decision.verdict.metadata["acs_decision"] == "deny"


def test_acs_policy_is_a_drop_in_pipeline_policy():
    # ACS is reachable not only through the mcp-governance MCPGovernor, but also
    # as a PolicyPort for the AGT GovernancePipeline: AcsPolicy.decide(snapshot)
    # consumes the pipeline snapshot directly. This proves the production policy
    # path is wired end to end, not just advertised.
    from agt_governance import GovernancePipeline, signing_key_from_identity_hex
    from lifecycle_engine import LifecycleManager

    class ResourceAcsDispatcher:
        def evaluate(self, invocation):
            if "payroll" in repr(invocation):
                return {"decision": "deny", "reason": "blocked_by_live_acs"}
            return {"decision": "allow", "reason": "allowed_by_live_acs"}

    identity = IdentityManager()
    lifecycle = LifecycleManager()
    observability = ObservabilityManager()
    issuer_seed = secrets.token_hex(32)
    issuer_did = identity.generate_identity(issuer_seed)["did"]
    did = identity.generate_identity(secrets.token_hex(32))["did"]
    credential = identity.issue_credential("c", did, issuer_seed, claims={"trust_score": 900})
    lifecycle.provision("bot", "owner@example.com", agent_id=did)
    lifecycle.approve(did)
    lifecycle.activate(did)

    pipeline = GovernancePipeline(
        identity=identity,
        lifecycle=lifecycle,
        observability=observability,
        audit_signing_key_b64=signing_key_from_identity_hex(secrets.token_hex(32)),
        policy=AcsPolicy(ACS_MANIFEST, policy_dispatcher=ResourceAcsDispatcher()),
        trusted_issuers={issuer_did},
    )

    allowed = pipeline.govern(did, "read", "invoices", credential=credential)
    assert allowed.allowed is True
    denied = pipeline.govern(did, "read", "payroll", credential=credential)
    assert denied.allowed is False
    assert "acs" in denied.verdict.reason
