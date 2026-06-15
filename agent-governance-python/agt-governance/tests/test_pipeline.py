# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End to end tests for the AGT governance pipeline.

These exercise the real Identity, Lifecycle, Observability, and Sandbox
standalones composed through the pipeline. They are evidence that the components
interact correctly through the contracts.
"""

from __future__ import annotations

import base64
import secrets

import pytest
from identity_engine import IdentityManager
from lifecycle_engine import LifecycleManager
from observability_engine import ObservabilityManager
from sandbox_engine import SandboxEngine

from agt_governance import (
    GovernancePipeline,
    ObservabilityAuditSink,
    RulePolicy,
    Verdict,
    signing_key_from_identity_hex,
)


@pytest.fixture()
def env():
    identity = IdentityManager()
    lifecycle = LifecycleManager()
    observability = ObservabilityManager()
    sandbox = SandboxEngine()

    # The caller holds the private keys; the core derives the DID and never
    # returns private material.
    agent_priv = secrets.token_hex(32)
    did = identity.generate_identity(agent_priv)["did"]
    issuer_priv = secrets.token_hex(32)
    issuer_did = identity.generate_identity(issuer_priv)["did"]
    credential = identity.issue_credential(
        "cred:1", did, issuer_priv, claims={"trust_score": 820}
    )

    lifecycle.provision("bot", "owner@example.com", agent_id=did)
    lifecycle.approve(did)
    lifecycle.activate(did)

    signer_priv = secrets.token_hex(32)
    audit_key = signing_key_from_identity_hex(signer_priv)
    signer_pub_b64 = base64.b64encode(
        bytes.fromhex(identity.generate_identity(signer_priv)["public_key"])
    ).decode("ascii")

    pipeline = GovernancePipeline(
        identity=identity,
        lifecycle=lifecycle,
        observability=observability,
        sandbox=sandbox,
        audit_signing_key_b64=audit_key,
        policy=RulePolicy(denied_actions={"delete"}, min_trust_level="standard"),
        trusted_issuers={issuer_did},
    )
    return {
        "identity": identity,
        "lifecycle": lifecycle,
        "observability": observability,
        "pipeline": pipeline,
        "did": did,
        "credential": credential,
        "issuer_priv": issuer_priv,
        "issuer_did": issuer_did,
        "audit_key": audit_key,
        "signer_priv": signer_priv,
        "signer_pub_b64": signer_pub_b64,
    }


def test_active_agent_valid_credential_allows(env):
    result = env["pipeline"].govern(env["did"], "read", "invoices", credential=env["credential"])
    assert result.allowed
    assert result.verdict.effect == "allow"
    assert result.snapshot["enrichment"]["identity"]["verified"] is True
    assert result.snapshot["enrichment"]["lifecycle"]["is_active"] is True
    assert result.snapshot["enrichment"]["identity"]["trust_level"] == "trusted"


def test_denied_action_is_blocked_by_policy(env):
    result = env["pipeline"].govern(env["did"], "delete", "invoices", credential=env["credential"])
    assert not result.allowed
    assert "denied by policy" in result.verdict.reason


def test_missing_credential_denies_on_identity(env):
    result = env["pipeline"].govern(env["did"], "read", "invoices")
    assert not result.allowed
    assert "not verified" in result.verdict.reason


def test_unknown_agent_denies_on_lifecycle(env):
    # A fresh agent with an anchored, subject-bound credential passes identity,
    # but is not provisioned in lifecycle, so it is denied there.
    identity = env["identity"]
    stranger_priv = secrets.token_hex(32)
    stranger = identity.generate_identity(stranger_priv)["did"]
    stranger_cred = identity.issue_credential(
        "cred:stranger", stranger, env["issuer_priv"], claims={"trust_score": 820}
    )
    result = env["pipeline"].govern(stranger, "read", "invoices", credential=stranger_cred)
    assert not result.allowed
    assert "not active" in result.verdict.reason


def test_sandbox_violation_denies(env):
    result = env["pipeline"].govern(
        env["did"],
        "execute",
        "tool:shell",
        credential=env["credential"],
        sandbox_spec={"id": "spec:1", "allowed_commands": ["python"]},
        sandbox_request={"command": "rm", "args": ["-rf", "/"]},
    )
    assert not result.allowed
    assert result.snapshot["enrichment"]["sandbox"]["allowed"] is False


def test_audit_event_is_signed_and_verifiable(env):
    # The audit sink signs each decision as a governance event. Verify the
    # signature with the audit signer public key through Observability.
    sink = ObservabilityAuditSink(env["observability"], env["audit_key"])
    snapshot = {
        "intervention_point": "pre_tool_call",
        "agent": {"agent_id": env["did"]},
        "target": {"action": "read", "resource": "invoices"},
        "enrichment": {},
    }
    audit = sink.record(snapshot, Verdict("allow", "ok"))
    assert audit["event_id"].startswith("evt:")
    assert (
        env["observability"].verify_event(audit["event"], env["signer_pub_b64"], audit["signature"])
        is True
    )


def test_audit_signer_did_is_bound_to_the_signing_key(env):
    # The recorded signer_did must be the DID derived from the signing key, not
    # a free-form label, so a verifier resolving it gets the actual signer key.
    from agt_governance import signer_did_from_signing_key

    sink = ObservabilityAuditSink(env["observability"], env["audit_key"])
    audit = sink.record(
        {
            "intervention_point": "pre_tool_call",
            "agent": {"agent_id": env["did"]},
            "target": {"action": "read", "resource": "x"},
            "enrichment": {},
        },
        Verdict("allow", "ok"),
    )
    expected = env["identity"].generate_identity(env["signer_priv"])["did"]
    assert audit["signer_did"] == expected
    assert audit["signer_did"] == signer_did_from_signing_key(env["audit_key"])
    assert audit["event"]["attributes"]["signer_did"] == expected


def test_credential_for_another_subject_is_rejected(env):
    # A1: an active agent presenting a valid credential issued to a different
    # subject must not be verified as itself.
    identity = env["identity"]
    attacker_priv = secrets.token_hex(32)
    attacker = identity.generate_identity(attacker_priv)["did"]
    env["lifecycle"].provision("attacker", "owner@example.com", agent_id=attacker)
    env["lifecycle"].approve(attacker)
    env["lifecycle"].activate(attacker)
    # env["credential"] was issued to env["did"], not to the attacker.
    result = env["pipeline"].govern(attacker, "read", "invoices", credential=env["credential"])
    assert not result.allowed
    assert result.snapshot["enrichment"]["identity"]["verified"] is False
    assert result.snapshot["enrichment"]["identity"]["credential_status"] == "subject_mismatch"


def test_self_issued_trust_is_not_honored(env):
    # The deepest form of A1: an agent self-issues itself a max-trust credential.
    # Identity is proven (its own credential), but trust is not honored because
    # the self-issuer is not anchored.
    identity = env["identity"]
    rogue_priv = secrets.token_hex(32)
    rogue = identity.generate_identity(rogue_priv)["did"]
    self_cred = identity.issue_credential(
        "cred:self", rogue, rogue_priv, claims={"trust_score": 1000}
    )
    env["lifecycle"].provision("rogue", "owner@example.com", agent_id=rogue)
    env["lifecycle"].approve(rogue)
    env["lifecycle"].activate(rogue)
    result = env["pipeline"].govern(rogue, "read", "invoices", credential=self_cred)
    assert not result.allowed
    assert result.snapshot["enrichment"]["identity"]["verified"] is True
    assert result.snapshot["enrichment"]["identity"]["trust_level"] == "untrusted"


def test_claimless_credential_is_untrusted(env):
    # An empty-claims credential carries no trust assertion; it must not default
    # to a trusted level.
    identity = env["identity"]
    result = _govern_with_claims(env, identity, {})
    assert result.snapshot["enrichment"]["identity"]["trust_level"] == "untrusted"
    assert not result.allowed


def test_garbage_trust_score_is_untrusted(env):
    # A non-integer / out-of-range score the core rejects must not upgrade trust.
    identity = env["identity"]
    result = _govern_with_claims(env, identity, {"trust_score": "not-an-int"})
    assert result.snapshot["enrichment"]["identity"]["trust_level"] == "untrusted"
    result2 = _govern_with_claims(env, identity, {"trust_score": 99999})
    assert result2.snapshot["enrichment"]["identity"]["trust_level"] == "untrusted"


def _govern_with_claims(env, identity, claims):
    holder_priv = secrets.token_hex(32)
    holder = identity.generate_identity(holder_priv)["did"]
    cred = identity.issue_credential("cred:c", holder, env["issuer_priv"], claims=claims)
    env["lifecycle"].provision("h", "owner@example.com", agent_id=holder)
    env["lifecycle"].approve(holder)
    env["lifecycle"].activate(holder)
    return env["pipeline"].govern(holder, "read", "invoices", credential=cred)


def test_non_dict_credential_denies_without_crashing(env):
    # A malformed (non-dict) credential is a deny, never an exception.
    result = env["pipeline"].govern(env["did"], "read", "invoices", credential="not-a-dict")
    assert not result.allowed
    assert result.snapshot["enrichment"]["identity"]["credential_status"] == "malformed"
    assert result.snapshot["enrichment"]["identity"]["verified"] is False


def test_sandbox_request_without_engine_fails_closed():
    # Sandbox parameters passed to a pipeline built without a SandboxEngine must
    # fail closed, not be silently ignored.
    identity = IdentityManager()
    lifecycle = LifecycleManager()
    observability = ObservabilityManager()
    issuer_priv = secrets.token_hex(32)
    issuer_did = identity.generate_identity(issuer_priv)["did"]
    holder_priv = secrets.token_hex(32)
    holder = identity.generate_identity(holder_priv)["did"]
    cred = identity.issue_credential("c", holder, issuer_priv, claims={"trust_score": 900})
    lifecycle.provision("h", "owner@example.com", agent_id=holder)
    lifecycle.approve(holder)
    lifecycle.activate(holder)
    pipeline = GovernancePipeline(
        identity=identity,
        lifecycle=lifecycle,
        observability=observability,
        audit_signing_key_b64=signing_key_from_identity_hex(secrets.token_hex(32)),
        trusted_issuers={issuer_did},
    )  # NOTE: no sandbox engine
    result = pipeline.govern(
        holder,
        "execute",
        "tool:shell",
        credential=cred,
        sandbox_spec={"id": "spec:1", "allowed_commands": ["python"]},
        sandbox_request={"command": "rm", "args": ["-rf", "/"]},
    )
    assert not result.allowed
    assert result.snapshot["enrichment"]["sandbox"]["violations"] == ["sandbox_not_enforced"]


def test_invalid_min_trust_level_is_rejected():
    with pytest.raises(ValueError):
        RulePolicy(min_trust_level="verified-partner")  # hyphen typo


def test_drift_threshold_denies_high_drift(env):
    # With a drift ceiling configured, an output that drifts past it is denied.
    policy = RulePolicy(min_trust_level="standard", max_drift_score=0.1)
    pipeline = GovernancePipeline(
        identity=env["identity"],
        lifecycle=env["lifecycle"],
        observability=env["observability"],
        audit_signing_key_b64=env["audit_key"],
        policy=policy,
        trusted_issuers={env["issuer_did"]},
    )
    result = pipeline.govern(
        env["did"],
        "emit",
        "output",
        intervention_point="output",
        credential=env["credential"],
        reference_output="def add(a, b): return a + b",
        candidate_output="totally different unrelated text that drifts a lot",
    )
    drift = result.snapshot["enrichment"]["drift"]
    # These inputs score ~0.38 drift, well above the 0.1 ceiling, so the
    # decision must be a drift deny.
    assert drift["score"] > 0.1
    assert not result.allowed
    assert "drift" in result.verdict.reason


def test_drift_enrichment_scores_output(env):
    result = env["pipeline"].govern(
        env["did"],
        "emit",
        "output",
        intervention_point="output",
        credential=env["credential"],
        reference_output="def add(a, b): return a + b",
        candidate_output="def add(x, y): return x * y",
    )
    drift = result.snapshot["enrichment"]["drift"]
    assert isinstance(drift["score"], float)
    assert 0.0 <= drift["score"] <= 1.0


def test_context_enrichment_routes_query(env):
    result = env["pipeline"].govern(
        env["did"],
        "read",
        "knowledge",
        credential=env["credential"],
        context_query="summarize the quarterly revenue report in detail",
    )
    context = result.snapshot["enrichment"]["context"]
    assert context["tier"] is not None
    assert context["suggested_model"]


def test_mesh_transport_round_trip(env):
    import secrets

    from agt_governance import MeshTransport

    identity = env["identity"]
    mesh = MeshTransport()
    a_priv = secrets.token_hex(32)
    a = identity.generate_identity(a_priv)
    b_priv = secrets.token_hex(32)
    b = identity.generate_identity(b_priv)
    mesh.register(a["did"], "http://a", a["public_key"])
    mesh.register(b["did"], "http://b", b["public_key"])

    sent = mesh.send(
        from_did=a["did"],
        from_private_key_hex=a_priv,
        to_did=b["did"],
        kind="greeting",
        payload={"hello": "world"},
    )
    assert mesh.verify(sent["message"], a["public_key"]) is True
    assert sent["routing"]["status"] == "deliverable"
    # A tampered message fails verification.
    tampered = dict(sent["message"])
    tampered["payload"] = {"hello": "tampered"}
    assert mesh.verify(tampered, a["public_key"]) is False
