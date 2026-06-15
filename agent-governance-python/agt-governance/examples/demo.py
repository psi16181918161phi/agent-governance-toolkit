# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End to end demonstration of the AGT governance pipeline.

Run with: python examples/demo.py

It wires the Identity, Lifecycle, Observability, and Sandbox standalones into one
pipeline and governs several agent actions, printing the snapshot enrichment, the
verdict, and the signed audit event for each.
"""

from __future__ import annotations

import secrets

from identity_engine import IdentityManager
from lifecycle_engine import LifecycleManager
from observability_engine import ObservabilityManager
from sandbox_engine import SandboxEngine

from agt_governance import (
    GovernancePipeline,
    MeshTransport,
    RulePolicy,
    signing_key_from_identity_hex,
)


def show(title: str, result) -> None:
    enrichment = result.snapshot["enrichment"]
    print(f"\n=== {title} ===")
    print(f"  verdict      : {result.verdict.effect}  ({result.verdict.reason})")
    print(f"  identity     : {enrichment.get('identity')}")
    print(f"  lifecycle    : {enrichment.get('lifecycle')}")
    if enrichment.get("sandbox") is not None:
        print(f"  sandbox      : {enrichment.get('sandbox')}")
    if enrichment.get("drift") is not None:
        print(f"  drift        : {enrichment.get('drift')}")
    if enrichment.get("context") is not None:
        print(f"  context      : {enrichment.get('context')}")
    print(f"  audit event  : {result.audit_event_id}  signature={result.audit_signature[:20]}...")


def main() -> None:
    identity = IdentityManager()
    lifecycle = LifecycleManager()
    observability = ObservabilityManager()
    sandbox = SandboxEngine()

    # An agent identity, and an issuer that vouches for it with a credential.
    # The caller holds the private keys; the core derives the DID and never
    # returns or serializes private material.
    agent_private_key_hex = secrets.token_hex(32)
    did = identity.generate_identity(agent_private_key_hex)["did"]
    issuer_private_key_hex = secrets.token_hex(32)
    issuer_did = identity.generate_identity(issuer_private_key_hex)["did"]
    credential = identity.issue_credential(
        "cred:agent-1", did, issuer_private_key_hex, claims={"trust_score": 820}
    )

    # Register the agent under lifecycle management, keyed by its DID, and activate it.
    lifecycle.provision("billing-bot", "team-fin@example.com", agent_id=did)
    lifecycle.approve(did)
    lifecycle.activate(did)

    # The audit signer is itself an identity.
    audit_signer_private_key_hex = secrets.token_hex(32)
    audit_key = signing_key_from_identity_hex(audit_signer_private_key_hex)

    pipeline = GovernancePipeline(
        identity=identity,
        lifecycle=lifecycle,
        observability=observability,
        sandbox=sandbox,
        audit_signing_key_b64=audit_key,
        policy=RulePolicy(denied_actions={"delete"}, min_trust_level="standard"),
        # Trust assertions are honored only from this anchored issuer, so an
        # agent cannot mint itself a high-trust credential.
        trusted_issuers={issuer_did},
    )

    print("AGT governance pipeline, composing identity + lifecycle + sandbox + observability")

    show(
        "active agent, valid credential, benign read -> ALLOW",
        pipeline.govern(did, "read", "invoices", credential=credential),
    )
    show(
        "action on the policy deny list -> DENY",
        pipeline.govern(did, "delete", "invoices", credential=credential),
    )
    show(
        "no credential presented -> DENY (identity)",
        pipeline.govern(did, "read", "invoices"),
    )
    show(
        "another agent's credential presented -> DENY (identity: subject mismatch)",
        pipeline.govern("did:mesh:" + "0" * 64, "read", "invoices", credential=credential),
    )
    show(
        "sandboxed action running a disallowed command -> DENY (sandbox)",
        pipeline.govern(
            did,
            "execute",
            "tool:shell",
            credential=credential,
            sandbox_spec={"id": "spec:1", "allowed_commands": ["python"]},
            sandbox_request={"command": "rm", "args": ["-rf", "/"]},
        ),
    )
    show(
        "output stage, drift between reference and candidate -> ALLOW with drift signal",
        pipeline.govern(
            did,
            "emit",
            "report",
            intervention_point="output",
            credential=credential,
            reference_output="revenue grew 12 percent in the second quarter",
            candidate_output="revenue collapsed 40 percent in the second quarter",
        ),
    )
    show(
        "context routing for a model call -> ALLOW with context tier",
        pipeline.govern(
            did,
            "read",
            "knowledge",
            credential=credential,
            context_query="summarize the quarterly revenue report in detail",
        ),
    )

    # Governed agent-to-agent messaging over the Mesh component.
    mesh = MeshTransport()
    a_private = secrets.token_hex(32)
    a = identity.generate_identity(a_private)
    b_private = secrets.token_hex(32)
    b = identity.generate_identity(b_private)
    mesh.register(a["did"], "https://agent-a.example", a["public_key"])
    mesh.register(b["did"], "https://agent-b.example", b["public_key"])
    sent = mesh.send(
        from_did=a["did"],
        from_private_key_hex=a_private,
        to_did=b["did"],
        kind="task",
        payload={"task": "reconcile"},
    )
    print("\n=== mesh: governed agent-to-agent message ===")
    print(f"  from {a['did'][:28]}... to {b['did'][:28]}...")
    print(
        f"  sealed message {sent['message']['id']}  verified={mesh.verify(sent['message'], a['public_key'])}"
    )
    print(f"  routing      : {sent['routing']}")

    print("\nACS is the production policy provider, wired through the mcp-governance composite.")
    print(f"fleet audit snapshot: {observability.audit_snapshot()['valid']=}")


if __name__ == "__main__":
    main()
