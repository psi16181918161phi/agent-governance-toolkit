# agt-governance

The AGT host wiring for the standalone governance components. This is the bridge
layer that re-imports the standalones as ordinary published dependencies and
composes them into one governance pipeline through the governance contracts.

```
                       GovernancePipeline.govern(agent, action)
                                       |
   build snapshot ---> enrichers ---> policy ---> enforce ---> audit sink
                         |  |  |         |                        |
                  Identity Lifecycle Sandbox     (ACS or RulePolicy)  Observability
```

Each component stays independent. The pipeline wires them only through the
snapshot, the enrichment namespace, and the ports defined in
`governance-contracts/`. A minimal deployment runs the pipeline with a built in
`RulePolicy`. The production policy provider is the ACS standalone, injected as a
`PolicyPort`.

## What it composes

- **Identity** verifies a presented credential and projects the verified DID,
  credential status, and trust level into `enrichment.identity`. The credential
  subject must equal the governed agent (so an agent cannot present another
  agent's credential), and a credential's trust score is honored only from an
  issuer the host anchors via `trusted_issuers` (so an agent cannot mint itself
  high trust).
- **Lifecycle** projects the agent state into `enrichment.lifecycle`.
- **Sandbox** evaluates an execution request into `enrichment.sandbox`.
- **Drift** scores a candidate output against a reference into `enrichment.drift`.
- **Context** routes a query into a model tier into `enrichment.context`.
- **Policy** decides a verdict over the enriched snapshot. The production
  provider is **ACS**, reached through the **mcp-governance** composite.
- **Observability** records the decision as a signed governance event. The
  signer DID is derived from the signing key, and the Ed25519 signature covers
  the decision body, so a recorded decision is attributable and tamper-evident.
  Events are also hash-chained over their metadata for ordering.
- **Mesh** carries governed agent-to-agent messages, sealed with Identity keys
  and addressed by `did:mesh`. Transport is exposed through `MeshTransport`.

Every standalone component is reachable from this one AGT host package.

## Usage

```python
from identity_engine import IdentityManager
from lifecycle_engine import LifecycleManager
from observability_engine import ObservabilityManager
from sandbox_engine import SandboxEngine
from agt_governance import GovernancePipeline, RulePolicy, signing_key_from_identity_hex

pipeline = GovernancePipeline(
    identity=IdentityManager(),
    lifecycle=LifecycleManager(),
    observability=ObservabilityManager(),
    sandbox=SandboxEngine(),
    audit_signing_key_b64=signing_key_from_identity_hex(signer_private_key_hex),
    policy=RulePolicy(denied_actions={"delete"}),
)
result = pipeline.govern(agent_did, "read", "invoices", credential=credential)
assert result.allowed
```

## Develop

```sh
cd agent-governance-python/agt-governance
python -m venv .venv && . .venv/bin/activate
pip install ../../identity-engine/sdk/python ../../lifecycle-engine/sdk/python \
            ../../observability-engine/sdk/python ../../sandbox-engine/sdk/python
pip install -e ".[dev]"
python examples/demo.py
pytest
```

This package is additive AGT host code. It does not modify the standalone
components or the rest of AGT.
