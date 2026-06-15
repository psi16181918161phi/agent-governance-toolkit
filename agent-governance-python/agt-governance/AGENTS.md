# AGENTS.md

## Overview

`agt-governance` is the AGT host wiring for the standalone governance components.
It re-imports the Identity, Lifecycle, Observability, and Sandbox standalones as
ordinary published dependencies and composes them into one `GovernancePipeline`
through the governance contracts. This is the bridge layer, the AGT side of the
standalone donation.

## Layout

| Path | Purpose |
| --- | --- |
| `src/agt_governance/ports.py` | The capability ports as Python protocols (Enricher, PolicyPort, Sink) and the Verdict type. |
| `src/agt_governance/enrichers.py` | IdentityEnricher, LifecycleEnricher, SandboxEnricher. Each writes one reserved snapshot key. |
| `src/agt_governance/policy.py` | RulePolicy, the dependency-light default PolicyPort. ACS is the production provider. |
| `src/agt_governance/sinks.py` | ObservabilityAuditSink. Signs a decision as a governance event and emits it. |
| `src/agt_governance/pipeline.py` | GovernancePipeline, the adapter host realized. |

## Rules

- This package is additive AGT host code. It depends on the standalones through
  their published surfaces and the contracts. It does not modify the standalones
  or the rest of AGT.
- An enricher writes only its reserved key in `snapshot["enrichment"]` and does
  not read another enricher's key. Enrichers stay order independent.
- The policy reads the enrichment as opaque input. Recording the decision is the
  sink's job. Keep these responsibilities separate.
- Private key material is never logged or serialized.

## Validation

```sh
pip install ../../identity-engine/sdk/python ../../lifecycle-engine/sdk/python \
            ../../observability-engine/sdk/python ../../sandbox-engine/sdk/python
pip install -e ".[dev]"
python examples/demo.py
pytest
ruff check --select E,F,W --ignore E501 src tests examples
```
