# Step 47 — Evidence Graph Integrity

Status: Complete

## Objective

Extend verified remediation into a deterministic, structurally valid,
semantically consistent, provenance-safe evidence graph whose relationships
remain material across reconciliation, snapshot identity, and durable SQLite
storage.

## Completed contracts

- Unified fix-verification evidence creates a deterministic `verifies`
  relationship to the authorized dynamic replay result.
- A verified fix creates deterministic `mitigates` relationships from
  verification evidence to every original vulnerability evidence item.
- Mitigation edges are emitted only after exact verification, replay, patch,
  and residual-risk gates pass.
- Reapplying the same verification workflow is relationship-idempotent.
- Relationship changes are material to claim reconciliation and project
  snapshot identity.
- Relationship identifiers are unique within a claim.
- Duplicate semantic edges are rejected by exact directed
  `(source_evidence_id, target_evidence_id, kind)` identity.
- Self-referential relationships are rejected.
- Reverse-direction relationships remain distinct directed edges.
- A directed evidence pair may contain only one epistemic relationship kind
  from `supports`, `corroborates`, `contradicts`, and `verifies`.
- Independent `derived_from` and `mitigates` dimensions may coexist with an
  epistemic edge on the same directed evidence pair.
- The `derived_from` provenance subgraph is acyclic and rejects direct and
  transitive cycles.
- Relationship ordering is semantically irrelevant.
- Full material relationship identity consists of:
  - `relationship_id`;
  - `source_evidence_id`;
  - `target_evidence_id`;
  - `kind`;
  - `reason`.
- Full relationship identity is preserved consistently by:
  - claim reconciliation;
  - deterministic project snapshot hashing;
  - SQLite snapshot collision detection.
- SQLite persistence remains idempotent for reordered but otherwise identical
  relationships.
- SQLite persistence fails closed when the same `snapshot_id` is presented
  with materially different relationship content.
- Existing stored snapshots are not overwritten after a collision attempt.

## Evidence

Final backend validation:

- 835 tests passed.
- 1 existing Starlette `httpx` deprecation warning.
- No test failures.
- 95 focused evidence-graph, identity, and persistence tests passed.
- `git diff --check` passed.
- Python compile checks passed for changed production and test modules.
- Secret-pattern checks passed before every Step 47 commit.

## Step 47 commits

- `1b5ace5` — link fix verification to dynamic replay
- `1246ec3` — link verified fixes to original evidence
- `2db8b65` — reconcile relationship graph changes
- `0a41c9c` — enforce structural graph integrity
- `02d1cc8` — enforce epistemic graph consistency
- `2f77305` — reject cyclic provenance graphs
- `61ff8cd` — preserve full relationship identity
- `1d0adc2` — enforce SQLite relationship identity

## Result

Aegis now treats evidence relationships as first-class, immutable security
facts rather than decorative links. Invalid graph structure, contradictory
epistemic roles, cyclic provenance, material identity drift, and persistent
storage collisions all fail closed. Verified remediation can therefore be
remembered as a deterministic evidence graph whose meaning survives workflow
replay, reconciliation, snapshot hashing, and durable storage.
