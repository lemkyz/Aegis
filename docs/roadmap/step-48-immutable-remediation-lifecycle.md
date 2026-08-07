# Step 48 — Immutable Remediation Lifecycle

Status: Complete

## Objective

Close the Fix-and-Prove lifecycle with immutable, cryptographically bound
remediation provenance that survives verification, transaction closure,
evidence-graph conversion, restart-safe persistence, and project-memory
snapshotting without mutating the original authorized manifest.

## Completed contracts

- The authorized/applied pending remediation is recorded as an immutable
  `RemediationLifecycleManifest`.
- Static fix verification is bound to the exact manifest and applied patch.
- Dynamic validation preserves the exact manifest identity and static
  verification digest.
- Terminal remediation is recorded separately as an immutable
  `RemediationLifecycleOutcome`.
- The outcome binds manifest identity, static verification, dynamic validation,
  unified verdict, terminal transaction state, and residual risk.
- Pending manifests and terminal outcomes are stored in an immutable SQLite
  remediation lifecycle ledger.
- Persistence is idempotent for identical content and fails closed on identity
  collisions, tampering, unsupported schema metadata, orphan outcomes, partial
  lifecycle corruption, or a second terminal truth for the same manifest.
- Lifecycle snapshot identity is deterministic across reloads.
- Security memory accepts `remediation_lifecycle_outcome` as explicit
  provenance only when it is named and supplied consistently.
- A manifest-aware dynamic artifact cannot update the evidence graph without
  the exact matching immutable lifecycle outcome.
- Memory rejects mismatches in manifest identity, manifest digest, static
  verification digest, dynamic artifact digest, unified verdict, terminal
  state, or residual risk.
- The lifecycle outcome becomes first-class deterministic evidence in the
  claim graph and is linked by a `derived_from` provenance relationship to the
  unified fix-verification evidence.
- Only a `committed` terminal lifecycle outcome may contribute to a
  `verified_fixed` transition. Rolled-back and rollback-blocked outcomes remain
  auditable evidence but cannot be remembered as successful remediation.
- The resulting evidence graph is persisted through the existing deterministic
  project-security snapshot machinery.

## Final lifecycle

```text
plan
→ approval
→ patch
→ pending immutable manifest
→ static verification
→ dynamic replay
→ unified verdict
→ commit / rollback
→ immutable outcome
→ evidence graph
→ deterministic security snapshot
→ durable persistence
```

The pending manifest remains immutable throughout. Terminal truth is represented
only by the separate outcome record.

## Validation

- Focused: `148 passed in 0.71s`
- Full backend: `909 passed, 1 warning in 10.79s`
- `git diff --check` passed before the implementation commit.
- Production and test modules compiled successfully.
- Credential-pattern checks passed.
- Step 48 implementation HEAD before this seal: `6fa13d93b877c32a3dde6eb7f958bbe12c3aa880`.

## Result

Aegis no longer treats a generated patch, a successful static check, or even a
successful dynamic replay as sufficient proof by itself. The complete
remediation decision is now a durable evidence chain whose authorization,
patch identity, verification results, terminal transaction state, residual
risk, lifecycle ledger records, evidence graph, and project-memory snapshot are
cryptographically and semantically bound.

This completes the Fix-and-Prove macro phase.

## Next macro phase

Attack Graph / Data Sentinel.
