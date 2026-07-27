# Aegis Security

Aegis is an evidence-first security extension for Visual Studio Code.

It combines deterministic security scanners, AI-assisted review,
secure patch generation, project verification, and explicitly
authorized dynamic replay.

## Requirements

The local Aegis backend must be available at the configured
`aegis.backendUrl`. The default address is:

    http://127.0.0.1:8000

For complete documentation, source code, security policy, and
contribution guidance, see the Aegis repository.

## Trusted Analysis

Run `Aegis: Run Trusted Analysis` from the Command Palette while
a local source file is open. The command executes the production
security-task graph and opens one report containing:

- deterministic scanner coverage
- primary and verifier model provenance
- consensus-backed claims
- a composed threat model
- immutable project security memory
- the final allow, review, or block policy decision
- append-only execution audit metadata
- verified source, plan, audit, and artifact-manifest hashes

Partial scanner or consensus coverage is reported as incomplete
and is never persisted as a clean project baseline.
The extension also checks that the returned source hash matches
the saved file before displaying a trusted result.
