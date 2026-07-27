<div align="center">

# Aegis

**Detect. Reproduce. Patch. Replay. Prove.**

Security verification for VS Code.

A finding is not fixed because the warning disappeared.

</div>

---

Aegis follows a vulnerability from the first piece of evidence to the final verification result.

It analyzes the code, records why a finding exists, runs explicitly authorized validation inside an isolated local container, applies a reviewable patch, checks the project, rescans the result, and replays the original validation.

The result is not a vague success message.

It is one of three states:

- **VERIFIED** — the evidence supports the fix
- **PARTIAL** — the static result improved, but complete proof is missing
- **FAILED** — the issue remains, the patch broke the project, or a regression appeared

## The problem

Most secure coding workflows end too early.

A scanner reports a dangerous pattern.

A patch removes the pattern.

The warning disappears.
Everyone moves on.

But the original behavior may still be exploitable.

Aegis treats detection, patching, and verification as separate stages. It does not let one stage silently prove another.

```text
detect
  ↓
collect evidence
  ↓
authorize validation
  ↓
reproduce in isolation
  ↓
apply a reviewable patch
  ↓
run project checks
  ↓
rescan
  ↓
replay the same validation
  ↓
prove the result
```

## What makes it different

| Conventional workflow | Aegis |
|---|---|
| Reports a suspicious pattern | Records the finding and supporting evidence |
| Suggests a replacement | Produces a reviewable patch |
| Stops when the edit is applied | Runs syntax, tests, and build checks |
| Assumes the warning disappearing means success | Rescans the patched code |
| Tests something different after the patch | Replays the authorized baseline |
| Returns a generic success state | Returns an evidence-based verdict |

## Verification states

### `VERIFIED`

Aegis uses this state only when:

- configured project checks passed
- the target finding disappeared
- no new static regression was introduced
- a previously confirmed dynamic baseline no longer reproduces

### `PARTIAL`

The patch passed the available static and project checks, but complete dynamic proof was unavailable or inconclusive.

Partial is intentionally not presented as verified.

### `FAILED`

The patch failed verification because at least one of the following occurred:

- project checks failed
- the original finding remained
- a new regression appeared
- the authorized validation still reproduced
- execution failed in a way that prevents a trustworthy conclusion

## Current capabilities

- source and workspace analysis
- Git change scanning
- scanner evidence correlation
- dependency vulnerability detection
- attack-surface mapping
- threat modeling
- exploitability classification
- reviewable secure patches
- syntax, test, and build verification
- static before-and-after comparison
- exact patch-digest approval and stale-file rejection
- atomic secure-fix writes with guarded rollback
- explicit validation authorization
- isolated Podman or Docker execution
- read-only repository mounts
- disabled or loopback-only networking
- dynamic evidence evaluation
- before-and-after validation replay
- unified fix-verification reports
- immutable project security-memory snapshots
- claim lifecycle reconciliation
- deterministic allow, review, or block policy output
- production security-task execution with append-only audit events
- SHA-256 attestations for source, plan, audit, and artifact manifests
- execution deadlines and client-disconnect cancellation
- Trusted Analysis reports spanning evidence, threat, memory, and policy
- real Git repository acceptance coverage for block, fix, and resolution
- persistent reports inside VS Code

## Safety model

Dynamic validation must be explicitly authorized.

Aegis does not silently execute validation commands and does not treat a blocked, failed, or timed-out run as proof of safety.

The local sandbox currently applies:

```text
read-only container root
read-only repository mount
no host repository relabeling
no implicit container image pulls
network disabled by default
all Linux capabilities dropped
no-new-privileges
unprivileged container user
CPU and memory limits
process limits
execution timeout
bounded stdout and stderr
no shell-based container command construction
exact human-approved patch digest
target and selection hash revalidation
atomic source replacement
rollback without overwriting newer user work
```

Security memory records only explicitly complete results.
Partial or failed analysis is never persisted as a clean
baseline, and an empty snapshot requires explicit
complete-scan confirmation.
Trusted Analysis also requires an explicit completed
scanner-coverage artifact before it can update the
project baseline.

Validation is designed for repositories and systems you own or are authorized to test.

## Architecture

```text
┌──────────────────────────────┐
│        VS Code Extension     │
│                              │
│ analysis • findings • diffs  │
│ authorization • reports      │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│          Aegis API           │
│                              │
│ orchestration • evidence     │
│ verification • replay        │
└───────┬──────────────┬───────┘
        │              │
        ▼              ▼
┌──────────────┐  ┌──────────────┐
│ Static Layer │  │ Dynamic Layer│
│              │  │              │
│ scanners     │  │ authorization│
│ data flow    │  │ sandbox plan │
│ dependencies │  │ Podman/Docker│
└──────┬───────┘  └──────┬───────┘
       │                 │
       └────────┬────────┘
                ▼
┌──────────────────────────────┐
│      Fix Verification        │
│                              │
│ project checks               │
│ static rescan                │
│ baseline replay              │
│ unified verdict              │
└──────────────────────────────┘
```

## Repository structure

```text
aegis/
├── backend/
│   ├── aegis/
│   │   ├── orchestrator/
│   │   ├── schemas/
│   │   └── security/
│   └── tests/
├── extension/
│   ├── src/
│   └── dist/
├── docs/
└── examples/
```

## Backend

Requirements:

- Python 3.14
- Podman or Docker
- Semgrep

```bash
cd backend

python -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"

export AEGIS_FINGERPRINT_KEY="$(
  python -c 'import secrets; print(secrets.token_urlsafe(48))'
)"

uvicorn aegis.main:app --reload
```

Check the service:

```bash
curl http://127.0.0.1:8000/health
```

## VS Code extension

```bash
cd extension

npm install
npm run compile
```

Open the extension directory in VS Code and launch the Extension Development Host.

The extension uses the following backend address by default:

```text
http://127.0.0.1:8000
```

Change it through the `aegis.backendUrl` setting when needed.

## Tests

Run the backend suite:

```bash
cd backend
source .venv/bin/activate
python -m pytest -q
```

Compile the extension:

```bash
cd extension
npm run compile
```

Run the complete pre-release gate:

```bash
./scripts/run-release-readiness.sh
```

See [the release checklist](docs/RELEASE_CHECKLIST.md) for the manual checks
that remain after the automated gate passes.

## Dynamic replay smoke fixture

A safe local fixture is included at:

```text
examples/dynamic_replay_smoke
```

Run it with:

```bash
cd examples/dynamic_replay_smoke

python validation.py
PYTHONPATH=. python -m pytest tests -q
```

The vulnerable baseline reports:

```text
AEGIS_EXPLOIT_CONFIRMED
```

After a successful fix, the same validator should report:

```text
AEGIS_SAFE_BEHAVIOR
```

The fixture inspects command construction without executing the supplied payload through a shell.

## Project status

Aegis is under active development.

The current milestone establishes the full verification chain:

```text
finding
→ authorized reproduction
→ patch
→ project verification
→ static rescan
→ dynamic replay
→ final verdict
```

Interfaces and schemas may change before the first stable release.

## Responsible use

Use Aegis only on code and systems you own or have explicit permission to test.

Do not use its validation features against third-party infrastructure without authorization.

## License

Aegis is licensed under the [Apache License 2.0](LICENSE).

---

<div align="center">

**Security claims are cheap. Evidence isn't.**

</div>
