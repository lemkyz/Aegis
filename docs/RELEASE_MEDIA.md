# Release media

Release images must show the packaged extension running against the checked-in release fixture. Do not use mockups, generated interfaces, seeded Marketplace reviews, or the Extension Development Host.

## Capture setup

1. Run `./scripts/run-release-readiness.sh`.
2. Install `extension/aegis-security-0.2.0.vsix` in a clean VS Code profile.
3. Start the backend from the same release commit.
4. Open a copy of the acceptance fixture with no personal paths, tokens, accounts, or unrelated extensions visible.
5. Use the default dark VS Code theme at 1440×900 or larger.
6. Keep text at a readable zoom and crop only empty desktop space.

## Required images

| File | Content |
|---|---|
| `docs/media/trusted-analysis.png` | Full Trusted Analysis decision with task graph and integrity section visible |
| `docs/media/finding-evidence.png` | One finding with scanner evidence and model consensus |
| `docs/media/secure-fix.png` | Real VS Code diff for the reviewed patch |
| `docs/media/fix-verification.png` | Final verdict with rescan and replay evidence |

Before committing, inspect every image at full size. Remove usernames, home directories, repository tokens, model API keys, notifications, and private workspace names.

The root and Marketplace READMEs should reference these files only after all four exist and have been reviewed.
