# Release checklist

Run the automated gate:

```bash
./scripts/run-release-readiness.sh
```

The command must finish without skipped failures. It covers the backend
suite, real-repository acceptance cases, the installed wheel smoke test,
extension tests, VSIX packaging, package inspection, and diff hygiene.

Before tagging a release:

- Confirm the version matches in the backend, extension, changelog, and tag.
- Install the generated VSIX in a clean VS Code profile.
- Run Fast Scan, Deep Analysis, Trusted Analysis, Secure Fix, and the task-plan
  preview against the release fixture.
- Confirm a blocked run cannot create a clean security-memory baseline.
- Confirm Trusted Analysis shows verified source, plan, audit, and artifact
  hashes.
- Capture screenshots from the packaged extension, not the development host.
- Read every command title, notification, report heading, README section, and
  release note. Remove filler, repeated claims, and placeholder text.
- Check every README link and marketplace link in a signed-out browser.
- Inspect the wheel and VSIX listings for local paths, source maps, credentials,
  private keys, environment files, and test data.
- Record the release commit, artifact checksums, and acceptance output.
- Create the tag only from a clean worktree.

Publishing remains a manual action. Passing this checklist does not upload an
artifact or change a marketplace listing.
