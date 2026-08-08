# Aegis public product capture gate

The investor/public website must show the shipping product, not invented UI. Capture these surfaces from Aegis 0.2.0 before launch.

## Capture 1 — Trusted Analysis

- Open the checked-in vulnerable SQL fixture in a trusted local workspace.
- Run **Aegis: Run Trusted Analysis**.
- Capture the canonical finding, deterministic scanner evidence, primary route, independent verifier, consensus, final `ALLOW / REVIEW / BLOCK` decision, and integrity state when they fit naturally in the real UI.
- Do not alter a result merely to make the screenshot look cleaner.

## Capture 2 — Fix verification

- Use a controlled repository fixture only.
- Capture the secure-fix review/authorization surface and the real verification outcome.
- Preserve the distinction among `VERIFIED`, `PARTIAL`, and `FAILED`.
- Do not present a generated patch as verified unless the product actually produced the verification evidence.

## Capture 3 — GitHub Action

- Use a test/public repository or sanitized fixture repository.
- Capture the Aegis change gate and the emitted policy/artifact surface.
- Do not expose organization names, private repository names, branch secrets, tokens, commit emails, or unrelated checks.

## Capture 4 — CLI/local backend

- Capture the real trusted-analysis path or a compact real artifact summary.
- Prefer deterministic output and policy/evidence records over decorative terminal text.

## Redaction gate

Before copying an image into `public/product/` verify that it contains none of the following:

- API keys, tokens, cookies, passwords, `.env` values, credentials
- private repository names or proprietary source code
- local usernames or home-directory paths unless intentionally genericized
- personal email addresses, account IDs, internal URLs, IPs, hostnames
- unrelated browser tabs, notifications, shell history, clipboard contents
- customer or employer information

Do not blur secrets after publishing. Retake or safely crop the source capture before it enters the website repository.

## Visual capture standard

- Desktop: 1440×900 or 1600×1000 source capture, 2× display scale when available.
- Keep VS Code chrome visible enough to prove it is the real extension.
- Use the Aegis fixture/repository context, not a fake customer project.
- Export lossless PNG/WebP; keep original capture outside the public website repo if it contains any discarded sensitive pixels.
- No fake cursor trails, fake success badges, fake customer data, or composited result states.
