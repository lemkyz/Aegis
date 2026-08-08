# Aegis public website — V8 institutional candidate

## What changed

- Replaced the repository screenshot treatment with a build-time GitHub integration:
  - `README.md` is fetched from the public repository during `prebuild`.
  - repository metadata is refreshed from the public GitHub API when available.
  - checked-in snapshots keep the site deterministic when GitHub is unavailable.
  - build-time README input is bounded and sanitized before it becomes embedded website content.
  - the homepage renders a large scrollable source explorer with Code / README / Release views.
- Rebuilt Product Surfaces as an interactive three-surface studio for VS Code, GitHub Action, and CLI/local API.
- Added an interactive Security Boundary Explorer for local, model-provider, controlled-validation, and website boundaries.
- Added a keyboard-accessible command palette (`Ctrl/⌘ K`) for navigation and install/source actions.
- Added an accessible current-release drawer from the homepage.
- Added a quiet, desktop-only interactive lifecycle rail that tracks Find → Evidence → Prove → Verify → Decide → Remember as the homepage scrolls.
- Upgraded pricing readability and added a plan-focus interaction while preserving full-card navigation.
- Rebuilt homepage contact routing for Product, Team/Enterprise, Founder/Investor, Partnerships, and Security.
- Added first-class addresses for `hello@`, `founder@`, `partnerships@`, `security@`, and `billing@`.
- Preserved zero-runtime-dependency public architecture: no remote JS, iframe, analytics, chat widget, database, login, or contact API.
- Kept the warm ivory / near-black / restrained-gold Aegis identity while increasing density, contrast, and product depth.

## Public-claim discipline

V8 still separates current `0.2.0` product capabilities from company direction. It does not invent customers, testimonials, performance metrics, compliance badges, or unshipped enterprise/runtime capabilities.
