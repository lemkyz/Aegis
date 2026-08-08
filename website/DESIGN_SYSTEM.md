# Aegis public web design system

## Brand thesis

Aegis should feel like security infrastructure, not a generic SaaS template. The visual system is derived from the existing trust-lattice mark and the product thesis: **Security claims need proof.**

## Locked visual identity

- Warm ivory canvas: `#f4f0e7`
- Near-black primary: `#111318`
- Verified-trust gold: `#c99a42`
- Red appears only for actual risk/failure states, never as the brand color.
- Green appears only for completed/verified operational states.
- No gradients used as decorative “AI” spectacle. Soft radial gold light is allowed only as atmospheric depth.
- Thin architectural rules, grids, evidence chains, and system diagrams are preferred over illustrations.
- Large whitespace and compact infrastructure UI create the premium contrast.

## Brand hierarchy

The hero must visibly establish the brand before the product thesis:

1. Official Aegis lattice mark
2. Large `AEGIS` wordmark
3. `Trust infrastructure for software agents`
4. `Security claims need proof.`

The slogan remains the dominant conceptual headline, but the company name must be unmistakable on first view.

## Typography

Use the native UI stack. No remote fonts. This removes a third-party request, improves startup performance, and keeps the public website compatible with a strict CSP.

- Display: system sans, medium weight, very tight tracking
- UI: system sans
- Evidence / provenance / integrity: system monospace

## Motion

Motion level: premium and visible but restrained.

Allowed:
- verification progress advancing through evidence stages
- selected Evidence Graph node state
- before/after Fix & Prove state switch
- product-surface tabs
- very small hover movement

Avoid:
- parallax spectacle
- floating particles
- cursor-following effects
- text scrambling
- endless marquees
- animation that hides content until scroll

Every interaction must remain understandable with `prefers-reduced-motion: reduce`.

## Product imagery

The site prioritizes real product evidence.

- Hero data comes from the checked-in/observed Aegis 0.2.0 SQL fixture run.
- Product surfaces must be replaced with captured current-release screenshots before public launch where noted in source.
- Never use fabricated customer dashboards, logos, testimonials, adoption counters, or compliance badges.
- Future agent-runtime direction must be labeled as direction, not shipped capability.

## Interaction rule

An interaction is allowed only when it clarifies a trust concept or exposes product evidence. It should never exist merely to make the page feel “AI.”

## Responsive behavior

Desktop compositions may be dense and architectural. Mobile collapses to a linear evidence narrative. Horizontal graph surfaces can scroll, but all important explanatory copy remains outside the overflow region.


## V3 readability and motion standard

- Light-background body copy uses `#373631` / `#57554f`; both exceed WCAG AA contrast on the ivory canvas.
- Small gold labels use the deeper `#80570f`, not the decorative mid-gold, so gold remains readable rather than ornamental.
- Dark panels use pale neutral copy (`#c1c5cc` and brighter) and pale gold accents.
- Product UI metadata is never intentionally reduced to decorative unreadable microtype; investor/demo surfaces have explicit minimum sizes.
- Hover motion is tactile rather than theatrical: cards lift by ~5px and receive a maximum ~0.9° axis rotation; buttons scale slightly; graph nodes expand on interaction.
- Fine-pointer motion is disabled on touch/coarse pointers and all enhanced motion respects `prefers-reduced-motion`.
- The hero uses a pointer-reactive gold light field with no telemetry or persistence.
