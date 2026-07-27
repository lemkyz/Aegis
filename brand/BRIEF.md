# Aegis visual identity brief

## Position

Aegis is trust infrastructure for software agents. The identity should suggest
control, proof, and continuity without presenting the product as another
scanner or generic security dashboard.

## Avoid

- shields, locks, keyholes, helmets, robot heads, and circuit-board traces
- neon gradients associated with generic AI products
- a stock capital A placed inside a container
- details that disappear at 16 or 32 pixels
- marks that require color to remain recognizable

## Functional requirements

- distinct silhouette at extension-icon size
- works in one color before color is introduced
- readable on light and dark backgrounds
- reproducible as a clean vector
- no generated imagery or marketplace mockups
- icon and wordmark must work independently

## Selected mark

The Aegis mark is an open isometric control plane containing six trust nodes,
three verification axes, and one attested center.

- The open top and bottom keep the system extensible rather than sealed.
- The six nodes represent independently inspectable ecosystem participants.
- The three axes represent separate routes to verification.
- The gold center is the invariant witness retained by Aegis.
- The heavier outer plane distinguishes governance from the evidence graph it
  contains.

The construction is deliberately geometric. Do not redraw it from a generated
image, close the outer plane, add effects, or change node positions.

## Palette

| Token | Value | Use |
|---|---|---|
| Aegis Ink | `#111318` | Primary geometry and dark surfaces |
| Evidence Paper | `#F5F1E8` | Light surfaces and reversed geometry |
| Attestation Gold | `#C99A42` | Invariant witness only |

Color is not required for recognition. The monochrome mark replaces the gold
center with the foreground color.

## Assets

- `aegis-mark.svg` — primary transparent vector
- `aegis-mark-reversed.svg` — transparent vector for dark surfaces
- `aegis-mark-mono.svg` — single-color reproduction
- `../extension/images/icon.png` — packaged 512 px extension icon

The mark has been checked at 16, 32, 64, 128, and 512 pixels. Use at least
32 pixels when the internal evidence lattice must remain legible.
