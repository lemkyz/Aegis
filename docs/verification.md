# Understanding Aegis verification

Aegis treats a security claim and its verification as separate things.

A finding may identify security-sensitive behavior. Evidence explains why the
behavior matters. A remediation changes the software. Verification then checks
the relevant result independently.

The important product rule is simple:

> A system should not be considered correct merely because it says its own fix
> succeeded.

Aegis product surfaces therefore distinguish verified outcomes from partial,
unavailable, or inconclusive verification.

This public document describes product behavior, not proprietary engine
implementation.
