# 0003: Separate self-hosted trust from public trust

Date: 2026-11-11. Status: accepted.

## Decision
Every key and certificate carries a trust tier (`lab`, `private`, `untrusted`, `external-ca`). Brigalow never labels anything "publicly trusted" on its own judgement. `external-ca` means the operator imported a chain that ends at an anchor they marked as an outside CA; Brigalow shows the anchor name and leaves trust decisions to the relying platform.

## Why
The research shows public trust always comes from a CA after identity validation, with hardware key requirements, often with country limits and fees (see docs/research/evidence-register.md, A8, A9, L4). An open-source tool that blurs this would mislead operators.
