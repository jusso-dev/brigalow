# 0001: Licence is Apache-2.0

Date: 2026-11-11. Status: accepted.

## Decision
Brigalow is licensed under the Apache License 2.0.

## Why
- Includes an explicit patent grant, which matters for security software that enterprises adopt.
- Permissive, so organisations can run it internally and integrate it with proprietary HSM tooling without licence friction.
- Widely accepted by corporate open-source policies; compatible with the RustCrypto and tokio ecosystem licences (MIT/Apache-2.0).

## Alternatives considered
- **AGPL-3.0**: protects against closed SaaS forks but blocks adoption by many enterprises, which is the main audience.
- **MIT**: simpler but no patent grant.
- **LGPL-2.1** (as SignServer CE uses): weaker fit for a Rust static-linking ecosystem.
