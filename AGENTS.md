# Instructions for coding agents

Read these before writing code, in this order:

1. `docs/product/scope.md` (trust tiers and non-goals are binding)
2. `docs/architecture.md`
3. `docs/threat-model.md`
4. `docs/acceptance-tests.md`
5. `ROADMAP.md` and the open GitHub issues (one per phase)

## Rules

- Work phase by phase. A phase is done only when its acceptance tests are automated and passing in CI.
- Security controls ship with the feature they protect.
- Never hand-roll cryptography. Use the crates named in `docs/decisions/0002-stack.md` or HSM mechanisms.
- Never add a private key export path, a bulk approve action, or a silent HSM-to-software fallback.
- Never claim public trust, FIPS validation or compliance certification in code, UI or docs.
- No real CA enrolment, certificate purchase, cloud account, production deployment or outbound messages. Use local test CAs, SoftHSM2, mock IdPs and mock services.
- Keep secrets out of the repo, logs and test fixtures (generate test keys at test time).
- Keep `brigalow-core` free of I/O.
- Commit in small, reviewable steps with clear messages. No force pushes or history rewrites on `main`.
- Pin GitHub Actions to full commit SHAs.

## Commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
