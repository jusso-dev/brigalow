# Brigalow

Open-source, self-hosted signing control plane. Build systems send a digest; Brigalow checks who is asking and whether policy allows it, has a key in an HSM sign it, and keeps a tamper-evident record.

> **Status: design and scaffold only.** Nothing here is ready to sign real software. Don't deploy it to production. Work is tracked in [issues](https://github.com/jusso-dev/brigalow/issues) and [ROADMAP.md](ROADMAP.md).

## Why

Signing keys still end up on build agents and laptops. Commercial signing platforms fix that, but the only open-source signing server with a long history (SignServer Community Edition) dropped HSM support in 7.7.1 and is labelled non-production. Brigalow aims to be a production-intended, HSM-first option you can run yourself, including air-gapped.

## What it will do

- Keep private keys in an HSM (PKCS#11) or KMS. No export.
- Accept digests only; artifacts stay on the build machine.
- Authenticate humans with OIDC and CI jobs with OIDC workload tokens, matched against rules (repo, branch, workflow, environment).
- Enforce signing policies with a test or release purpose, async k-of-n approvals where one deny rejects, release windows with signature caps, and fail-closed pre-sign gates.
- Produce raw signatures and detached CMS with RFC 3161 timestamps; later a PKCS#11 module so existing tools (osslsigncode, jsign, cosign, GPG) work unchanged.
- Record every step in a hash-chained audit log you can verify offline.

## What it won't do

Brigalow is not a certificate authority and can't make a signature publicly trusted. Public trust (Windows SmartScreen, macOS Gatekeeper and similar) needs a certificate from a public CA after identity validation, usually with a fee and certified key hardware. Brigalow can put policy, approvals and audit in front of such a key, but the trust comes from the CA. See [docs/product/scope.md](docs/product/scope.md).

## Docs

| Doc | What's in it |
| --- | --- |
| [docs/research/](docs/research/README.md) | Research on ten commercial signing products, with an evidence register and comparison |
| [docs/product/scope.md](docs/product/scope.md) | Who it's for, trust tiers, scope and non-goals |
| [docs/architecture.md](docs/architecture.md) | Components, request lifecycle, audit chain, identity, tenancy |
| [docs/threat-model.md](docs/threat-model.md) | Assets, boundaries, threats, controls |
| [docs/acceptance-tests.md](docs/acceptance-tests.md) | Executable acceptance tests per phase |
| [ROADMAP.md](ROADMAP.md) | Phased plan |
| [docs/decisions/](docs/decisions) | Licence, stack, trust tier decisions |

## Build

Requires stable Rust.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [docs/decisions/0001-licence.md](docs/decisions/0001-licence.md).

Product names mentioned in the research belong to their owners. Brigalow contains no code, UI or text from those products.
