# Dependency remediation and production reference review

Date: 12 November 2026. Scope: self-hosted signing software and a single-instance deployment reference, not a deployed production service.

## Delivered changes

- All direct RSA/P-256 operations use current RustCrypto families; JWT verification uses jsonwebtoken/AWS-LC. OAuth2 PKCE plus explicit OIDC claim checks replace the advisory-bearing OIDC dependency chain. SQLx 0.9 uses a Postgres-only facade; Askama excludes unused TOML parsing. See [ADR 0003](decisions/0003-dependency-audit.md).
- Root and fuzz lockfiles pass `cargo audit --deny warnings` with no ignores and no vulnerabilities or warnings (1458-advisory local database). The pinned hosted workflow repeats both audits on changes and daily. This supersedes the residual dependency findings in the [earlier review](security-review-2026-11-12.md); its historical evidence remains unchanged.
- Released `brigalow-admin` separates owner migration/bootstrap credentials from runtime. Organisation creation/audit is atomic and idempotent. Runtime rejects schema version/checksum drift, missing identity and non-PKCS#11 production backends. Readiness checks DB and authenticated HSM session; liveness is separate.
- Root Dockerfile builds a non-root production image without compiler or SoftHSM. The separate test target supplies SoftHSM for qualification. Compose supplies restricted containers and a real TLS proxy with request bounds. Helm enforces one replica, Recreate updates, probes and explicit NetworkPolicy egress. The checked Compose entry point rejects mutable image tags, unsafe file types/modes and owners differing from the container UIDs.

## Independent source review

A separate read-only Codex reviewer (`/root/production_auditor`) reviewed frozen `d8d33b282fd4eb61a5a32f31ff28c4602c29965d` and the Compose guard follow-up `a9cd12f25100e7e3b1f57d850608d2c18353e448`. This is AI-assisted source review, not an external professional security audit or certification. The reviewer ran no tests, builds, services or deployment probes.

Initial gaps addressed: production could start without signing/identity; no matching runtime image; no released migration/bootstrap command; and process-local OIDC state conflicted with HA guidance. The chosen scope explicitly supports one server and requires restarting unfinished logins after process restart. Existing sessions remain in Postgres.

Final review findings addressed:

1. Compose accepted mutable image tags despite the documented immutable-image contract. Added the checked `scripts/production.py` entry point, used by deployment instructions, with negative tests.
2. Mode-only validation accepted root-owned private directories/files unreadable by the runtime UIDs. Added ownership checks for both directories and every file, plus separate wrong-owner regressions. This reference assumes ordinary Linux Docker UID mapping; user namespaces/Desktop sharing require separate qualification.

No other confirmed blocker was reported in those source reviews. Final follow-up verdict and hosted results for the delivered commit are recorded on the Phase 8 tracking issue. No review establishes absence of defects.

## Local evidence

- Format and all-target/all-feature Clippy pass; default workspace suite: 23 tests, zero failures.
- Full Compose suite passes all 35 AT IDs, including new AT-OPS-04 owner/bootstrap/schema checks and AT-OPS-05 production image/TLS/body/rate/redaction checks. Runs include generated-key IdP/JWKS/TSA, native signing tools, SoftHSM, private CA, mock CSC, independent OpenSSL verification and scratch backup/restore.
- Three 15-second fuzz targets pass: requests 1,129,471 executions; certificates 131,533; audit 1,192,095. Bounded fuzzing is regression evidence only.
- Helm/render refusals, release packaging/tamper, GitHub action wrapper and production-input regressions pass. Source and full-history gitleaks scans report no findings.
- Ownership guard tests simulate alternate UIDs while using real temporary file types/modes; container acceptance separately sets and exercises real numeric ownership. Compose syntax checks do not deploy the reference or establish host UID mapping.

## Remaining operator qualification

Follow the [production reference](../deploy/production/README.md). Qualify the actual vendor HSM/provider, capacity/timeouts and backup; provision TLS/IdP and restricted Postgres roles; verify ingress/CNI controls; independently pin signing/audit public keys; rehearse actual restore and review the exact image/configuration. Container OS packages and proprietary providers require their own scanning/patch process. HA is unsupported. No production deployment, real CA enrolment, purchase, cloud account or outbound notification occurred. No public trust, FIPS validation or compliance certification is claimed.
