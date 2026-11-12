# GitLab workload identity: design outcome

Reviewed Brigalow source `89cf46697091a1b175435f1971ba74a3131db7d1`. Public GitLab documentation retrieved through Context7 on 2026-11-12: [CI ID tokens](https://docs.gitlab.com/ci/secrets/id_token_authentication/), [CI YAML `id_tokens`](https://docs.gitlab.com/ci/yaml/), and [Vault protected-ref example](https://docs.gitlab.com/ci/secrets/hashicorp_vault/). The retrieved ID-token table was from [GitLab 19.4](https://docs.gitlab.com/19.4/ci/secrets/id_token_authentication/); minimum-version claims below are documented there, not inferred for older instances. No real GitLab account or token was used. This is a proposal, not implemented or verified provider compatibility.

## Provider claim mapping

| Brigalow concept | GitLab signed token field | Decision and evidence |
| --- | --- | --- |
| Issuer/audience | `iss`, `aud` | Pin an explicit HTTPS issuer/JWKS; job config sets `id_tokens.<name>.aud` to exact `brigalow:<org>`. Never use unverified data as an outbound URL. Documentation: ID-token payload and CI YAML links above. |
| Source project | `project_id`, `project_path` | Both identify the source project for merge-request pipelines. Require exact issuer-scoped immutable project ID and exact expected path in workload rules; do not assume they identify target project for merge requests. |
| Job project | `job_project_id`, `job_project_path` | Documentation says present from GitLab 18.4. Proposed supported baseline is **18.4+** and both must exactly match configured job project ID/path; absence fails. Validate issuer/version in operator onboarding, never infer version from token alone. |
| Ref | `ref_path`, `ref_type`, `ref` | `ref_path` is fully qualified, e.g. `refs/heads/main`; `ref` is short. For policies map only the verified `ref_path` to canonical `ref`, after validating type/path consistency; reject ambiguous values. Require exact allowed `pipeline_source`, e.g. explicitly configured `push`; default-deny merge-request and other sources. |
| Protected ref | `ref_protected` | Require exact provider-signed true according to documented supported version and fixture shape; a GitLab Vault example uses string `"true"`. The existing workload rule matcher only accepts JSON strings, while `Principal` supports strings/bools; don't silently broaden it. Until the accepted token type is evidenced for each supported version, fail closed for release. |
| Environment | `environment`, `environment_protected` | Claims exist only when job specifies an environment. Require exact configured environment and a verified protected environment when release policy requires it. Absence, null or unknown type fails closed. These are separate from ref protection. |
| Commit | `sha` | A verified job commit claim is available in the referenced ID-token table; validate documented format and carry it as verified `sha`. It is not evidence that Brigalow observed a build. |
| Workflow | `ci_config_ref_uri`, `ci_config_sha` | URI is null when top-level config is not in the same project. It identifies the top-level config ref, not necessarily every included or executed file. Do **not** map it to GitHub-style `workflow` as though semantics match. Missing/scope ambiguity means GitLab attestation and release stay disabled pending a reviewed, versioned provider-specific statement. |
| Pipeline/job | `pipeline_id`, `job_id`, `pipeline_source` | Treat as signed provider-specific identifiers/claims only; do not substitute self-reported CI environment variables or parse configurable `sub` as authority. |

All mappings are issuer-specific, applied only after cryptographic JWT/issuer/audience/time validation, never inferred from a host or caller metadata. Do not rename or reinterpret existing GitHub principals. A common canonical field is permitted only when documented semantics and allowed types are proven equivalent.

## Trust and policy contract

Initial proposed capability: **test-purpose signing only** on an explicitly configured GitLab authority/rule, generated JWT fixtures, and no attestation. Preserve existing release policy requirements and deny `release` and provider-ambiguous attestation until protected-ref/environment types, job/source project relationships and workflow provenance have a reviewed versioned contract. This is stricter than assuming name equivalence, not a claim GitLab tokens are insecure. Record exact issuer, project IDs, expected paths, pipeline source, ref and environment in the operator-owned rule; unknown issuers, unsupported algorithms, missing claims or incompatible types fail closed. Distinct GitLab instances can issue identical project IDs; issuer binding remains mandatory.

Current server `verify_workload` validates signed token and exact raw configured string claims (`crates/brigalow-server/src/auth/workload.rs:49–78`), but `Principal` keeps only GitHub-shaped fields (`auth/mod.rs:281–303`); a GitLab profile needs explicit post-verification normalization and policy changes, not a recipe alone. Reject mapping conflicts if both provider/native and canonical fields exist. Preserve token secrecy, scope, RBAC, no redirect/proxy and bounded JWKS logic.

GitLab documentation says a CI ID token expires at the job timeout or five minutes when no timeout is specified. Brigalow currently rejects signed token lifetimes over 3600 seconds. Document this incompatibility and fail closed; do not weaken the lifetime limit. A job with a longer configured timeout can fail even when its token is otherwise valid.

## Integration and test matrix

Later implementation must use an HTTPS local issuer with generated RSA signing keys and configured test CA; no checked-in JWTs. Generate same-issuer signed scenarios for exact org audience, wrong issuer/key/aud, expiry/nbf, 3601-second lifetime, short- and fully-qualified refs, unprotected ref, missing/wrong environment, missing/wrong project ID/path, mixed job/source project, merge-request source, provider claim type changes, conflicting canonical/provider claims and metadata spoofing. For the test-only profile assert success only under configured `test` purpose, and explicitly assert all release/attestation attempts fail. Exercise cross-tenant isolation, token scope, expiry after previous success and generated request-ID replay. Once a separately reviewed provenance format exists, reconstruct DSSE framing independently and use OpenSSL to verify the signature; don't enable it in this initial slice.

A later minimal self-hosted job example may declare `id_tokens: { BRIGALOW_ID_TOKEN: { aud: "brigalow:<org>" } }`, then copy only that environment value into `BRIGALOW_TOKEN` for `brig` without echoing it or putting it in argv. It must use a digest-pinned, operator-provided CLI image and a locally reachable verified-TLS Brigalow URL; no runner, account or real endpoint is created by the repository.

## Compatibility

Keep current GitHub action and verified GitHub `repository/ref/workflow/environment/sha/ref_protected` semantics unchanged. Add provider profile/version explicitly to trusted configuration; no implicit inference by unverified token contents. Preserve immutable existing policies and the exact `brigalow:<org>` audience contract. Test matrix must run all existing AT-ID-01..03, AT-POL-02, AT-ATT-01 and AT-TEN-01 plus proposed **AT-ID-04** locally and in hosted CI. Update `docs/threat-model.md` with provider-specific mapping and version boundary in the same implementation change.

## Open questions

- Documentation examples support a string `ref_protected`; confirm actual JSON types for every supported GitLab release using locally generated fixtures based on a reviewed published contract, without collecting a real user token. Reject other forms until established.
- Specify and independently review semantics of `ci_config_ref_uri`, included CI configuration and provenance wording before allowing release/DSSE. A top-level config URI alone is not proof of the whole executed pipeline.
- Decide how an operator can assert installed GitLab version and protect immutable project IDs against project transfer/rename; acceptance tests cannot qualify a real deployment.
- Candidate files: `auth/mod.rs`, `auth/workload.rs`, `brigalow-core/src/policy.rs`, `deploy/dev/test_idp.py`, `crates/brigalow-server/tests/identity.rs`, integration documentation, acceptance tests and threat model. This spike changed none of them.
