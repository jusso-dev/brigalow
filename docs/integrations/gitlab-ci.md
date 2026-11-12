# GitLab CI workload identity (test-purpose signing)

Brigalow can accept GitLab CI ID tokens for **test-purpose policies only**. Release policies and attestation-enabled policies reject GitLab principals. This follows the reviewed design in plan 003: GitLab's protected-ref types, environment protection and pipeline-configuration provenance do not yet have a reviewed contract equivalent to the GitHub release rules. The profile has been tested against generated local tokens only, not a real GitLab instance.

## Supported baseline

GitLab 18.4 or later, which documents `job_project_id` and `job_project_path` in ID tokens. Tokens without them are rejected. Brigalow cannot detect the GitLab version; confirm it yourself during onboarding.

GitLab ID tokens expire at the job timeout, or after five minutes if none is set. Brigalow rejects any workload token with a lifetime over 3600 seconds, so keep the signing job's `timeout` at one hour or less. A longer job timeout produces a validly signed token that Brigalow still rejects.

## Brigalow configuration

In the operator-owned identity file, set `provider` explicitly on the authority. Brigalow never infers it from the token or host. Each workload rule needs a `gitlab` object and an empty (or omitted) `claims` map:

```json
{
  "org_id": "<organisation UUID>",
  "name": "gitlab",
  "issuer": "https://gitlab.example.internal",
  "jwks_url": "https://gitlab.example.internal/oauth/discovery/keys",
  "provider": "gitlab",
  "human": null,
  "workloads": [
    {
      "project": "<project UUID>",
      "policy": "<test policy UUID>",
      "gitlab": {
        "project_id": "<numeric GitLab project ID>",
        "project_path": "group/project",
        "ref_path": "refs/heads/main",
        "pipeline_sources": ["push"],
        "environment": "signing-test"
      }
    }
  ]
}
```

- `project_id` and `project_path` must match the signed job project and source project exactly. Pipelines whose job and source projects differ are refused.
- `ref_path` is fully qualified (`refs/heads/<branch>` or `refs/tags/<tag>`). The token's `ref_type` and short `ref` must agree with it, and `ref_protected` must be `"true"`.
- `pipeline_sources` is an exact allow-list. `merge_request_event` and `external_pull_request_event` are refused at startup.
- `environment` is optional. When set, the job must declare exactly that environment.
- Do not configure the same issuer under both `github` and `gitlab` in one organisation; startup fails.

The bound policy must have `purpose = "test"` and `attestation = false`. Policy claim rules can match the normalised claims (`ref`, `environment`, `sha`, `project_path`, `pipeline_source`), but never `repository` or `workflow`, which GitLab principals do not carry.

## Minimal job

```yaml
sign-test:
  # Operator-built image containing `brig`; pin by digest, never by tag.
  image: registry.example.internal/brigalow/brig@sha256:<64-hex digest>
  stage: deploy
  environment: signing-test
  timeout: 30m
  rules:
    - if: $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_REF_PROTECTED == "true"
  id_tokens:
    BRIGALOW_ID_TOKEN:
      aud: "brigalow:<organisation UUID>"
  script:
    # The token stays in the environment: never echo it or pass it as an argument.
    - export BRIGALOW_TOKEN="$BRIGALOW_ID_TOKEN"
    - unset BRIGALOW_ID_TOKEN
    - >
      brig sign --server https://signing.example.internal
      --org <organisation UUID> --project <project UUID>
      --policy <test policy name> --format raw
      --ca-file /etc/brigalow/ca.pem
      --output dist/artifact.sig dist/artifact.bin
```

The `rules:` clause only stops unintended pipelines from requesting tokens. Brigalow enforces the source, ref, protection and project checks itself from the signed token. Do not enable shell tracing (`set -x`, `CI_DEBUG_TRACE`) in signing jobs, because it can print variable values. Point the job at a self-hosted, verified-TLS Brigalow endpoint. Never disable TLS verification or expose an unprotected signing service to reach it.

## What is not mapped

- `ci_config_ref_uri` and `ci_config_sha` are not treated as a GitHub-style `workflow`. They identify only the top-level configuration, not every included file.
- `repository` is not derived from `project_path`. A GitLab token that carries `repository`, `workflow`, `job_workflow_ref`, `run_id` or `provider` is rejected.
- `environment_protected`, `namespace_*`, `user_*` and runner claims confer no authority.

See `docs/threat-model.md` (GitLab workload profile boundary) and AT-ID-04 in `docs/acceptance-tests.md`.
