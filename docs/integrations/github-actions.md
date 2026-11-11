# GitHub Actions OIDC wrapper

The composite action under `actions/sign` builds the Rust `brig` CLI and obtains a short-lived workload token with audience `brigalow:<org>`. It uses Python's standard library and Rust stable; no Node.js action runtime. Callers grant `id-token: write` and configure Brigalow's issuer/repository/ref/workflow/environment rules before signing.

For a workflow in this repository, after a SHA-pinned checkout:

```yaml
permissions:
  contents: read
  id-token: write
jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
      # Build your artifact in a preceding step.
      - uses: ./actions/sign
        with:
          server: https://signing.example
          org: <organisation UUID>
          project: <project UUID>
          policy: <policy UUID>
          file: dist/artifact.bin
          output: dist/artifact.sig
          format: raw
```

Consumers in other repositories must pin `jusso-dev/brigalow/actions/sign` to a reviewed full commit SHA, and check the action can reach their self-hosted HTTPS endpoint. Do not expose an unprotected signing service to make a hosted runner connect. `ca-file` optionally supplies a private HTTPS CA to Brigalow; TLS verification is never disabled. The runner needs stable Rust and Python 3.

GitHub supplies `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`. The wrapper accepts no workflow input overriding these. It replaces any endpoint audience with the exact organisation audience, refuses plaintext/credential-bearing URLs and redirects, bounds the response, and passes only the resulting ID token to `brig` through `BRIGALOW_TOKEN`. The GitHub token-minting credential is removed from the child environment. Neither token appears in argv or action output.

Brigalow verifies the issuer/JWKS, audience, expiry and exact configured workload claims. A repository/ref/environment string in user metadata confers no authority. Approval, gates, release windows and certificate trust rules remain server-side. The CLI hashes locally and writes the signature, optional timestamp and provenance sidecars without overwriting existing files. An interruption requires querying/reconciling the printed request ID before retrying.

The acceptance tests use a generated-token mock issuer and local signing service. They do not request real GitHub signing authority, enrol with a CA, publish a release or send email.
