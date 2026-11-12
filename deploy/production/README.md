# Single-instance production reference

This directory supplies deployment configuration, not a running production service. Use the exact tested revision, an operator-reviewed image including your vendor PKCS#11 provider, external PostgreSQL with verified TLS, a configured RS256 OIDC provider and operator-supplied TLS certificates. No CA purchase, cloud account or production deployment is performed by these files or tests.

Supported topology: one server, one TLS proxy, external Postgres and a vendor HSM. In-progress OIDC login state is process-local: restarting the server requires restarting that login. Existing authenticated sessions remain in Postgres. Do not scale beyond one server; the Helm chart rejects that setting and uses Recreate updates to prevent overlapping server pods. HA and vendor-device qualification remain outside this reference.

## Build and qualify

Build the `production` target from the repository's root Dockerfile using an explicitly named Docker context. The final image runs as UID/GID 10001, includes the server and operator commands, and defaults to production mode. It contains neither a compiler nor SoftHSM. Builder/runtime base images are pinned by digest. Rebuild and scan OS packages and the vendor provider as part of your image release process.

Extend that image with your licensed/reviewed vendor PKCS#11 module and its required non-secret configuration. Configure `hsm_module` to the exact path and `hsm_token` to the intended token label. The stock image cannot sign without that provider; it never falls back. Do not deploy the `test-runtime` target: it adds SoftHSM solely for isolated acceptance tests.

`python3 scripts/e2e.py --context <local-context>` validates the production image contract, then starts a separate production-mode container with the test-only provider, external test Postgres/IdP and generated credentials. The real TLS proxy is checked for body/rate limits and secret-free output. No real HSM or cluster is contacted. A successful SoftHSM run is not evidence about vendor hardware, firmware, backup or key attestation.

## Migrate and bootstrap separately

Stop the single application instance during schema upgrades. Take and verify an operator-controlled backup/checkpoint first. Migration and bootstrap credentials must never be mounted in the server container or its Kubernetes Secret.

Run the released `brigalow-admin` command using a separate private config file selected by `BRIGALOW_CONFIG`. It needs only DB settings and `backend = "disabled"`; it never loads a key provider. Database credentials still come from a 0600 regular file or environment, with TLS verification enabled. The operator role must own migration objects and be a superuser or have CREATEROLE/BYPASSRLS plus schema-creation authority. Restrict this role to the offline provisioning process.

1. `brigalow-admin migrate` applies embedded migrations under SQLx's lock. Repeating it is safe. Migrations never run in the HTTP server or on each replica.
2. Provision a separate login through your DB administration process: NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS; grant only membership in `brigalow_app`. Set its password interactively or through your secret manager. A CA operator, if used, gets a separate login inheriting `brigalow_ca`, not `brigalow_app`.
3. `brigalow-admin org-create --org <UUID> --name <name>` creates the tenant and its first audit event atomically. Repeating the same UUID/name does nothing; a conflicting name fails rather than renaming the tenant.
4. Configure that exact organisation UUID in `identity.json`. Map the operator's IdP groups to required roles. Org administration does not grant signing/approval authority; keep requester, custodian and approver separation.
5. Start the application with the restricted runtime login. It refuses missing, extra, failed or checksum-mismatched migrations. Do not run an older binary against a newer schema; restore through the documented recovery procedure if rollback is necessary.

## Docker Compose

Set `BRIGALOW_IMAGE` to the reviewed immutable image digest, `BRIGALOW_CONFIG_DIR` to a private directory owned/readable by UID 10001, and `BRIGALOW_TLS_DIR` to a private directory owned/readable by UID 101. Values select paths/images; never put PINs or passwords in the Compose file. Both directories must have mode 0700; all files must be regular files with mode 0600.

The config directory contains `config.toml`, `identity.json`, DB CA certificate, credential files, trust anchors and any referenced configuration. Use `/run/brigalow/...` paths in config. The TLS directory contains `tls.crt` and `tls.key`. TLS certificates must match the external URL configured in `identity.json`.

Use `python3 scripts/production.py --context <context> config --quiet` before an operator-authorised rollout, then the same checked entry point with `up -d`. It rejects mutable image tags, missing files, symlinks and permissive directory/file modes. Direct Compose invocation bypasses these input guards and is not the supported entry point. The default host binding is loopback port 8443; selecting another bind address is an explicit operator network decision. The backend HTTP port is never published. The runtime mounts that private directory read-only; credential changes require a controlled server restart. Never place owner credentials in that directory.

The proxy uses TLS 1.2/1.3, 64 KiB body limits, bounded headers/connections/timeouts, an IP budget and no automatic upstream retry. Request/error access logs are disabled because OIDC URLs can carry codes; application audit records provide business/security history. Use infrastructure metrics and health probes that do not capture credentials. Do not put an unconfigured proxy in front that lets clients choose their own source-IP identity; the reference ignores caller-supplied forwarding headers.

## Helm

The chart requires an immutable image digest, an existing runtime-only Secret and explicit egress destination/port rules. A default-deny NetworkPolicy admits HTTP only from the configured TLS ingress namespace and pod labels. DNS uses kube-system/k8s-app=kube-dns; adapt this selector for the intended cluster. The CNI must actually enforce NetworkPolicy. Supply a separately configured TLS ingress with the same body/header/connection/time limits as the Compose proxy; the chart intentionally does not create public ingress or certificates.

Run migrations as an explicit owner-controlled one-shot job/command before applying the server revision. Do not add owner credentials to the chart's runtime Secret. Projected runtime secrets are copied to regular 0600 files in a memory-backed volume, with no service-account token, root user, writable root filesystem or Linux capabilities.

`/livez` reports HTTP process liveness and does not restart the service for a database outage. `/healthz` checks database reachability and the logged-in PKCS#11 session with a bounded response timeout; busy/unavailable HSM checks make the instance unready. This probe does not create a signature or prove a particular key's policy/availability. Set vendor module transport timeouts; an uninterruptible native call requires operator recovery. In-flight signing intents must never be blindly retried.

Before go-live, qualify the actual HSM/provider, TLS/IdP and restricted DB roles, validate ingress/CNI enforcement, pin the signing/audit public keys independently, rehearse your real HSM/DB restore procedure and review the exact deployed image/configuration. The repository tests establish software/reference-container behaviour only. No HA, public trust, FIPS validation or compliance certification is claimed.
