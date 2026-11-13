# Azure reference: Brigalow with Azure Artifact Signing

These Bicep files describe one Brigalow server on one Azure VM, signing through an Azure Artifact Signing certificate profile. They were validated offline only (`az bicep build`, `az bicep lint`, `python3 deploy/azure/test_azure.py`). Nothing in this repository has deployed them, created an account or made a real signing request. Deploying creates billable resources in your subscription. Review the template and costs first.

For a first real deployment, follow the step-by-step [operator runbook](../../docs/runbooks/azure-first-deployment.md).

Supported topology: one VM, one server process, one TLS proxy. There is no scale set and no HA. The backend contract and its limits are in [Azure Artifact Signing backend](../../docs/integrations/azure-artifact-signing.md). Brigalow makes no public-trust, platform-acceptance or compliance claim for anything this produces.

## What it creates

| Resource | Notes |
| --- | --- |
| User-assigned managed identity | Attached to the VM. Holds **Artifact Signing Certificate Profile Signer** on the one profile, and **Key Vault Secrets User** on the vault. |
| Artifact Signing account and certificate profile | `Microsoft.CodeSigning/codeSigningAccounts@2025-10-13` plus `certificateProfiles`. Needs `identityValidationId` (portal step below). |
| VNet and NSGs | VM, delegated PostgreSQL and private-endpoint subnets. VM inbound allows 443 from `httpsSourceCidr` only, and 22 only when `enableSsh = true` (from `sshSourceCidr`). Other inbound is denied. |
| PostgreSQL Flexible Server | Private VNet access, `publicNetworkAccess = Disabled`, `require_secure_transport = on`, TLS 1.2 minimum, private DNS zone. |
| Key Vault | RBAC authorisation, purge protection, soft delete, public network access disabled, private endpoint. It holds the runtime DB password, login-state key, TLS material, the image reference, the runtime `config.toml`, `identity.json`, the pinned root and the optional TSA signer and anchor. |
| Linux VM (Ubuntu 24.04, Trusted Launch) | Cloud-init installs Docker and embeds the repository's `deploy/production/compose.yml`, `nginx.conf` and `scripts/production.py` unchanged (the offline test checks the bytes). At every boot, `brigalow-boot.py` reads the vault and writes the files into tmpfs: `/run/brigalow/config` (0700, UID 10001) and `/run/brigalow/tls` (0700, UID 101), each file 0600. It then starts Compose through `scripts/production.py`, so the digest-pin, ownership and mode guards apply. The proxy listens on 443. |

Secrets enter only as `@secure()` parameters, which [`main.bicepparam.example`](main.bicepparam.example) fills with Key Vault references to a vault you already control. No secret is written in a parameter file, and `deploy/azure/*.bicepparam` is git-ignored.

The PostgreSQL administrator (owner/migration) credential is used only to create the server and by your separate bootstrap step. It is not copied to the Brigalow vault, the VM or the runtime configuration. The runtime uses the restricted `brigalow_runtime` login, which you create during bootstrap with `dbRuntimePassword`.

## Prerequisites

1. An Azure subscription and a resource group where you may create these resources and role assignments.
2. The `Microsoft.CodeSigning` resource provider registered on that subscription (portal: **Subscriptions** > your subscription > **Resource providers**, or `az provider register --namespace Microsoft.CodeSigning`). It is not registered by default.
3. A completed Artifact Signing identity validation. Microsoft allows this in the Azure portal only, and it needs an Artifact Signing account to start from:
   - Get the **Artifact Signing Identity Verifier** role. Microsoft requires it to create identity validations, and the holder also needs at least Reader on the subscription.
   - Create an Artifact Signing account in the portal, or open an existing one. **Creating an account starts billing.** Microsoft charges the full monthly amount for the SKU from creation, not pro rata, whether or not you sign anything.
   - Go to **Identity validations**, choose **New identity**, then **Private** or **Public**. Private validations work only with the Private Trust profile type (Private Trust CI Policy too, but this template refuses that type). Public validations work only with Public Trust, Public Trust Test and VBS Enclave. Pick the one that matches `certificateProfileType`.
   - Submit the request and wait for **Completed**. Copy its **Identity validation ID** into `identityValidationId`.

   Identity validations belong to the subscription, not the account. Microsoft shares them across every Artifact Signing account in that subscription, so the validation you completed under the portal account also works for the account this template creates. You do not need to validate again. To avoid paying for two accounts, set `signingAccountName` to the portal account's name so the template manages that account, or delete the portal account once the validation is complete. Deleting an account keeps its subscription-scoped validations. Eligibility (organisation or individual, country) is Microsoft's decision; check it before you start.
4. An OIDC provider for people (authorisation code with PKCE) and your CI issuer for workloads, configured as in [development](../../docs/development.md#identity-setup-phase-1).
5. A reviewed production image pinned by digest. Build the `production` target from the root `Dockerfile`, scan it, push it to a registry the VM can pull from, and record `registry/brigalow@sha256:<digest>`. The VM must be able to pull it **anonymously**. The boot path has no registry login and no credential for one, so a private registry that requires authentication does not work with this template.
6. A TLS certificate and key for the public URL, and a separate operator vault holding the secure parameter values. Generate the login-state key with `openssl rand -base64 32`, and use strong generated database passwords. Bicep reads these through `az.getSecret`, so that vault must have **Azure Resource Manager for template deployment** enabled (`enabledForTemplateDeployment`), and the identity running the deployment needs `Microsoft.KeyVault/vaults/deploy/action` on it (for example through the Owner or Contributor role on that vault). Without both, deployment fails before any resource is created.
7. Outbound access from the VM to your registry, `<region>.codesigning.azure.net`, your OIDC issuers' HTTPS endpoints and the OS package mirrors. The VNet does not add a NAT gateway or firewall; add egress controls that suit your environment.

## Deploy

```sh
cp deploy/azure/main.bicepparam.example deploy/azure/main.bicepparam
# Replace every placeholder. Keep artifactSigningBindings = [] and the root '-' for now.
az deployment group create \
  --resource-group <rg> \
  --template-file deploy/azure/main.bicep \
  --parameters deploy/azure/main.bicepparam
```

Set `httpsSourceCidr` and `sshSourceCidr` to one CIDR each. The NSG rules take a single source prefix, so admit a range that covers every client you need. GitHub-hosted runners use many changing address ranges and cannot be covered by one CIDR. Use self-hosted runners with known egress, or put your own egress control in front.

### What the first boot looks like

The first boot is **not** expected to be healthy. The Brigalow server cannot start until bootstrap (below) creates the `brigalow_runtime` login, so:

- `brigalow-boot.py` reads the vault and writes `/run/brigalow/config` and `/run/brigalow/tls` as normal. Role propagation can delay this for up to 15 minutes.
- The server container exits and restarts, and its log shows `database startup failed`.
- The TLS proxy waits for a healthy server, so nothing answers on 443 and `/healthz` is unreachable. `brigalow.service` may show as failed, because Compose waits for that health check.

Check this without SSH by using Run Command, for example `az vm run-command invoke -g <rg> -n <prefix>-vm --command-id RunShellScript --scripts 'systemctl show brigalow.service -p ActiveState -p Result; journalctl -u brigalow.service -b --no-pager -o cat | tail -12'`. Azure keeps Run Command output, so never print secret values in it. The only failure that needs action now is `brigalow-boot: cannot materialise configuration from Key Vault (details withheld)` that is still there after 15 minutes. `/healthz` reports ready only after bootstrap and a service restart: the database must be reachable with the runtime login and a managed-identity token must be available. It never makes a signing request.

### Redeploying

The VM's `customData` (the cloud-init file with the embedded Compose file, proxy configuration, `production.py` and `brigalow-boot.py`) is applied at first boot only. Azure does not allow it to change on an existing single VM. A later deployment from a commit that changed any of those files fails on the VM resource. Deploy every later change from the same commit, or delete and recreate the VM to move to a new commit. Configuration that lives in Key Vault (parameters, bindings, roots) is not affected: redeploy, then restart the service.

## Bootstrap (separate owner step)

Run this from a separate, short-lived admin VM that you create in the **`vm` subnet** of the template's VNet. It must be in that subnet: the database NSG admits port 5432 only from the `vm` subnet. Give it no managed identity, keep it apart from the Brigalow VM's runtime directories, and delete it when bootstrap is done.

This template creates no `AzureBastionSubnet` and no Bastion host, and the VMs have no boot diagnostics and no password user, so neither Azure Bastion nor the serial console is available. Reach the admin VM through Run Command, or set `enableSsh = true` with your own `/32` in `sshSourceCidr` for the duration. The SSH rule is on the subnet, so it also opens 22 to the Brigalow VM. Set `enableSsh = false` and redeploy afterwards.

On the admin VM, use a private config file selected by `BRIGALOW_CONFIG` with `backend = "disabled"`, the owner login, `db_host` set to the `postgresFqdn` output and `db_ca_file` set to the CA bundle that verifies Azure PostgreSQL. Supply the owner password from a 0600 file, never as an argument.

1. Check that the owner role can run migrations. `brigalow-admin` requires superuser, or CREATEROLE plus BYPASSRLS. Azure documents the administrator as NOSUPERUSER with CREATEROLE, and BYPASSRLS depends on version and provisioning. Check with `SELECT rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = current_user;`. If BYPASSRLS is absent, follow Microsoft's guidance for your server version before continuing. Do not weaken Brigalow's checks.
2. `brigalow-admin migrate`
3. Create the restricted runtime login with the `dbRuntimePassword` value: `CREATE ROLE brigalow_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS IN ROLE brigalow_app PASSWORD '<from your secret store>';`. Enter the password interactively (for example `\password brigalow_runtime` in psql) rather than in shell history.
4. `brigalow-admin org-create --org <orgId> --name <name>`, using the same `orgId` as the deployment.
5. Restart the service on the VM (`sudo systemctl restart brigalow`) so the runtime connects with the new login.

See [production reference](../production/README.md#migrate-and-bootstrap-separately) for the same steps in more detail.

## First project, key registration and signing

1. Sign in as an org admin at `<publicUrl>/auth/<org>/<provider>/login` and create a project (`POST /v1/orgs/<org>/projects`).
2. Get the profile's issuing root and EKU, and review them independently, as described in [the backend guide](../../docs/integrations/azure-artifact-signing.md#configuration). Use `Get-AzArtifactSigningCertificateRoot` and `Get-AzArtifactSigningCustomerEku` from the `Az.ArtifactSigning` PowerShell module. Microsoft lists the **Artifact Signing Certificate Profile Signer** role as a prerequisite, so grant it to yourself on the profile for this step only. It also lets you sign with the profile, so remove it straight after. Check both values against a leaf from a reviewed signature or Microsoft's published fingerprints.
3. Redeploy with `artifactSigningRootDerBase64` set to the base64 of the root DER, and one `artifactSigningBindings` entry: `{ id: '<new key UUID>', org: '<org>', project: '<project>', purpose: 'release', account: '<account>', profile: '<profile>', profileEku: '1.3.6.1.4.1.311.97....' }`. The VM reads the vault at boot, so restart the service after the deployment.
4. As a key custodian, register and activate the key:

   ```sh
   # Session cookie and X-CSRF-Token from your browser session; never put them in shell history.
   POST /v1/orgs/<org>/projects/<project>/keys
   {"remote_key":"<key UUID>","algorithm":"rsa3072","purpose":"release","offline":false}
   POST /v1/orgs/<org>/keys/<key UUID>/activate   {}
   ```

   The key reports `trust: "external-ca"` with the pinned anchor's name. `external-ca` records your anchor configuration only.
5. As an org or project admin, create a policy bound to that key with `algorithms: ["rsa3072"]` and a timestamp setting (see below). Then add a workload rule for it in `oidcAuthorities` and redeploy.
6. From CI, with a workload OIDC token for audience `brigalow:<org>` in `BRIGALOW_TOKEN`:

   ```sh
   brig sign --server <publicUrl> --org <org> --project <project> \
     --policy release --format cms --output app.cms app.bin
   ```

   `brig` hashes locally and sends only the digest. Check the CMS with `openssl cms -verify -binary -inform DER -in app.cms -content app.bin -CAfile <pinned root PEM> -purpose any`.

## Timestamps

Microsoft's timestamp service (`http://timestamp.acs.microsoft.com`) is HTTP only, and Brigalow does not support HTTP TSAs. Artifact Signing certificates are valid for 72 hours. Without a trusted timestamp, most verifiers reject the signature after that certificate expires.

By default the template configures no TSA. `config.toml` has no `[tsa]` section, so policies must use `timestamp = "disabled"` (or `"optional"`), and you timestamp with a separate tool you trust.

To use an HTTPS RFC 3161 TSA you trust, set all three parameters and redeploy:

| Parameter | Value |
| --- | --- |
| `tsaUrl` | The TSA's `https://` URL. The deployment fails for any other scheme, including Microsoft's HTTP TSA. |
| `tsaSignerDerBase64` | Base64 of the pinned TSA signer certificate (DER). It must carry a critical, exclusive timeStamping EKU. |
| `tsaAnchorDerBase64` | Base64 of the CA certificate (DER) the signer chains to. |

The template then writes `[tsa]` with `url`, `signer_file = "/run/brigalow/tsa-signer.der"` and `anchors = ["/run/brigalow/tsa-anchor.der"]`. Both certificates go through Key Vault like the Artifact Signing root, and `brigalow-boot.py` writes them as 0600 files owned by UID 10001. Set both certificates or neither; the deployment fails for one alone. Obtain them through a channel independent of the TSA's responses. The template does not set `tls_ca_file`, so the TSA's HTTPS certificate must chain to a public web root that Brigalow's TLS client trusts. Whether a platform accepts your chosen TSA is that platform's decision.

## Operations notes

- Changing configuration means updating the parameters, redeploying and restarting the service. The VM reads the vault at every boot and keeps nothing on disk.
- Requests that time out are never resubmitted. Each request records its Artifact Signing operation ID for reconciliation.
- Disabling a key in Brigalow does not remove the Azure role assignment. Remove the assignment, or the profile, in Azure when retiring the key or responding to an incident.
- The VM is inside the signing boundary: anything on it that can reach `169.254.169.254` can obtain the identity's tokens. Do not run other workloads on it. Keep `enableSsh = false` except for time-boxed work, and prefer Run Command.
- Back up PostgreSQL and the external audit head as described in [operations](../../docs/operations.md). Purge protection means a deleted vault keeps its name reserved for the retention period.
- This reference has no signed audit checkpoints. They need a dedicated PKCS#11 audit key, and this template configures no HSM. `brig audit verify` on an export checks chain integrity only. Plan an off-host copy of exports, and an HSM-backed checkpoint key if you need authenticated checkpoints.
- PostgreSQL TLS uses `verify-full` (certificate and hostname) with no fallback, against the VM's system CA bundle. Microsoft notes that full hostname verification may not be possible with some private endpoint or VNet-integration DNS setups. This template's private DNS zone has not been tested against a real server. If connections fail on hostname verification, fix DNS so the server's FQDN resolves privately; do not weaken the TLS mode.
- Endpoint host: Microsoft's quickstart and region table use `https://<region>.codesigning.azure.net`, which is what Brigalow accepts. Microsoft's `Az.ArtifactSigning` cmdlet reference also shows `https://<region>.artifactsigning.azure.net`. Brigalow refuses that host. It will not be allowed until Microsoft documents it as a supported signing data plane. Keep `signingEndpoint` on `codesigning.azure.net`. Pass that same endpoint to the cmdlets, as Microsoft's CI policy how-to does.
