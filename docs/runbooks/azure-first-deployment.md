# Runbook: first Azure deployment with Artifact Signing

> **Status: not yet exercised against real Azure (13-11-2026).** This runbook is built from the repository's Bicep, cloud-init and docs, and from Microsoft Learn pages read on 13-11-2026 (see [References](#references)). Nobody has run it end to end. Expect to correct it on the first run. Record every difference you find.

This is the operator procedure for the first real deployment of [`deploy/azure`](../../deploy/azure/README.md). It puts in order, and expands, the steps already written in that README, the [backend guide](../integrations/azure-artifact-signing.md) and the [production reference](../../deploy/production/README.md). If this runbook and those documents disagree, stop and resolve the difference before you continue. The disagreements found while writing it are listed in [Known gaps in the reference](#known-gaps-in-the-reference).

End state: one VM running Brigalow in production mode with the restricted `brigalow_runtime` database login, one Artifact Signing certificate profile pinned by root and EKU, and one **test-purpose** detached CMS signature verified with OpenSSL on a machine other than the VM.

Brigalow makes no public-trust, platform-acceptance or compliance claim for this deployment or anything it signs. See [Trust statement](#trust-statement).

## How to use this runbook

- Work top to bottom. Tick a box only when its **Expect** line holds.
- Each step has **Do**, **Expect** and **If it fails**. If a failure is not covered, stop. Do not improvise around a guard.
- Keep a private evidence folder outside the repository. Steps say what to save there.
- Placeholders: `<resource-group>`, `<region>`, `<region-code>`, `<subscription-id>`, `<tenant-id>`, `<operator-rg>`, `<operator-vault>`, `<prefix>`, `<host>` (the hostname in `publicUrl`), `<org>`, `<project>`, `<key>`, `<image>` (`registry/brigalow@sha256:<digest>`), `<date>` (DD-MM-YYYY). Portal labels are quoted exactly as Microsoft shows them.

### Secret handling rules (apply to every step)

```sh
mkdir -m 0700 -p ~/brigalow-work ~/brigalow-evidence/<date>
cd ~/brigalow-work
umask 077   # every file created in this shell is 0600
```

- Generate secrets straight into files. Never type or paste a secret value as a command argument, an environment assignment or a heredoc.
- If you must enter a value by hand, read it without echo: `read -rs NAME && export NAME`, then `unset NAME` when done.
- To paste a value into a prompt (psql `\password`), copy it with `pbcopy < file` and clear the clipboard afterwards with `pbcopy < /dev/null`.
- Never print a secret in a Run Command script or its output. Azure keeps Run Command output.
- Commands that return secret values by default (for example `az keyvault secret set`) are run here with `--query id`, so the value is never printed.
- Delete working copies when the step that needed them is done.

## Phase map

| Phase | Outcome | Redeploy? |
| --- | --- | --- |
| [0. Before you start](#0-before-you-start) | Costs, eligibility and inputs confirmed. Go/no-go signed off. | |
| [1. Identity validation](#1-identity-validation-and-identityvalidationid) | `identityValidationId` captured | |
| [2. Secrets and parameters](#2-operator-vault-secrets-and-mainbicepparam) | Operator vault filled, `main.bicepparam` written | |
| [3. What-if and deploy](#3-what-if-and-first-deploy) | Resources created, outputs saved, DNS pointed | first deploy |
| [4. First boot](#4-vm-first-boot-and-key-vault-access) | Key Vault read on the VM confirmed | |
| [5. Database bootstrap](#5-database-bootstrap-with-the-restricted-runtime-login) | Migrations, `brigalow_runtime`, organisation | |
| [6. Health over HTTPS](#6-health-endpoint-and-sign-in-over-https) | `/healthz` ok, staff sign-in works | |
| [7. Root and EKU pinning](#7-root-certificate-and-eku-pinning) | Root DER and profile EKU reviewed out of band | |
| [8. Binding redeploy](#8-project-key-binding-and-redeploy) | Test-purpose binding live, SSH closed | second deploy |
| [9. First signing](#9-first-test-purpose-signing-request) | One CMS signature | |
| [10. Independent verification](#10-independent-verification-with-openssl) | OpenSSL verifies against the pinned root | |
| [11. Close out](#11-close-out) | Temporary access removed, evidence filed | |

---

## 0. Before you start

### 0.1 Costs

Deploying creates billable resources. Use the Azure pricing calculator for your region before you start. Do not rely on the dated figures below.

| Resource (from the Bicep) | Billing note |
| --- | --- |
| Artifact Signing account (`signingSku`, default `Basic`) | Microsoft's pricing FAQ (13-11-2026): billing starts when the account is created, is not pro rata, and each invoice is for the full SKU amount. Basic includes 5,000 signatures a month and 1 of each certificate profile type. Premium includes 100,000 and 10 of each. The repository's evidence register recorded US$9.99 (Basic) and US$99.99 (Premium) a month on 11-11-2026. The pricing page did not render amounts on 13-11-2026, so check it. |
| VM `Standard_D2s_v5` with a `Premium_LRS` OS disk | Compute while running, disk while it exists |
| Standard static public IP | While it exists |
| PostgreSQL Flexible Server `Standard_B1ms`, 32 GiB, 14-day backups | Compute, storage and backup storage |
| Key Vault (standard), private endpoint, two private DNS zones | Operations, endpoint hours and data, zones and queries |
| Temporary admin VM (phase 5) | While it exists. Delete it the same day. |

A soft-deleted Key Vault is not billed for storage, according to Microsoft. Purge and recover operations are billed.

### 0.2 Eligibility and region

Microsoft decides identity validation. As read on 13-11-2026:

- **Public Trust:** available to organisations in the United States, Canada, the EU, the UK, **Australia**, New Zealand, Japan, South Korea, Singapore, Switzerland, Norway and Israel. Individual developers must be in the United States or Canada.
- **Private Trust:** private identity validation is for organisations only. The geographic restrictions do not apply.
- **An Australian individual cannot complete either path. That is a no-go.**
- The profile type must match the validation type. **Private** validation covers `PrivateTrust` and `PrivateTrustCIPolicy`. **Public** validation covers `PublicTrust`, `PublicTrustTest` and `VBSEnclave`.
- For this first deployment use `PrivateTrust` (the template example) or `PublicTrustTest`. **Do not use `PrivateTrustCIPolicy`.** Microsoft documents that its certificates carry no code-signing EKU. Brigalow requires code signing on every leaf, so every request would fail closed.
- Public identity validation takes 1 to 20 business days, according to Microsoft. Private validation time is not stated. Allow days.
- **Region:** Artifact Signing is available only in these regions (endpoint code in brackets): Brazil South (`brs`), Central US (`cus`), East US (`eus`), Japan East (`jpe`), Korea Central (`krc`), North Central US (`ncus`), North Europe (`neu`), Poland Central (`plc`), South Central US (`scus`), Switzerland North (`swn`), West Central US (`wcus`), West Europe (`weu`), West US (`wus`), West US 2 (`wus2`) and West US 3 (`wus3`). None is in Australia. The template puts **every** resource (VM, PostgreSQL, Key Vault) in the resource group's region, so your data lives there too. Decide whether that is acceptable.

### 0.3 What you must already have

- [ ] **Subscription access.** Owner on the target resource group, or Contributor plus Role Based Access Control Administrator. The template creates role assignments, which plain Contributor cannot do. You also need Reader at subscription scope for the Identity Verifier role (1.4).
- [ ] **Operator Key Vault** (`<operator-vault>` in `<operator-rg>`) that you control, separate from the vault the template creates. It needs `enabledForTemplateDeployment = true`, and your deploying identity needs `Microsoft.KeyVault/vaults/deploy/action` on it (Owner or Contributor on the vault grants it). You must also be able to write secrets to it.
- [ ] **Reviewed production image pinned by digest**: `<image>`, built from the root `Dockerfile` `production` target, scanned, at the commit you will deploy. The VM must be able to pull it **without credentials**. The boot path has no registry login (see [Known gaps](#known-gaps-in-the-reference)).
- [ ] **TLS certificate chain and private key** (PEM) for `<host>`, valid for the whole trial. Port 80 is never open, so an ACME HTTP-01 challenge cannot work. Obtain the certificate first, for example by DNS-01.
- [ ] **Control of DNS** for `<host>`. You create an A record after the first deploy.
- [ ] **Staff OIDC provider**: a public client with S256 PKCE, able to emit group claims ([identity setup](../development.md#identity-setup-phase-1)). You need two test accounts. User A is in an `org_admin` group only. User B is in a `key_custodian` group only. Brigalow refuses API token issuance by anyone holding `key_custodian`, and refuses submission by custodians.
- [ ] **Your egress IP** as a single `/32`. The template takes one `httpsSourceCidr` and one `sshSourceCidr`.
- [ ] **An SSH key pair** for the VM admin user and the temporary admin VM.
- [ ] **Tools on your workstation:** a recent Azure CLI with Bicep (`az bicep version`), PowerShell 7 with `Az.Accounts` and `Az.ArtifactSigning` (7.2), **OpenSSL 3** (`openssl version` must print `OpenSSL 3.`; the macOS system `openssl` is LibreSSL and is not suitable), curl 7.55 or later, `jq`, `uuidgen`, and either a `brig` binary built from the same commit or Docker with a named context to run `brig` from `<image>`.
- [ ] **Budget approval and a teardown date.**

### 0.4 Go/no-go

Do not start phase 1 unless every line is yes.

- [ ] Eligibility confirmed for the validation type you will request (0.2), and the profile type matches it.
- [ ] Supported region chosen, and its data location accepted.
- [ ] Costs reviewed in the pricing calculator. You accept that the Artifact Signing account bills a full month as soon as it is created.
- [ ] Every item in 0.3 is in hand.
- [ ] You accept the first-deployment limits: no timestamps (`timestamp = "disabled"`), one VM with no HA, no signed audit checkpoints, and certificates that expire after 72 hours ([Limits](#timestamps-certificate-lifetime-and-topology-limits)).
- [ ] You have read [Rollback and teardown](#rollback-and-teardown), including the 90-day Key Vault name reservation.
- [ ] The repository commit to deploy is chosen, and you will deploy every later change from that same commit.

---

## 1. Identity validation and `identityValidationId`

Identity validation can only be completed in the Azure portal, under an Artifact Signing account. ARM cannot create it. Microsoft scopes a validation to the subscription and lets every Artifact Signing account in that subscription use it. This runbook creates the account in the portal under the exact name and resource group the template uses, so the template adopts it and you pay for one account.

- [ ] **1.1 Create the resource group in a supported region.**
  - Do: `az group create --name <resource-group> --location <region>`
  - Expect: `"provisioningState": "Succeeded"` and the region you chose.
  - If it fails: check that your role and subscription are selected (`az account show`).

- [ ] **1.2 Register the Artifact Signing resource provider.**
  - Do: `az provider register --namespace Microsoft.CodeSigning`, then `az provider show --namespace Microsoft.CodeSigning --query registrationState -o tsv`. In the portal the path is **Subscriptions** > your subscription > **Settings** > **Resource providers** > **Microsoft.CodeSigning** > **Register**.
  - Expect: `Registered`. Registration can take a few minutes.
  - If it fails: you need registration rights on the subscription. The other providers the template uses (Compute, Network, KeyVault, DBforPostgreSQL, ManagedIdentity) are normally registered already. Check them the same way if the deployment reports an unregistered namespace.

- [ ] **1.3 Create the Artifact Signing account in the portal. Billing starts here.**
  - Do: search for **Artifact Signing Accounts** > **Create**. Set **Subscription**. Set **Resource group** to `<resource-group>`. Set **Account name** to the value you will use for `signingAccountName` (3 to 24 alphanumeric characters, globally unique, starting with a letter, not starting with "one"). Set **Region** to the resource group's region and **Pricing** to your `signingSku`. Then **Review + Create**.
  - Expect: the account exists in `<resource-group>`.
  - If it fails: the name is taken globally, or the region is unsupported. Choose another name and use it consistently.

- [ ] **1.4 Give yourself the Artifact Signing Identity Verifier role.** Owner does not include it.
  - Do: on the account, **Access Control (IAM)** > **Add** > **Add role assignment** > **Artifact Signing Identity Verifier** > yourself. Microsoft notes that this role also needs at least Reader at subscription scope.
  - Expect: the assignment is listed. Role changes can take up to 10 minutes. Sign out and in again to refresh.
  - If it fails: if the **New identity** button stays dimmed, the role is not yet effective or is missing.

- [ ] **1.5 Submit the identity validation.**
  - Do: on the account **Overview**, or under **Objects**, open **Identity validations** > **Organization** > **New Identity**. Choose **Private** (for `PrivateTrust`) or **Public** (for `PublicTrust`/`PublicTrustTest`). Fill in **New organization validation** exactly as your legal records show. Check **Certificate subject preview**, then select **Create**.
  - Expect: status **In Progress**.
  - If it fails: the form rejects fields. Read Microsoft's field table in the quickstart. Details cannot be edited after creation. A correction needs a new request.

- [ ] **1.6 Wait for completion and act on requests.**
  - Do: watch the primary email and the portal. On **Action Required**, follow Microsoft's link: individual verification of the named representative, or a document upload (three attempts).
  - Expect: status **Completed**.
  - If it fails: on **Failed**, read Microsoft's email. A failed email verification needs a new request. Do not continue to phase 3 without **Completed**.

- [ ] **1.7 Capture the ID.**
  - Do: **Identity validations** > select the entity > copy **Identity validation Id**. Save it in `~/brigalow-evidence/<date>/identity-validation.txt`. It is not a secret, but keep it private.
  - Expect: a GUID.

---

## 2. Operator vault, secrets and `main.bicepparam`

Secrets reach the template only as `az.getSecret` references to your operator vault. The parameter file holds no secret values and is git-ignored.

- [ ] **2.1 Prepare the operator vault.**
  - Do: `az keyvault update --name <operator-vault> --enabled-for-template-deployment true --query properties.enabledForTemplateDeployment -o tsv`
  - Expect: `true`. Also confirm you hold Owner or Contributor on the vault, which grants `Microsoft.KeyVault/vaults/deploy/action`.
  - If it fails: without both settings, the deployment fails before creating anything ([README prerequisite 5](../../deploy/azure/README.md#prerequisites)).

- [ ] **2.2 Generate secrets into files with no trailing newline.** A trailing newline would become part of the PostgreSQL administrator password set through ARM. Brigalow strips one newline when it reads a password file, so the two would no longer match.
  - Do (in `~/brigalow-work`, with `umask 077`):

    ```sh
    openssl rand -base64 32 | tr -d '\n' > login-state-key     # 32 random bytes, as Brigalow requires
    openssl rand -base64 36 | tr -d '\n' > pg-owner-password
    openssl rand -base64 36 | tr -d '\n' > pg-runtime-password
    # Copy your TLS material in as tls.crt (full chain, PEM) and tls.key (PEM).
    openssl x509 -in tls.crt -noout -subject -ext subjectAltName -enddate
    openssl x509 -in tls.crt -noout -pubkey | openssl dgst -sha256
    openssl pkey -in tls.key -pubout | openssl dgst -sha256
    ls -l
    ```

  - Expect: every file is `-rw-------`. The SAN includes `<host>`. The two public-key digests match.
  - If it fails: a digest mismatch means the key and certificate do not belong together. Fix that before continuing.

- [ ] **2.3 Store them in the operator vault without printing values.**
  - Do:

    ```sh
    for pair in brigalow-pg-owner-password:pg-owner-password \
                brigalow-pg-runtime-password:pg-runtime-password \
                brigalow-login-state-key:login-state-key \
                brigalow-tls-crt:tls.crt brigalow-tls-key:tls.key; do
      az keyvault secret set --vault-name <operator-vault> --name "${pair%%:*}" \
        --file "${pair#*:}" --query id -o tsv
    done
    ```

  - Expect: five secret IDs (URLs) and no values.
  - If it fails: you need secret write permission on the operator vault and network access to it. Keep `pg-owner-password` and `pg-runtime-password` locally until phase 5 is complete. Delete `login-state-key`, `tls.key` and `tls.crt` now.

- [ ] **2.4 Choose identifiers and register the OIDC client.**
  - Do: create the organisation UUID with `uuidgen | tr '[:upper:]' '[:lower:]'` and record it as `<org>`. At your IdP, register the exact redirect `https://<host>/auth/<org>/staff/callback` (where `staff` is the authority name in the example). Create the groups `brigalow-admins` (user A) and `brigalow-custodians` (user B).
  - Expect: the IdP shows the redirect, and the groups are released in the ID token.

- [ ] **2.5 Write `main.bicepparam`.**
  - Do: `cp deploy/azure/main.bicepparam.example deploy/azure/main.bicepparam && chmod 0600 deploy/azure/main.bicepparam`. Then replace every placeholder:

    | Parameter | Value for the first deployment |
    | --- | --- |
    | `prefix` | 3 to 12 lowercase characters. If an earlier trial in a resource group of the same name was deleted within 90 days, use a new prefix or resource group ([teardown](#rollback-and-teardown)). |
    | `image` | `<image>` (`@sha256:` plus 64 hex characters; the boot script refuses anything else) |
    | `httpsSourceCidr` | `<your-egress-ip>/32` |
    | `enableSsh`, `sshSourceCidr` | `true`, `'<your-egress-ip>/32'`. This allows the phase 5 bootstrap. You close SSH in phase 8. Add `param sshSourceCidr = ...`, because the example omits it. |
    | `sshPublicKey` | Your public key |
    | `publicUrl` | `https://<host>` with no trailing slash |
    | `orgId` | `<org>` |
    | `oidcAuthorities` | Your issuer, `jwks_url` and human settings. Add `'brigalow-custodians': 'key_custodian'` to `group_roles`. Leave `workloads: []`. |
    | `artifactSigningBindings`, `artifactSigningRootDerBase64` | `[]` and `'-'` (filled in phase 8) |
    | `signingAccountName` | The account name from 1.3 |
    | `certificateProfileName` | 5 to 100 characters, letters, digits and single hyphens |
    | `signingSku` | The pricing you chose in 1.3 |
    | `certificateProfileType` | `'PrivateTrust'` (or `'PublicTrustTest'` with a public validation) |
    | `identityValidationId` | The GUID from 1.7 |
    | `signingEndpoint` | `'https://<region-code>.codesigning.azure.net'` for the resource group's region (0.2). A mismatch gives 403 at signing. |
    | Five `az.getSecret(...)` lines | `'<subscription-id>', '<operator-rg>', '<operator-vault>', '<secret-name>'` with the names from 2.3 |

  - Expect: `git check-ignore -v deploy/azure/main.bicepparam` prints the `.gitignore` rule, and `git status --short deploy/azure` does not list the file. `grep -nE 'Password|loginStateKey|Pem' deploy/azure/main.bicepparam` shows only `az.getSecret` lines.
  - If it fails: if the file is not ignored, stop. Do not commit it.

- [ ] **2.6 Run the offline checks and pin the commit.** The VM's cloud-init (`customData`) embeds `compose.yml`, `nginx.conf`, `production.py` and the boot script. Azure does not allow `customData` to change on an existing VM, so every later redeploy must come from this same commit.
  - Do:

    ```sh
    az bicep build --file deploy/azure/main.bicep --stdout > /dev/null
    az bicep lint --file deploy/azure/main.bicep
    python3 deploy/azure/test_azure.py
    git rev-parse HEAD > ~/brigalow-evidence/<date>/commit.txt
    ```

  - Expect: no build errors, no lint errors, the tests pass, and the commit is recorded.

---

## 3. What-if and first deploy

- [ ] **3.1 Confirm the Azure context.**
  - Do: `az account show --query "{subscription:id, tenant:tenantId, user:user.name}" -o table`
  - Expect: the intended subscription and tenant. If not, use `az account set --subscription <subscription-id>`.

- [ ] **3.2 Run what-if and review it.**
  - Do:

    ```sh
    az deployment group what-if --resource-group <resource-group> --name brigalow-first-01 \
      --template-file deploy/azure/main.bicep --parameters deploy/azure/main.bicepparam \
      > ~/brigalow-evidence/<date>/what-if-01.txt
    ```

  - Expect: creates for the managed identity, VNet and three NSGs, PostgreSQL (server, two configurations, database, private DNS zone and link), the certificate profile and its role assignment, the Key Vault with eight secrets, its role assignment, private endpoint and DNS, the public IP, the NIC and the VM. The signing account from 1.3 shows as **Modify** or **NoChange**, not **Create**. Nothing is deleted. Secure values appear unevaluated, which is normal. Microsoft warns that what-if output can contain noise.
  - If it fails: a `getSecret` or Key Vault reference error means 2.1 or the secret names are wrong. `AuthorizationFailed` on `roleAssignments/write` means you lack the RBAC role from 0.3. If the signing account shows **Create**, the name or resource group differs from 1.3. Fix that, or you will pay for a second account.

- [ ] **3.3 Deploy.**
  - Do: run the same command as `az deployment group create ... --name brigalow-first-01 --confirm-with-what-if --query properties.provisioningState -o tsv`, and answer `y` only if the preview matches 3.2.
  - Expect: `Succeeded`. PostgreSQL alone can take many minutes.
  - If it fails: read the failing operation with `az deployment operation group list -g <resource-group> -n brigalow-first-01 --query "[?properties.provisioningState=='Failed'].properties.statusMessage"`. Common causes:
    - Identity validation not **Completed**, or the wrong type for the profile type.
    - Vault name conflict from a soft-deleted vault (change `prefix` or the resource group).
    - SKU or quota unavailable in the region (set `vmSize` or `postgresSkuName`, which `main.bicep` exposes).
    - Password complexity (regenerate in 2.2).

    The deployment is incremental. Rerunning after a fix is safe.

- [ ] **3.4 Save the outputs.**
  - Do: `az deployment group show -g <resource-group> -n brigalow-first-01 --query properties.outputs -o json > ~/brigalow-evidence/<date>/outputs-01.json`
  - Expect: `publicIpAddress`, `postgresFqdn`, `keyVaultName`, `managedIdentityClientId`, `signingAccountUri` and `certificateProfileId`. None is secret.

- [ ] **3.5 Point DNS at the VM.**
  - Do: create an A record from `<host>` to `publicIpAddress` at your DNS provider.
  - Expect: `dig +short <host>`, run against a resolver you trust, returns that IP.

---

## 4. VM first boot and Key Vault access

At every boot, `brigalow.service` runs `brigalow-boot.py` once. It retries Key Vault reads with backoff for at most 15 minutes, then fails with a fixed message. systemd caps the whole start at 30 minutes (`TimeoutStartSec=1800`, `Restart=no`), so a failed unit stays failed until you act. New role assignments can take up to 10 minutes to apply.

**Before bootstrap, the server is expected to fail.** The `brigalow_runtime` login does not exist yet, so the server exits with `database startup failed`. Compose may then fail to start the proxy, and the unit may show as failed. At this stage, check only that Key Vault materialisation worked.

- [ ] **4.1 Check the first boot** (wait about 10 minutes after 3.3).
  - Do (Run Command works whether or not SSH is open; output is capped at 4,096 bytes):

    ```sh
    az vm run-command invoke -g <resource-group> -n <prefix>-vm --command-id RunShellScript \
      --query 'value[0].message' -o tsv --scripts '
    cloud-init status --long | head -3
    systemctl show brigalow.service -p ActiveState -p Result
    journalctl -u brigalow.service -b --no-pager -o cat | tail -12
    ls -ln /run/brigalow/config /run/brigalow/tls
    docker --context default ps -a --format "{{.Names}} {{.Status}}"'
    ```

  - Expect:
    - There is no line `brigalow-boot: cannot materialise configuration from Key Vault (details withheld)`.
    - `/run/brigalow/config` holds `config.toml`, `db-ca.pem`, `db-password`, `identity.json` and `login-key`. Each is `-rw-------` and owned by UID 10001. There is no `artifact-signing-root.der` yet.
    - `/run/brigalow/tls` holds `tls.crt` and `tls.key`, owned by UID 101.
    - The server container is restarting or exited. `docker --context default logs --tail 5 <server-container>` shows `database startup failed`. That is expected.
  - If it fails:
    - **`cannot materialise` within the first 15 minutes:** wait. Role propagation is the usual cause.
    - **`cannot materialise` after the unit has failed:** do 4.2, check that the private endpoint resolves on the VM (`getent hosts <keyVaultName>.vault.azure.net` should return a `10.40.2.x` address), then run `systemctl restart brigalow.service` through Run Command. Each restart is one more bounded attempt.
    - **Other causes:** a non-digest image, or a login key that is not base64 of 32 bytes. The message is generic by design, so recheck 2.2 and the `image` parameter.
    - **`/run/brigalow` missing:** the unit never ran. Check `tail -30 /var/log/cloud-init-output.log`, which contains no secrets because cloud-init carries none.
    - **Serial console:** not available on this template. Boot diagnostics are off and there is no password user. Use Run Command or SSH.

- [ ] **4.2 Confirm least-privilege role assignments.**
  - Do:

    ```sh
    principal=$(az identity show -g <resource-group> -n <prefix>-id --query principalId -o tsv)
    az role assignment list --assignee "$principal" --all \
      --query "[].{role:roleDefinitionName, scope:scope}" -o table | tee ~/brigalow-evidence/<date>/mi-roles.txt
    ```

  - Expect: exactly two rows. **Key Vault Secrets User** at the Brigalow vault, and **Artifact Signing Certificate Profile Signer** at the certificate profile.
  - If it fails: a missing row means the deployment did not finish. Extra rows mean someone granted more than the reference intends. Remove them.

---

## 5. Database bootstrap with the restricted runtime login

This expands [README bootstrap](../../deploy/azure/README.md#bootstrap-separate-owner-step) and the [production reference](../../deploy/production/README.md#migrate-and-bootstrap-separately). The owner password never goes to the Brigalow VM, its vault or its configuration. Use a short-lived admin VM. It must sit in the **`vm` subnet**, because the database NSG admits port 5432 only from that subnet. It gets **no** managed identity.

- [ ] **5.1 Create the temporary admin VM.**
  - Do:

    ```sh
    az vm create -g <resource-group> -n <prefix>-admin --image Ubuntu2404 --size Standard_B1s \
      --vnet-name <prefix>-vnet --subnet vm --nsg "" --public-ip-sku Standard \
      --admin-username <admin-user> --ssh-key-values ~/.ssh/<key>.pub \
      --os-disk-delete-option Delete --nic-delete-option Delete \
      --query "{public:publicIpAddress, private:privateIpAddress}" -o table
    ```

    If the image alias is refused, find the current Ubuntu LTS alias with `az vm image list -o table`. `--nsg ""` keeps the subnet NSG in charge. SSH is allowed only from your `/32`.
  - Expect: a public and a private IP. You can connect with `ssh <admin-user>@<admin-public-ip>`.

- [ ] **5.2 Prepare the admin host.**
  - Do: on the workstation, run `scp -p ~/brigalow-work/pg-owner-password <admin-user>@<admin-public-ip>:`. Then on the admin host:

    ```sh
    sudo apt-get update && sudo apt-get install -y docker.io postgresql-client
    sudo install -d -m 0700 -o 10001 -g 10001 /run/brigalow-admin
    sudo install -m 0600 -o 10001 -g 10001 ~/pg-owner-password /run/brigalow-admin/owner-password && shred -u ~/pg-owner-password
    sudo install -m 0600 -o 10001 -g 10001 /etc/ssl/certs/ca-certificates.crt /run/brigalow-admin/db-ca.pem
    sudo tee /run/brigalow-admin/admin.toml > /dev/null <<'EOF'
    mode = "production"
    backend = "disabled"
    db_host = "<postgresFqdn>"
    db_port = 5432
    db_name = "brigalow"
    db_user = "brigalow_owner"
    db_ca_file = "/run/admin/db-ca.pem"
    db_password_file = "/run/admin/owner-password"
    EOF
    sudo chown 10001:10001 /run/brigalow-admin/admin.toml && sudo chmod 0600 /run/brigalow-admin/admin.toml
    admin() { sudo docker --context default run --rm --read-only --user 10001:10001 \
      -e BRIGALOW_CONFIG=/run/admin/admin.toml -v /run/brigalow-admin:/run/admin:ro \
      --entrypoint brigalow-admin <image> "$@"; }
    ```

    `db_user` is your `postgresAdministratorLogin`. `/run` is tmpfs, so these files vanish on reboot.
  - Expect: `sudo ls -ln /run/brigalow-admin` shows three `-rw-------` files owned by 10001.
  - If it fails: if the image pull fails, the admin VM cannot reach your registry. Fix egress first.

- [ ] **5.3 Check the owner role.**
  - Do: `psql "host=<postgresFqdn> port=5432 dbname=brigalow user=brigalow_owner sslmode=verify-full sslrootcert=/etc/ssl/certs/ca-certificates.crt"`. At the password prompt, paste the value (`pbcopy < ~/brigalow-work/pg-owner-password` on the workstation). Then run `SELECT rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = current_user;`
  - Expect: `t | t`.
  - If it fails:
    - **TLS error:** Microsoft lists DigiCert Global Root G2 and Microsoft RSA Root CA 2017 as the current roots. Check with `openssl s_client -starttls postgres -connect <postgresFqdn>:5432 -CAfile /etc/ssl/certs/ca-certificates.crt`.
    - **`rolbypassrls` is `f`:** stop. Follow Microsoft's guidance for your server version, as the README says. Do not weaken Brigalow's checks.

- [ ] **5.4 Apply migrations.**
  - Do: `admin migrate`
  - Expect: `Operator operation completed`. Repeating it is safe.
  - If it fails: the fixed message names credentials, TLS, schema or arguments. Recheck 5.2 (newline in the password file, CA, hostname).

- [ ] **5.5 Create the restricted runtime login.** Set the password with `\password`. psql sends a SCRAM verifier, so the plaintext never reaches the server or its logs.
  - Do, in the owner psql session:

    ```sql
    CREATE ROLE brigalow_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS IN ROLE brigalow_app;
    \password brigalow_runtime
    SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,
           pg_has_role('brigalow_runtime', 'brigalow_app', 'member') AS app_member
      FROM pg_roles WHERE rolname = 'brigalow_runtime';
    ```

    Paste the runtime password at both prompts (`pbcopy < ~/brigalow-work/pg-runtime-password`). It must equal the value stored as `brigalow-pg-runtime-password` in 2.3.
  - Expect: `f | f | f | f | f | t`. Then confirm the login works with `psql "host=<postgresFqdn> ... user=brigalow_runtime ..."` and `SELECT current_user;`.
  - If it fails: if the login check fails, the pasted value differs from the vault value. Repeat `\password` carefully. The server's startup check refuses any role that is a superuser, has BYPASSRLS, CREATEDB or CREATEROLE, owns Brigalow objects, or is not a member of `brigalow_app`.

- [ ] **5.6 Create the organisation.**
  - Do: `admin org-create --org <org> --name "<organisation name>"`
  - Expect: `Operator operation completed`. Repeating it with the same values does nothing.

- [ ] **5.7 Remove the admin host and the owner credential copies.**
  - Do: on the admin host, `sudo shred -u /run/brigalow-admin/owner-password && exit`. Then on the workstation:

    ```sh
    az vm delete -g <resource-group> -n <prefix>-admin --yes
    az network public-ip delete -g <resource-group> -n <prefix>-adminPublicIP
    az resource list -g <resource-group> --query "[?contains(name, 'admin')].{name:name, type:type}" -o table
    pbcopy < /dev/null
    ```

  - Expect: the last listing is empty. Keep the local `pg-owner-password` only if your process needs it, otherwise delete it. The operator vault keeps the authoritative copy.

- [ ] **5.8 Restart Brigalow.**
  - Do:

    ```sh
    az vm run-command invoke -g <resource-group> -n <prefix>-vm --command-id RunShellScript \
      --query 'value[0].message' -o tsv --scripts '
    systemctl restart brigalow.service
    systemctl show brigalow.service -p ActiveState -p Result
    docker --context default ps --format "{{.Names}} {{.Status}}"'
    ```

  - Expect: `ActiveState=active`, `Result=success`, and both containers up, with the server `(healthy)`.
  - If it fails: if the server log shows `database startup failed`, the cause is a runtime password mismatch, an unsafe role (5.5), a missing migration (5.4) or database TLS. Brigalow uses `verify-full` with no fallback. Microsoft notes that full verification may not work with some VNet-integration DNS setups. If you see that, report it. Do not weaken TLS.

---

## 6. Health endpoint and sign-in over HTTPS

- [ ] **6.1 Check TLS and health from your workstation.**
  - Do:

    ```sh
    openssl s_client -connect <host>:443 -servername <host> < /dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -enddate
    curl --fail-with-body -sS https://<host>/healthz | tee ~/brigalow-evidence/<date>/healthz-01.json
    ```

  - Expect: your certificate, and `{"status":"ok","mode":"production","signing_available":true}` (key order may differ). `/healthz` checks the database and that a managed-identity token can be fetched. It never signs, so it does not prove the signer role works.
  - If it fails:
    - **Timeout:** your IP is outside `httpsSourceCidr`, DNS is wrong, or the proxy is down (5.8).
    - **`unavailable` (503):** the database or IMDS token is failing. Read the server log tail.

- [ ] **6.2 Sign in as user A.**
  - Do: open `https://<host>/auth/<org>/staff/login`, complete the IdP login and select **Continue**.
  - Expect: `/orgs/<org>` shows a **Create project** form.
  - If it fails:
    - **IdP redirect error:** the callback in 2.4 is wrong.
    - **No access:** the group claim does not match `group_roles`.

---

## 7. Root certificate and EKU pinning

Brigalow validates every returned chain to **one** operator-pinned root, and requires the profile EKU in every leaf ([backend guide, Configuration](../integrations/azure-artifact-signing.md#configuration)). Get both through a channel independent of signing responses. A root copied from a returned bundle proves nothing on its own.

- [ ] **7.1 Grant yourself temporary signer access to the profile.** Microsoft's how-to lists **Artifact Signing Certificate Profile Signer** as a prerequisite for these cmdlets. While you hold it, you can sign with the profile, so record it and remove it in 7.6.
  - Do:

    ```sh
    me=$(az ad signed-in-user show --query id -o tsv)
    profile=$(jq -r .certificateProfileId.value ~/brigalow-evidence/<date>/outputs-01.json)
    az role assignment create --assignee-object-id "$me" --assignee-principal-type User \
      --role "Artifact Signing Certificate Profile Signer" --scope "$profile" --query id -o tsv \
      | tee ~/brigalow-evidence/<date>/temp-signer-assignment.txt
    ```

  - Expect: an assignment ID. Allow up to 10 minutes before 7.2.

- [ ] **7.2 Retrieve the root and EKU with Az.ArtifactSigning.** The module was renamed. The repository docs still use the older names `Az.CodeSigning`, `Get-AzCodeSigningRootCert` and `Get-AzCodeSigningCustomerEku`.
  - Do, in PowerShell 7:

    ```powershell
    Install-Module -Name Az.Accounts, Az.ArtifactSigning -Scope CurrentUser
    Get-Module -ListAvailable Az.ArtifactSigning | Select-Object Name, Version
    Connect-AzAccount -Tenant <tenant-id> -Subscription <subscription-id>
    $ep = 'https://<region-code>.codesigning.azure.net'
    Get-AzArtifactSigningCertificateRoot -AccountName <signingAccountName> -ProfileName <certificateProfileName> -EndpointUrl $ep -Destination "$HOME/brigalow-work/root.cer"
    Get-AzArtifactSigningCustomerEku -AccountName <signingAccountName> -ProfileName <certificateProfileName> -EndpointUrl $ep | Tee-Object "$HOME/brigalow-work/profile-eku.txt"
    ```

  - Expect: `root.cer` is written, and the command prints one OID beginning `1.3.6.1.4.1.311.97.`.
  - If it fails:
    - **`401 invalid_token`:** Azure PowerShell PR #30138 (merged 15-09-2026) fixed a malformed token audience in the module, and the PR names 0.2.1 as affected. Update to a release that includes it.
    - **403:** the role from 7.1 is not effective yet. Wait, then reconnect.
    - **Endpoint refused:** the cmdlet reference examples use `https://<x>.artifactsigning.azure.net`, while the quickstart lists `codesigning.azure.net`. Try the other form for the cmdlet only. `signingEndpoint` must stay `codesigning.azure.net`, because the backend refuses any other host.
    - **Cmdlets will not run on macOS:** Microsoft's how-to lists Azure PowerShell on Windows. Use a Windows host you control.

- [ ] **7.3 Normalise the root to DER and inspect it.**
  - Do (OpenSSL 3, in `~/brigalow-work`):

    ```sh
    if openssl x509 -in root.cer -noout 2>/dev/null; then fmt=PEM; else fmt=DER; fi
    openssl x509 -inform "$fmt" -in root.cer -outform DER -out root.der
    openssl x509 -inform DER -in root.der -out root.pem
    openssl x509 -in root.pem -noout -subject -issuer -dates -ext basicConstraints,keyUsage
    openssl x509 -in root.pem -noout -fingerprint -sha256
    openssl x509 -in root.pem -noout -fingerprint -sha1
    openssl verify -CAfile root.pem root.pem
    ```

  - Expect: subject equals issuer, a Microsoft subject, `CA:TRUE`, certificate signing in key usage, currently valid, and `root.pem: OK`.
  - If it fails: if the file is not a single self-signed CA certificate, stop. Do not pin an intermediate.

- [ ] **7.4 Verify the root out of band.**
  - Do, for Public Trust profile types: download Microsoft's published root from `https://www.microsoft.com/pkiops/certs/microsoft%20identity%20verification%20root%20certificate%20authority%202020.crt`. Normalise it as in 7.3. Compare its SHA-1 with the value you read yourself in the [Microsoft PKI repository](https://www.microsoft.com/pkiops/docs/repository.htm) table, and `cmp` its DER with `root.der`. As read on 13-11-2026, the repository lists SHA-1 `f40042e2e5f7e8ef8189fed15519aece42c3bfa2` for "Microsoft Identity Verification Root Certificate Authority 2020". Use your own reading, not this copy.
  - Do, for Private Trust: Microsoft states that the Private Trust CA hierarchy is not default-trusted in any root program. No published Private Trust root fingerprint was found on 13-11-2026. Repeat 7.2 and 7.3 from a second machine on a different network, with a separate sign-in session, and compare the SHA-256 fingerprints. If the subject is the 2020 Identity Verification root, also compare it with the repository value. Check Microsoft's current docs for published Private Trust material. Record that pinning rests on two independent authenticated retrievals.
  - Expect: identical DER from both sources.
  - If it fails: on any mismatch, stop. Do not pin.

- [ ] **7.5 Check the EKU.**
  - Do: read `profile-eku.txt`.
  - Expect:
    - It is a canonical OID (no empty arcs, no leading zeros, at most 128 characters) beginning `1.3.6.1.4.1.311.97.` with further arcs.
    - For `PrivateTrust` it begins `1.3.6.1.4.1.311.97.1.3.1.`. Microsoft describes that suffix as unique to the identity validation.
    - For Public Trust it is `1.3.6.1.4.1.311.97.` followed by profile-specific arcs.
    - A second retrieval from 7.4's second machine gives the same value. If the portal shows the EKU for the profile or its certificates, compare it too. That display is unconfirmed, so check the current portal.
  - If it fails: never pin a shared identifier. The backend refuses them at startup and the server will not start:
    - `1.3.6.1.4.1.311.97.1.0` (on every Public Trust certificate)
    - `1.3.6.1.4.1.311.97.1.3.1` (the Private Trust type prefix)
    - `1.3.6.1.4.1.311.97.1.4.1` (the CI policy type prefix)
    - `1.3.6.1.5.5.7.3.3` (code signing)

    A value under `.1.4.1.` means a CI policy profile, which cannot work (0.2).

- [ ] **7.6 Remove the temporary signer access.**
  - Do: `az role assignment delete --ids "$(cat ~/brigalow-evidence/<date>/temp-signer-assignment.txt)"`, then `az role assignment list --assignee "$me" --scope "$profile" -o table`.
  - Expect: an empty list.

- [ ] **7.7 Record the pin.** Save to evidence: `root.der`, its SHA-256 and SHA-1, subject and notAfter, each source and method, the EKU and how it was cross-checked, the module version, the date and your name.

---

## 8. Project, key binding and redeploy

- [ ] **8.1 Create the project as user A.**
  - Do: on `/orgs/<org>`, use **Create project**.
  - Expect: you are redirected to `/orgs/<org>/projects/<project>`. Record `<project>` from the URL.

- [ ] **8.2 Choose the key UUID.**
  - Do: `uuidgen | tr '[:upper:]' '[:lower:]'` and record it as `<key>`.

- [ ] **8.3 Update the parameters.**
  - Do: copy the current file to `~/brigalow-evidence/<date>/main.bicepparam.01`. Then set:

    ```bicep
    param enableSsh = false
    param artifactSigningRootDerBase64 = '<single line from: openssl base64 -A -in ~/brigalow-work/root.der>'
    param artifactSigningBindings = [
      {
        id: '<key>'
        org: '<org>'
        project: '<project>'
        purpose: 'test'
        account: '<signingAccountName>'
        profile: '<certificateProfileName>'
        profileEku: '<EKU from 7.5>'
      }
    ]
    ```

    The root is public. The binding's `account` and `profile` must equal `signingAccountName` and `certificateProfileName`.

- [ ] **8.4 Confirm the commit and run what-if.**
  - Do: `test "$(git rev-parse HEAD)" = "$(cat ~/brigalow-evidence/<date>/commit.txt)" && echo same-commit`. Then run the same what-if as 3.2 with `--name brigalow-first-02`, saved to `what-if-02.txt`.
  - Expect: `same-commit`. Changes to Key Vault secrets (`brigalow-config-toml` and `brigalow-artifact-signing-root`; other secrets may also show as changed because secure values are not evaluated) and to the VM NSG, where the SSH rule is removed. Do not rely on what-if to show a `customData` change. The commit check is the real control.
  - If it fails: on a different commit, stop. Check out the recorded commit and rerun. A deployment error mentioning `customData` (`PropertyChangeNotAllowed`) means the same thing.

- [ ] **8.5 Deploy and restart.**
  - Do: deploy as in 3.3 with `--name brigalow-first-02`. Then use Run Command to run `systemctl restart brigalow.service`, `systemctl show brigalow.service -p ActiveState -p Result` and `ls -ln /run/brigalow/config`. Then repeat 6.1.
  - Expect: the unit is active and successful, `artifact-signing-root.der` is present (0600, UID 10001), and `/healthz` is `ok`. SSH to the VM now times out.
  - If it fails: the server refuses to start with a fixed message:
    - `invalid Artifact Signing binding`: EKU format or shared EKU, account or profile name, or a root that does not parse as a CA.
    - `Artifact Signing anchor must name a trust anchor`: the root was left as `'-'`.
    - An endpoint error: `signingEndpoint` is not `https://<region-code>.codesigning.azure.net`.

    Fix the parameter and redeploy.

---

## 9. First test-purpose signing request

A test-purpose binding exercises the whole chain: managed identity, the Artifact Signing call, chain validation to the pinned root, the EKU check, signature verification and CMS assembly. It needs no CI workload rule and no release claims. The submitter is a short-lived API token issued by user A, scoped to one project and policy.

- [ ] **9.1 Capture session headers without shell history.**
  - Do: for each user, use a separate browser profile, because both use the `__Host-brigalow` cookie. Copy the `__Host-brigalow` cookie value from the browser's developer tools. Copy the hidden `csrf` input value from the page source of `/orgs/<org>`. Menu names differ by browser, so check yours. Then:

    ```sh
    cd ~/brigalow-work && umask 077
    cat > session-b.headers   # paste these three lines with B's values, then Ctrl-D
    # Cookie: __Host-brigalow=<value>
    # X-CSRF-Token: <value>
    # Origin: https://<host>
    ```

    Repeat for user A as `session-a.headers`. Leave out the `# ` prefixes when pasting.
  - Expect: two 0600 files.

- [ ] **9.2 Register and activate the key as user B (key custodian).**
  - Do:

    ```sh
    api=https://<host>/v1/orgs/<org>
    printf '{"remote_key":"%s","algorithm":"rsa3072","purpose":"test","offline":false}' '<key>' > key.json
    curl --fail-with-body -sS -H @session-b.headers -H 'Content-Type: application/json' \
      --data @key.json "$api/projects/<project>/keys" | tee ~/brigalow-evidence/<date>/key-registered.json
    curl --fail-with-body -sS -H @session-b.headers -H 'Content-Type: application/json' \
      --data '{}' "$api/keys/<key>/activate" | tee ~/brigalow-evidence/<date>/key-activated.json
    ```

  - Expect: the key reports `external-ca` trust with the anchor name, and an empty public key. Activation succeeds.
  - If it fails:
    - **404:** the org or project does not match the binding.
    - **403:** B lacks `key_custodian`, or the Origin or CSRF value is wrong.
    - **401:** the session expired. Sign in again and recapture.
    - **`untrusted`:** the anchor is not configured as `external-ca` (8.5).

- [ ] **9.3 Create the policy as user A.** The template cannot configure a TSA, so the policy must use `disabled` ([Limits](#timestamps-certificate-lifetime-and-topology-limits)).
  - Do:

    ```sh
    printf '{"name":"azure-first-test","key":"%s","purpose":"test","claims":{},"algorithms":["rsa3072"],"timestamp":"disabled"}' '<key>' > policy.json
    curl --fail-with-body -sS -H @session-a.headers -H 'Content-Type: application/json' \
      --data @policy.json "$api/projects/<project>/policies" | tee ~/brigalow-evidence/<date>/policy.json
    ```

  - Expect: the created policy with an `id`. Record it as `<policy-id>`.
  - If it fails: 422 with `timestamp: "required"` means no TSA is configured.

- [ ] **9.4 Issue a one-hour API token as user A.** The token is returned once. Never print it.
  - Do:

    ```sh
    exp=$(( $(date +%s) + 3600 ))
    printf '{"project":"%s","policy":"%s","expires_at":%d}' '<project>' '<policy-id>' "$exp" > token-request.json
    curl --fail-with-body -sS -H @session-a.headers -H 'Content-Type: application/json' \
      --data @token-request.json "$api/tokens" -o token.json
    jq -r .id token.json | tee ~/brigalow-evidence/<date>/token-id.txt
    ```

  - Expect: a token ID. `token.json` is 0600.
  - If it fails: 403 means user A also holds `key_custodian`.

- [ ] **9.5 Sign a test artefact.**
  - Do:

    ```sh
    head -c 4096 /dev/urandom > app.bin
    shasum -a 256 app.bin | tee ~/brigalow-evidence/<date>/app.bin.sha256
    export BRIGALOW_TOKEN="$(jq -r .token token.json)"
    brig sign --server https://<host> --org <org> --project <project> \
      --policy azure-first-test --format cms --output app.cms app.bin
    # Or from the reviewed image (add --platform linux/amd64 on Apple silicon if needed):
    # docker --context <context> run --rm --read-only --user "$(id -u):$(id -g)" -e BRIGALOW_TOKEN \
    #   -v "$PWD:/work" -w /work --entrypoint brig <image> sign --server https://<host> --org <org> \
    #   --project <project> --policy azure-first-test --format cms --output app.cms app.bin
    unset BRIGALOW_TOKEN
    ```

  - Expect: `Submitting request <request-id>`, then `Signed request <request-id>`. Record `<request-id>`.
  - If it fails:
    - **502:** Brigalow refused the result or the Azure call failed. Nothing is output, and the request is stored as failed with any operation ID received. Causes, most likely first:
      - The managed identity's signer role is not effective yet (Azure 403; wait up to 10 minutes and submit a **new** request).
      - The region does not match `signingEndpoint`.
      - The wrong EKU is pinned.
      - The chain does not reach the pinned root.
      - The leaf is not RSA-3072.

      Read the stored request with `curl -sS -H @session-a.headers "$api/requests/<request-id>"`.
    - **Timeout or interruption:** do not resubmit blindly. The operation may still complete at Microsoft. Check the request by ID and reconcile using the operation ID ([backend guide](../integrations/azure-artifact-signing.md#async-operation-timeouts-and-no-retry)).
    - **403 or 404 from Brigalow:** the token scope or policy name is wrong.

- [ ] **9.6 Revoke the token.**
  - Do: `curl --fail-with-body -sS -X DELETE -H @session-a.headers "$api/tokens/$(cat ~/brigalow-evidence/<date>/token-id.txt)" && rm -P token.json`
  - Expect: success. A later `brig` call with that token returns 401.

---

## 10. Independent verification with OpenSSL

Verify on your workstation, not on the VM, against the root pinned in phase 7. Do it within 72 hours of signing. There is no timestamp, so the signature fails ordinary verification once the certificate expires.

- [ ] **10.1 Verify the CMS against the pinned root.**
  - Do:

    ```sh
    openssl version
    openssl cms -verify -binary -inform DER -in app.cms -content app.bin \
      -CAfile root.pem -purpose any -signer signer.pem -out /dev/null
    ```

  - Expect: `OpenSSL 3...` and `CMS Verification successful`. `-purpose any` stops OpenSSL requiring an S/MIME purpose on a code-signing certificate.
  - If it fails: stop and keep every file. A Brigalow output that does not verify against its pinned root is an incident.

- [ ] **10.2 Confirm that tampering is detected.**
  - Do: `cp app.bin tampered.bin && printf x >> tampered.bin`, then rerun 10.1 with `-content tampered.bin`.
  - Expect: verification **fails**.

- [ ] **10.3 Inspect the signing certificate.**
  - Do:

    ```sh
    openssl x509 -in signer.pem -noout -subject -issuer -dates -ext extendedKeyUsage,basicConstraints
    openssl x509 -in signer.pem -noout -text | grep -m1 'Public-Key'
    openssl x509 -in signer.pem -outform DER | openssl dgst -sha256
    openssl x509 -in signer.pem -noout -fingerprint -sha1
    ```

  - Expect:
    - The EKU list includes Code Signing and your pinned profile EKU. OpenSSL prints unknown OIDs numerically.
    - `CA:FALSE`.
    - `Public-Key: (3072 bit)`.
    - `notBefore` and `notAfter` are about 72 hours apart.

- [ ] **10.4 Cross-check with Brigalow's record and with Azure.**
  - Do: `curl -sS -H @session-a.headers "$api/requests/<request-id>" | jq '.. | .remote? // empty | {operation_id, certificate_sha256}'`. Then, in the portal, find the certificates listed for the profile. Microsoft documents a portal log of issued certificates with serial and thumbprint, but the path is not confirmed, so check the current portal.
  - Expect: `certificate_sha256` equals the SHA-256 from 10.3. The portal shows a certificate whose thumbprint matches the SHA-1 from 10.3. Record the `operation_id`.

---

## 11. Close out

- [ ] Delete `session-a.headers`, `session-b.headers`, `key.json`, `policy.json` and `token-request.json`. Sign both users out.
- [ ] Delete any remaining local secret files (`pg-owner-password`, `pg-runtime-password`). The operator vault holds the copies.
- [ ] Confirm the state: SSH closed (8.5), admin VM gone (5.7), temporary signer role gone (7.6), managed identity holding exactly two roles (rerun 4.2).
- [ ] File the evidence ([Evidence to keep](#evidence-to-keep)).
- [ ] Decide whether to keep running or tear down, and record the teardown date. The account bills monthly regardless.
- [ ] Before any release-purpose work, read [README first project](../../deploy/azure/README.md#first-project-key-registration-and-signing) and the [known gaps](#known-gaps-in-the-reference). Release needs a GitHub workload rule, and the single `httpsSourceCidr` cannot admit GitHub-hosted runners.

---

## Timestamps, certificate lifetime and topology limits

- **Timestamps:** Microsoft's TSA is `http://timestamp.acs.microsoft.com`, which is HTTP only, and Microsoft recommends it. Brigalow accepts only HTTPS TSAs and does not change that for this backend. You have two options: configure an HTTPS RFC 3161 TSA you trust (`[tsa]` with a pinned signer), or knowingly set the policy timestamp to `disabled` and timestamp separately with a tool you trust ([README, Timestamps](../../deploy/azure/README.md#timestamps)). **This template has no way to add `[tsa]`.** `config.toml` is generated in `main.bicep`, and the boot script writes no TSA files. Until that changes, `disabled` is the only option on this reference.
- **72-hour certificates:** Microsoft renews certificates daily, and each is valid for 72 hours. Without a trusted timestamp, verifiers that check validity at verification time reject the signature after the certificate expires, usually within three days of signing ([backend guide](../integrations/azure-artifact-signing.md#timestamping-and-the-72-hour-certificate)).
- **Single VM, no HA:** one VM, one server process, one proxy. No scale set, no failover, and no zone redundancy for PostgreSQL. A VM or region outage stops signing.
- **Signing boundary:** anything on the VM that can reach `169.254.169.254` can mint tokens for the managed identity. Run nothing else on it.
- **No signed audit checkpoints:** `brigalow-audit checkpoint` requires a PKCS#11 audit key, and this reference has no HSM. The audit chain exists only in the PostgreSQL database and its Azure backups.
- **Preview API:** the Artifact Signing data-plane API Brigalow calls (`2022-06-15-preview`) is a preview.

## Rollback and teardown

Choose the smallest action that fits.

1. **Stop signing now.** Removing the role takes effect within about 10 minutes, so also stop the service if you need an immediate stop.
   - Remove the managed identity's signer role with `az role assignment delete --assignee "$principal" --role "Artifact Signing Certificate Profile Signer" --scope "$profile"`.
   - Stop the service with Run Command `systemctl stop brigalow.service`, or deallocate the VM with `az vm deallocate -g <resource-group> -n <prefix>-vm`.

   Disabling the key in Brigalow is permanent and does not remove the Azure role. If misuse is suspected, check the current portal for certificate revocation under the profile.
2. **Roll back configuration.** Restore the previous `main.bicepparam.NN` from evidence, run what-if (no `customData` change), deploy, then restart the service. Every change needs a redeploy and a restart, because the VM reads the vault at each boot and keeps nothing on disk.
3. **Tear down.** Work through these in order:
   - **Keep what you need first.** The audit chain and request records exist only in PostgreSQL. To keep them, take a `pg_dump` from a temporary admin VM (phase 5 pattern) into encrypted storage you control. Check Microsoft's current docs for how long backups of a deleted server are kept. Do not assume they are.
   - **Delete the resource group:** `az group delete --name <resource-group>`.
   - **Key Vault:** the vault is soft-deleted with **purge protection**. It cannot be purged until the 90-day retention ends. It cannot be recovered after that. Its name stays reserved. The template derives the vault name from the resource group ID, so redeploying into a resource group of the same name in the same subscription fails for 90 days. Use a new resource group name or `prefix`, or recover the vault with `az keyvault recover`. Microsoft notes that recovery does not restore role assignments, which a redeploy recreates. List soft-deleted vaults with `az keyvault list-deleted`. A soft-deleted vault is not billed except for purge and recover operations.
   - **Artifact Signing:** deleting the account deletes its profiles and stops signing. Billing is not refunded pro rata. The identity validation stays at subscription level. A recreated profile gets a new EKU, so pin it again.
   - **Outside the resource group:** delete or rotate the operator vault secrets (the database passwords become useless; decide about the TLS key). Remove the DNS record and the IdP client and groups. Remove any role assignments you created outside the resource group.
   - **Check for leftovers:** `az resource list -g <resource-group>` should fail because the group no longer exists. Then run `az keyvault list-deleted`.

## Evidence to keep

Store it outside the repository, private (0700), and keep no secret values in it.

- `commit.txt`, the image digest, both parameter files (`main.bicepparam.NN`), `what-if-01.txt`, `what-if-02.txt`, and the deployment names and outputs.
- The identity validation ID, completion date and type. The profile type, account and profile names, region and SKU.
- `mi-roles.txt`, plus the temporary signer assignment ID and its removal time.
- The run results of 4.1 and 5.8, and `healthz-01.json`.
- `root.der` with its SHA-256 and SHA-1, sources and method (7.4). The EKU, its sources, the module version and the date.
- The key registration and activation responses, `policy.json`, the token ID and its revocation time.
- `app.bin`, `app.bin.sha256`, `app.cms` and `signer.pem`. The OpenSSL output for 10.1 to 10.3. The request ID, the operation ID and the matching certificate SHA-256 values.
- Every deviation from this runbook, with date and fix.

## Trust statement

Brigalow makes no public-trust, platform-acceptance or compliance claim for this deployment or its signatures. The `external-ca` trust tier records only that an operator pinned an outside CA. Whether Windows or any other platform accepts a signature is decided by that platform and Microsoft's programmes, not by Brigalow ([trust tiers](../decisions/0003-trust-tiers.md)). Microsoft states that Private Trust hierarchies are not default-trusted in any root program, and that Public Trust Test certificates should not be trusted. Microsoft also states (13-11-2026) that the Artifact Signing code-signing CAs are scheduled for removal from the Common CA Database and are no longer in the Trusted Root Program, while remaining on the Windows Platform Trust List. Microsoft's FIPS statements describe Microsoft's modules and certify nothing about Brigalow.

## Known gaps in the reference

These came up while writing this runbook. Each is worked around above where possible. None has been fixed in the repository.

1. **The root/EKU cmdlet names in the repository docs are out of date.** The README and the backend guide name `Az.CodeSigning`, `Get-AzCodeSigningRootCert` and `Get-AzCodeSigningCustomerEku`. The current module is `Az.ArtifactSigning`, with `Get-AzArtifactSigningCertificateRoot` and `Get-AzArtifactSigningCustomerEku`. Neither doc mentions that the operator needs a temporary Certificate Profile Signer role to run them.
2. **Private Trust EKU semantics.** The backend guide calls the EKU profile-specific. Microsoft's certificate management page says that for Private Trust the suffix is unique to the **identity validation**. On the same page it also says a recreated profile gets a new EKU. Microsoft's docs are inconsistent here. Brigalow's binding also pins the account, profile and root, but the "profile-specific" wording does not hold for Private Trust.
3. **`PrivateTrustCIPolicy` cannot work.** Microsoft documents that it has no code-signing EKU, and Brigalow requires one, yet the Bicep `@allowed` list includes it.
4. **The README says identity validation may need repeating** under the template's account. Microsoft scopes validations to the subscription and shares them across accounts. The README also omits the Identity Verifier role, the Private/Public choice, and the need to create an account in the portal first, which starts billing.
5. **`Microsoft.CodeSigning` provider registration** is missing from the README prerequisites.
6. **The README says `/healthz` is ready after the first boot.** In fact the server cannot start until bootstrap creates `brigalow_runtime`, so the first boot is expected to show a failed server.
7. **The bootstrap host must be in the `vm` subnet**, because the database NSG admits only that subnet. The README says only "a jump host in the VNet". The README and `main.bicep` suggest Azure Bastion or the serial console, but the VNet has no `AzureBastionSubnet`, port 22 is closed unless `enableSsh` is set, and the serial console needs boot diagnostics and a password user, which the VM has neither of.
8. **No TSA path in the template.** The README says to configure `[tsa]` in `config.toml`, but `config.toml` is generated by `main.bicep` with no TSA parameter, and the boot script writes no TSA files.
9. **No private registry support.** The boot path has no registry login, so `<image>` must be pullable anonymously from the VM.
10. **`customData` is immutable** on an existing VM, and the README does not mention it. Redeploying from a commit that changed any embedded file fails.
11. **One CIDR each** for HTTPS and SSH. The example comment calls the HTTPS placeholder an RFC 5737 range, but it is a plain placeholder string. GitHub-hosted runners cannot be admitted with one CIDR.
12. **No signed audit checkpoints** on this reference (no PKCS#11 audit key), which [operations](../operations.md) does not say for Azure.
13. **Endpoint host drift.** Microsoft's cmdlet reference uses `*.artifactsigning.azure.net`, while the quickstart and Brigalow use `*.codesigning.azure.net`. If Microsoft moves the data plane, Brigalow's endpoint check will refuse the new host.
14. **PostgreSQL TLS.** Microsoft notes that full hostname verification may not be possible with some VNet-integration DNS setups. Brigalow requires `verify-full` with no fallback. Untested here.

## References

Microsoft Learn and Microsoft pages, read 13-11-2026:

- Quickstart: set up Artifact Signing (provider registration, regions and endpoints, account naming, identity validation steps and fields, eligibility, profile types, cleanup): <https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart>
- Assign roles in Artifact Signing (Identity Verifier, Certificate Profile Signer, portal path, profile-scope assignment): <https://learn.microsoft.com/en-us/azure/artifact-signing/tutorial-assign-roles>
- Artifact Signing certificate management (72-hour certificates, EKU structure, shared EKUs, recreated profiles, TSA, CCADB note): <https://learn.microsoft.com/en-us/azure/artifact-signing/concept-certificate-management>
- Artifact Signing trust models (Public Trust root, Private Trust not default-trusted, Public Trust Test): <https://learn.microsoft.com/en-us/azure/artifact-signing/concept-trust-models>
- Sign a CI policy (root and EKU cmdlets, prerequisites): <https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-sign-ci-policy>
- `Get-AzArtifactSigningCertificateRoot`: <https://learn.microsoft.com/en-us/powershell/module/az.artifactsigning/get-azartifactsigningcertificateroot>
- `Get-AzArtifactSigningCertificateChain`: <https://learn.microsoft.com/en-us/powershell/module/az.artifactsigning/get-azartifactsigningcertificatechain>
- `Get-AzArtifactSigningCustomerEku`: <https://learn.microsoft.com/en-us/powershell/module/az.artifactsigning/get-azartifactsigningcustomereku>
- Azure PowerShell PR #30138 (Az.ArtifactSigning token audience fix): <https://github.com/Azure/azure-powershell/pull/30138>
- Microsoft PKI Services repository (Identity Verification Root CA 2020 download and SHA-1): <https://www.microsoft.com/pkiops/docs/repository.htm>
- Artifact Signing pricing and billing FAQ: <https://azure.microsoft.com/en-us/pricing/details/artifact-signing/>
- Key Vault secrets as Bicep parameters (`enabledForTemplateDeployment`, `deploy/action`, `az.getSecret`): <https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/key-vault-parameter>
- Bicep what-if: <https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/deploy-what-if>
- Troubleshoot Azure RBAC (up to 10 minutes for role changes): <https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting>
- Key Vault network security (control-plane secret deployment is not subject to the firewall): <https://learn.microsoft.com/en-us/azure/key-vault/general/network-security>
- Key Vault soft-delete and purge protection: <https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview>
- Custom data on Azure VMs (first boot only, not updatable on a single VM): <https://learn.microsoft.com/en-us/azure/virtual-machines/custom-data>
- Run Command on Linux VMs (limits, permissions): <https://learn.microsoft.com/en-us/azure/virtual-machines/linux/run-command>
- Serial console for Linux (prerequisites): <https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/linux/serial-console-linux>
- Azure Bastion portal quickstart (subnet, port 22, Developer SKU): <https://learn.microsoft.com/en-us/azure/bastion/quickstart-host-portal>
- TLS for Azure Database for PostgreSQL (root CAs, verification modes): <https://learn.microsoft.com/en-us/azure/postgresql/security/security-tls>
