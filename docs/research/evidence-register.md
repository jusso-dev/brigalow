# Evidence register

All sources were read on **2026-11-11** (Australia/Sydney) from the public web. Nothing here came from a vendor account, trial, sales call or private document.

Each finding carries one status:

| Status | Meaning |
| --- | --- |
| **Doc** | Stated in the vendor's own technical documentation (product docs, KB, API reference, CPS). Strongest evidence we have, but still not independently tested. |
| **Claim** | Stated on a vendor marketing or product page. Treat as a claim. |
| **3P** | From a third party (partner page, review site, regulator filing, press release by acquirer). |
| **Unknown** | We looked and could not confirm it from public sources. |

"Verified" in this repo never means we ran the product. It means the statement appears in the vendor's own documentation at the cited URL on the access date.

---

## 1. Keyfactor SignServer Enterprise

- Requested URL: https://www.keyfactor.com/products/signserver-enterprise/ (fetched OK)
- Owner: Keyfactor (SignServer came from PrimeKey, which merged with Keyfactor in 2021; the merger date is background knowledge, not re-verified in this pass).

| # | Finding | Status | Source |
| --- | --- | --- | --- |
| K1 | Server-side signing engine for code, firmware, containers, PDF, XML, CMS, Authenticode, JAR/APK, ePassports/eIDs. | Claim | product page |
| K2 | Keys generated and stored in on-prem or cloud HSMs, or a built-in HSM on the hardware appliance. PQC algorithms mentioned. | Claim | product page |
| K3 | Timestamping: RFC 3161 and Authenticode timestamps. | Claim | product page |
| K4 | Request auth by X.509 client cert, OAuth, basic auth or IP address. Signed audit logs of requests, signing and key/cert events. Clustering for failover and load balancing. | Claim | product page |
| K5 | Architecture is "Workers": signers reference a **Crypto Worker** that hosts a **Crypto Token** (keystore, PKCS#11, P11NG, Azure Key Vault, Fortanix). Config is property-based (`CRYPTOTOKEN_IMPLEMENTATION_CLASS`, `SHAREDLIBRARYNAME`, `SLOTLABELTYPE`, `PIN`, `DEFAULTKEY`). Admin Web and REST interface. | Doc | https://docs.keyfactor.com/signserver/latest/cryptotokens ; https://docs.keyfactor.com/signserver/latest/set-up-a-crypto-worker |
| K6 | Keystore files (PKCS#12, JKS) are "for testing but not recommended for production". | Doc | cryptotokens page |
| K7 | A `PIN` in the worker config auto-activates the token; omitting it requires manual activation. This is a design trade-off worth copying carefully (activation without secrets in config). | Doc | set-up-a-crypto-worker |
| K8 | **SignServer Community Edition** is open source (LGPL) at github.com/Keyfactor/signserver-ce, Java on a JVM, and is described as "not intended for production use". | Doc | https://github.com/Keyfactor/signserver-ce |
| K9 | As of **SignServer CE 7.7.1**, all HSM crypto tokens (PKCS#11, Azure Key Vault) are Enterprise-only. CE deployments using them must migrate or deactivate before upgrade. | Doc | https://docs.keyfactor.com/signserver/latest/signserver-community-7-7-1-release-notes ; https://docs.keyfactor.com/signserver/latest/pkcs11cryptotoken |
| K10 | Pricing | Unknown | not published |

Takeaway: mature worker/crypto-token model and broad formats, but the open-source edition no longer supports HSMs. That leaves a real gap for an open-source, HSM-capable signing server.

## 2. DigiCert Software Trust Manager (DigiCert ONE)

- Requested URL: https://www.digicert.com/signing/software-trust-manager returned **HTTP 403** to the fetch tool and **HTTP 404** to a direct request on 2026-11-11. The DigiCert site navigation still lists "Software Trust Manager". The product page has likely moved; we did not guess a new URL and used the docs instead.

| # | Finding | Status | Source |
| --- | --- | --- | --- |
| D1 | Software Trust Manager is a core service of DigiCert ONE covering threat/vulnerability detection, code signing and SBOM generation. | Doc | https://docs.digicert.com/en/software-trust-manager.html |
| D2 | **Releases (release windows)**: a named release with a time window, chosen keypairs, allowed users/groups, optional maximum signature count and an optional release baseline that pauses the release on mismatch. Needs the `Request release window` permission. | Doc | https://docs.digicert.com/en/software-trust-manager/releases/create-release.html |
| D3 | Keypair states: **online** (usable any time by users with access), **offline** (usable only inside a release window), **test**. GPG and standard keypairs. | Doc | create-release page |
| D4 | Threat detection can be a release purpose; signing can be blocked if the CI/CD threat-detection status fails. ReversingLabs integration exists. | Doc | create-release page; https://docs.digicert.com/en/software-trust-manager/connectors/reversinglabs-integration.html (search result, page not opened) |
| D5 | Client tooling: `smctl` CLI (keypair, certificate, sign, healthcheck), KSP and PKCS#11 libraries, works with SignTool, jarsigner, jsign, osslsigncode, NuGet, Mage, OpenSSL. "Simple signing" signs without third-party tools. Hash signing so files are not transported. | Doc | https://docs.digicert.com/en/digicert-keylocker/client-tools/command-line-interface/smctl.html ; https://docs.digicert.com/en/digicert-keylocker/smctl-command-manual/manage-signatures.html |
| D6 | Signer auth uses an API key plus a client authentication certificate (described as 2FA). "Dynamic authentication" uses browser SSO; third-party tools need `SM_DYNAMIC_AUTH=true`. | Doc | https://docs.digicert.com/en/digicert-keylocker/get-started/signer-guide.html ; dynamic-authentication page |
| D7 | 2026 release notes: SHA-3 hashing in SMCTL (Apr 2026), SHA3-384withRSA/PSS for HSM keypairs (Jul 2026), automatic retirement/deletion of HSM keys tied to expired or revoked certs (Jul 2026). | Doc | https://docs.digicert.com/en/whats-new/release-notes/digicert-keylocker-release-notes.html |
| D8 | Exact relationship between "DigiCert KeyLocker" and "Software Trust Manager" (separate SKU vs rename) | Unknown | docs use both names; KeyLocker notes refer to "the Software Trust Manager interface" |
| D9 | Pricing | Unknown | not found on public pages fetched |

Takeaway: the **release window** with offline keys and a signature cap is the strongest "time-boxed key use" control in the set. Worth an original equivalent.

## 3. SignPath

- Requested URL: https://signpath.io/ (fetched OK). Docs at https://docs.signpath.io/.

| # | Finding | Status | Source |
| --- | --- | --- | --- |
| S1 | Positions as a "Software Integrity Platform": Pipeline Integrity, Semantic Code Signing, Software Attestation, Code Governance. Native integrations for GitHub, GitLab, Azure DevOps, Jenkins, TeamCity, plus REST and CLI. EU-hosted, data residency on request. | Claim | homepage |
| S2 | Signs only after verifying origin; produces signed SLSA provenance and signs SBOMs; in-toto attestations. | Claim | homepage |
| S3 | Projects contain **signing policies** (typically `test-signing` and `release-signing`), **artifact configurations**, **trusted build systems** and **webhooks**. A policy has a purpose (test vs release, prevents cross-use), a certificate, and submitters. | Doc | https://docs.signpath.io/projects |
| S4 | Approval process with approvers and required approval count (k-of-n). **A single deny aborts the request.** | Doc | projects page |
| S5 | **Origin verification** checks repository URL, branch (per policy), commit, build job URL and reproducibility signals (build settings from source-controlled config, no manual overrides, no caching from unverified builds). Requires a linked trusted build system. | Doc | https://docs.signpath.io/origin-verification/ |
| S6 | Docs warn that build scripts can download anything, so code review must include CI config and build scripts. | Doc | origin-verification page |
| S7 | Artifact configurations describe nested artifacts and do **deep signing** (inside-out, e.g. CAB/MSI containing EXE/DLL), defined in XML, versionable. | Doc | projects page |
| S8 | When trusted-build-system verification is on, interactive users cannot be submitters. | Doc | projects page |
| S9 | Open Source Code Signing: SignPath Foundation provides certificates to OSS projects under its policies. | Doc | origin-verification page |
| S10 | Malware scanning per policy (enabled via support). | Doc | projects page |
| S11 | Pricing | Unknown | not captured in this pass |

Takeaway: the best model for **policy-as-gate**: submitters, purposes, origin claims from CI, deny-wins approvals, and artifact structure. SignPath uploads artifacts (deep signing needs the file), unlike hash-only services.

## 4. Venafi (now Palo Alto Networks, via CyberArk)

- Requested URL: https://www.venafi.com/ now lands on a Palo Alto Networks page: "CyberArk Certificate Manager is now Next-Gen Trust Security (NGTS)".

| # | Finding | Status | Source |
| --- | --- | --- | --- |
| V1 | Venafi TLS Protect SaaS became CyberArk Certificate Manager SaaS and is now **Next-Generation Trust Security (NGTS)** at Palo Alto Networks. Self-hosted products (Certificate Manager Self-Hosted, SSH Manager Self-Hosted, **Code Sign Manager Self-Hosted**) are built on **Trust Protection Foundation**. | Claim | https://www.venafi.com/ (redirect landing page) |
| V2 | Palo Alto Networks completed its acquisition of CyberArk (reported date 11 Feb 2026). | 3P | https://investors.paloaltonetworks.com/news-releases/news-release-details/palo-alto-networks-completes-acquisition-cyberark-secure--ai-era (search result; page not opened) |
| V3 | Code Sign Manager Self-Hosted (formerly Venafi CodeSign Protect) = Trust Protection Foundation server + code signing clients (Windows CSP/KSP, PKCS#11, GPG; Linux PKCS#11, GPG; macOS PKCS#11, Keychain, GPG) + optional HSM. | Doc | https://docs.venafi.com/Docs/currentSDK/TopNav/Content/CodeSigning/c-codesigning-architecture.php |
| V4 | Keys live in the product's Secret Store or an HSM. HSM use needs the separately licensed "Advanced Key Protect". Docs say the product "itself does not sign code": it governs key use and returns a signed hash. | Doc | architecture page |
| V5 | Two endpoints: `vedauth` (returns per-user or per-machine grants) and `vedhsm` (receives hash, hash algorithm and certificate). Machine grants are documented as "generally considered less secure". Grant tokens stored in registry or `~/.libhsmconfig` / `/etc/venafi`. | Doc | architecture page |
| V6 | Projects, environments and **environment templates**; **flows** with standard approval steps by "Key Use Approvers" and a required approval count; projects inherit flows from templates. | Doc | https://docs.venafi.com/Docs/current/TopNav/Content/CodeSigning/t-codesigning-configuring-flows.php (search summary) |
| V7 | Pricing | Unknown | not published |

Takeaway: the virtual-HSM client pattern (native CSP/KSP/PKCS#11 shims talking to a central server) is the industry norm. The documented weakness of long-lived machine grants is a lesson: prefer short-lived, workload-bound credentials.

## 5. Encryption Consulting (CodeSign Secure)

- Requested URL: https://www.encryptionconsulting.com/ (fetched via direct request). Encryption Consulting is a **company** selling products (CertSecure Manager, CodeSign Secure, CBOM Secure, SSH Secure, PKI-as-a-Service, HSM-as-a-Service) plus advisory services and training. The signing product is CodeSign Secure.

| # | Finding | Status | Source |
| --- | --- | --- | --- |
| E1 | Keys generated and used inside FIPS 140-2 Level 3 HSMs (Entrust nShield, Thales Luna, Securosys Primus, Utimaco), on-prem or cloud, with HA. | Doc | https://support.encryptionconsulting.com/knowledgebase/products/codesign-secure/codesign-secure-overview |
| E2 | Client hashes locally and sends only the hash. Clients plug into SignTool, jarsigner, apksigner, codesign. | Doc | overview |
| E3 | Request flow: mutual TLS + API user creds -> JWT; role must include CodeSigning Operation and user must be in a team mapped to the certificate; environment policy applied; optional pre-sign hash validation against a trusted rebuild; HSM signs; signing tool fetches RFC 3161 timestamp directly from a public TSA; logged in Logs and Audit Trail. | Doc | https://support.encryptionconsulting.com/knowledgebase/products/codesign-secure/how-codesign-secure-works |
| E4 | Approval policy is per **environment** (No Approval / Certificate Owner / Quorum), each certificate belongs to exactly one environment, optional email OTP MFA for approvers. | Doc | https://support.encryptionconsulting.com/knowledgebase/products/codesign-secure/approval-workflows-and-signing-policies |
| E5 | **Approval window is fixed at 100 seconds**; otherwise the request times out and the signing command fails. KB recommends No Approval for automated pipelines and putting the human gate in the CI platform instead. | Doc | approval page; FAQ; troubleshooting page |
| E6 | Five default roles: System Admin, Project Manager, Security Officer, Auditor, Developer. Logs exportable to Splunk or Grafana Loki. | Doc | overview |
| E7 | PQC: ML-DSA and LMS support stated by the vendor. | Doc (vendor statement) | overview |
| E8 | Pricing | Unknown | not published |

Takeaway: clear, honest docs. The fixed 100-second synchronous approval is a practical limitation for real release approvals; an asynchronous approval model with a pre-approved release is better.

## 6. Microsoft Azure Artifact Signing

- Requested URL: https://learn.microsoft.com/en-us/azure/artifact-signing/ (fetched OK). Previously branded "Trusted Signing" (background; the rename was not confirmed from a primary source in this pass).

| # | Finding | Status | Source |
| --- | --- | --- | --- |
| A1 | Fully managed signing service. Resource model: Azure subscription -> resource group -> Artifact Signing account -> identity validation + certificate profile. Basic and Premium SKUs. | Doc | https://learn.microsoft.com/en-us/azure/artifact-signing/overview |
| A2 | **Public Trust** certs chain to Microsoft Identity Verification Root CA 2020 under the Microsoft PKI Services Third-Party CPS. **Private Trust** is not default-trusted and targets App Control for Business (WDAC). "Public Trust Test" profiles are not publicly trusted. | Doc | https://learn.microsoft.com/en-us/azure/artifact-signing/concept-trust-models |
| A3 | Certificates renew **daily** and are valid for **72 hours**; revocation can be scoped to a single day's certificate. | Doc | https://learn.microsoft.com/en-us/azure/artifact-signing/concept-certificate-management |
| A4 | Each certificate profile gets a durable custom EKU under `1.3.6.1.4.1.311.97.` so trust can be pinned across daily renewals. | Doc | certificate-management page |
| A5 | No private key import or export. Keys in managed HSMs. The overview says **FIPS 140-3 Level 3**; the certificate-management page says **FIPS 140-2 Level 3** in one place. Microsoft's own pages are inconsistent. | Doc (inconsistent) | overview; certificate-management |
| A6 | Artifact Signing code-signing CAs are scheduled for removal from CCADB; Microsoft no longer includes them in the Trusted Root Program, but they remain on the Windows Platform Trust List and Windows continues to trust them. | Doc | certificate-management page |
| A7 | TSA at `http://timestamp.acs.microsoft.com`; timestamping is essential because of 72-hour certs. Digest signing: "your file never leaves your endpoint". | Doc | certificate-management; overview |
| A8 | **Public Trust eligibility**: organisations in the US, Canada, EU, UK, **Australia**, New Zealand, Japan, South Korea, Singapore, Switzerland, Norway and Israel; individual developers in the US or Canada only. Identity validation only in the portal, 1 to 20 business days. A search-engine summary on the same day omitted Australia; the primary doc includes it. | Doc | https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart |
| A9 | **Pricing**: Basic US$9.99/month per account, 5,000 signatures; Premium US$99.99/month, 100,000 signatures; US$0.005 per signature over quota. Basic allows 1 certificate profile per type, Premium 10. | Doc | https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-change-sku |
| A10 | Regions listed in the quickstart do not include an Australian region (as of access date). | Doc | quickstart |

Takeaway: short-lived certs plus durable profile EKUs is the cleanest answer to revocation blast radius. Public trust here is Microsoft's CA; our product cannot replicate it and must integrate with it instead.

## 7. SSL.com eSigner

- Requested URL: https://www.ssl.com/esigner/ (fetched OK).

| # | Finding | Status | Source |
| --- | --- | --- | --- |
| L1 | eSigner for Code: cloud-HSM-backed signing for IV, OV and EV code signing certificates bought from SSL.com, then enrolled in eSigner as a separate subscription. | Claim | product page |
| L2 | Keys in a FIPS 140-2 (stated Level 3) validated cloud HSM operated by SSL.com. | Claim | product page |
| L3 | **eSigner CKA** (Crypto Key Adapter) is a Windows component that works with signtool.exe. For Linux, use the **CSC API** (Cloud Signature Consortium) directly. | Claim | product page FAQ |
| L4 | Published prices on access date: IV/OV code signing US$129/yr, EV US$349/yr; eSigner tiers from US$15/mo (240 signings, 1 credential) to US$187.50/mo (12,000 signings, 13 credentials); extra credential US$20/mo; YubiKey token +US$249; bring-your-own cloud HSM attestation fees (AWS CloudHSM US$1,500, Google Cloud HSM US$1,500, Azure Dedicated HSM US$500). | Claim (published price list) | product page |
| L5 | SmartScreen reputation is tied to the certificate, not the signing tool. | Claim | product page FAQ |

Takeaway: the cost and CA/B Forum hardware-key rules are why public-trust signing always needs a purchased cert and certified key custody. CSC API is a standard worth supporting as a remote-key backend.

## 8. Aujas (CodeSign)

- Requested URL: https://www.aujas.com/ returned **HTTP 404** to both the fetch tool and a direct request on 2026-11-11; the vendor datasheet URL also returned 404. Evidence below comes from a partner page and a third-party review. Weakest-evidenced vendor in this register.

| # | Finding | Status | Source |
| --- | --- | --- | --- |
| J1 | Aujas Cybersecurity's "CodeSign": automated, DevOps-ready code signing; integrates with Thales Luna HSM (FIPS 140-2 Level 3 mode) using PKCS#11, CSP and KSP; fetches the key per request. | 3P | https://cpl.thalesgroup.com/partners/aujas-cybersecurity-limited ; https://cpl.thalesgroup.com/sites/default/files/content/partners/resources/Aujas-CodeSign-Solution-Brief.pdf |
| J2 | Workflow engine for approval routing for projects, builds and certificates; granular audit trail; enterprise directory auth; role-based access; signing modes include basic, GPG, hash, force, append, MAGE, WHQL. | 3P | Thales solution brief |
| J3 | Pre-sign malware scanning; cloud and self-hosted; pricing on request; broad format list (Authenticode, JAR, APK, RPM, Debian, Docker, macOS/iOS packages, Helm charts). | 3P | https://www.itechguides.com/products/aujas-automated-code-signing-platform/ (review site, checked 20 Sep 2026 per that page) |
| J4 | Current product status, ownership and site availability | Unknown | site returned 404 |

## 9. GaraTrust (Garantir)

- Requested URL: https://garatrust.com/ returned **HTTP 500** to the fetch tool and no response to a direct request on 2026-11-11. GaraTrust is a product of **Garantir**; the vendor's live pages are on garantir.io.

| # | Finding | Status | Source |
| --- | --- | --- | --- |
| G1 | Client-side hashing; only the hash crosses the network. Native clients: Windows CNG, Java JCA/JCE, macOS CryptoTokenKit, Linux PKCS#11/GPG/OpenSSL, so SignTool, jarsigner, codesign and rpmsign work unchanged. | Claim | https://garantir.io/enterprise-code-signing/ ; https://aws.amazon.com/marketplace/pp/prodview-qihcmd3xcjsdu |
| G2 | Non-exportable keys in FIPS 140-2/3 HSMs; multi-vendor (Thales, Entrust nShield, AWS CloudHSM, Azure Key Vault, Google Cloud KMS). | Claim | enterprise-code-signing page |
| G3 | Controls: FIDO2/WebAuthn, TOTP, TPM-based device auth, just-in-time key activation, per-key or per-user policies, approval workflows. | Claim | marketplace listing; https://garantir.io/solutions/business-need/dev-sec-ops/ |
| G4 | **Hash validation** pre-sign and post-sign, and reproducible-build verification, to detect compromised build servers. Pre-sign malware scanning. | Claim | enterprise-code-signing page |
| G5 | PQC: hybrid RSA/ECC + ML-DSA for software, stateful LMS for firmware. | Claim | enterprise-code-signing page |
| G6 | SaaS, on-prem, air-gapped. AWS Marketplace public tiers by signature volume (250,000 to 1,000,000 per year); exact prices not captured here. | Claim | marketplace listing |
| G7 | Broader platform: also CLM, Git commit signing, SBOM signing. | Claim | https://garantir.io/garatrust/ |

## 10. Sectigo Certificate Manager (SCM)

- Requested URL: https://www.sectigo.com/enterprise-solutions/certificate-manager (fetched via direct request).

| # | Finding | Status | Source |
| --- | --- | --- | --- |
| C1 | SCM is a CA-agnostic certificate lifecycle management platform (discover, issue, deploy, renew, replace) across SSL/TLS, Microsoft CA, S/MIME, private PKI, DevOps, code signing, VMC/CMC. Cloud-based. ACME supported. MCP server offered. | Claim | product page |
| C2 | Page states public TLS max validity is 200 days now, falling to 100 days in March 2027 and 47 days in March 2029 under CA/B Forum rules. (TLS, not code signing.) | Claim | product page |
| C3 | Code signing certificate states: Requested, Approved, Applied, Issued, Expired, Declined, Rejected, Revoked. Sub types OV, EV, Private. Enrolment via self-enrolment form, REST API, Admin API or CA connector. Revoke with reason; per-cert audit. | Doc | https://docs.sectigo.com/scm/scm-administrator/understanding-code-signing-certificates |
| C4 | Supported HSM types for key attestation listed: Thales Luna SA, Thales Federal Luna SA, YubiKey, Google Cloud KMS, Fortanix DSM, YubiHSM 2, Entrust nShield. | Doc | same page |
| C5 | REST import of code signing certs: `POST /api/cscert/v1/import` (up to 128 per call). | Doc | https://scm.devx.sectigo.com/reference/import-code-signing-certificates (search result) |
| C6 | SCM manages certificates; it is **not** a signing service. | Doc (inferred from scope of docs) | as above |
| C7 | Pricing | Unknown | free trial offered; prices not published on page |

Takeaway: CLM, not signing. Relevant as an upstream: our product should track code signing cert lifecycle states and could accept certs issued through a CLM, but should not try to be a CLM.

---

## Cross-cutting facts used by the design

| Fact | Status | Basis |
| --- | --- | --- |
| Publicly trusted code signing requires a CA-issued certificate after identity validation, with the key in certified hardware (CA/B Forum Code Signing Baseline Requirements). | Doc | SSL.com and Azure pages above reference the CA/B Forum hardware requirement; the CSBRs themselves were not re-read in this pass. |
| Timestamping (RFC 3161) is what keeps signatures valid after cert expiry. | Doc | Azure certificate management (A7), Keyfactor (K3), Encryption Consulting (E3) |
| Hash-only signing is the dominant pattern for speed and IP protection; artifact upload is needed for deep signing and content inspection. | Doc | DigiCert (D5), EC (E2), Venafi (V5), Azure (A7), SignPath (S7) |
