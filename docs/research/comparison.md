# Cross-vendor comparison

Based on [evidence-register.md](evidence-register.md). Cell codes: **D** = vendor docs, **C** = vendor claim, **3P** = third party, **?** = unknown from public sources. Accessed 2026-11-11.

## What each one actually is

| Vendor / product | Category | Delivery | Signs, or governs keys? |
| --- | --- | --- | --- |
| Keyfactor SignServer Enterprise | Signing server | Self-hosted software, appliance, cloud (C) | Signs (D) |
| DigiCert Software Trust Manager | Signing + supply chain service on DigiCert ONE | SaaS (D), other models ? | Signs hashes via client tools (D) |
| SignPath | Policy-gated signing + attestation | SaaS, EU hosting (C) | Signs, including deep signing of uploaded artifacts (D) |
| Venafi CodeSign Protect, now CyberArk Code Sign Manager Self-Hosted (Palo Alto Networks) | Key governance for signing | Self-hosted on Trust Protection Foundation (D) | Governs keys, returns signed hashes (D) |
| Encryption Consulting CodeSign Secure | Signing platform | On-prem or cloud (D) | Signs hashes (D) |
| Azure Artifact Signing | Managed signing + Microsoft CA | Azure service (D) | Signs digests, issues 72h certs (D) |
| SSL.com eSigner for Code | CA + cloud HSM signing | SaaS (C) | Signs via CKA or CSC API (C) |
| Aujas CodeSign | Signing platform | Cloud, self-hosted (3P) | Signs (3P) |
| GaraTrust (substitute source: Garantir, link to garatrust.com unconfirmed) | Crypto services platform incl. signing | SaaS, on-prem, air-gapped (C) | Signs hashes (C) |
| Sectigo Certificate Manager | Certificate lifecycle management | SaaS (C) | Neither: manages certificates (D) |

## Capability matrix

| Capability | SignServer | DigiCert STM | SignPath | CSM-SH (Venafi) | EC CodeSign | Azure AS | SSL.com | Aujas | GaraTrust | Sectigo SCM |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| HSM key custody | D (Ent only) | D | ? | D (extra licence) | D | D (managed) | C | 3P | C | n/a (attestation list D) |
| Software keys allowed | D (test only) | ? | ? | D (Secret Store) | ? | no import/export D | ? | ? | ? | n/a |
| Hash-only client | C | D | partial, uploads for deep signing D | D | D | D | C | 3P | C | n/a |
| Native CSP/KSP/PKCS#11 shims | ? | D | ? | D | D | ? | C (CKA, Windows) | 3P | C | n/a |
| Approvals, k-of-n | ? | via release windows D | D (deny wins) | D | D (100 s window) | ? | ? | 3P | C | approval of cert requests D |
| Time-boxed key use | ? | D (release window, sig cap) | ? | ? | ? | 72h certs D | ? | ? | JIT activation C | n/a |
| CI origin verification | ? | ? | D | ? | pre-sign rebuild check D | ? | ? | ? | hash validation C | n/a |
| Malware scan before sign | ? | D (ReversingLabs) | D (via support) | ? | ? | ? | ? | 3P | C | n/a |
| SLSA / in-toto / SBOM | ? | SBOM D | C | ? | ? | ? | ? | ? | C | n/a |
| RFC 3161 TSA | C (built in) | ? | ? | ? | client to public TSA D | D (Microsoft TSA) | ? | ? | C | n/a |
| Signed/tamper-evident audit | C | ? | ? | ? | D (audit trail) | D (portal logs) | ? | 3P | C | D (per cert) |
| Public trust certificate included | no | DigiCert CA (product scope ?) | OSS Foundation certs D | no | no | yes, eligibility limits D | yes, purchased D/C | no (CA-issued) 3P | no | issues via Sectigo CA C |
| Open source | CE only, LGPL, no HSM since 7.7.1 D | no | no | no | no | no | no | no | no | no |
| Published price | no | no | ? | no | no | yes D | yes C | no | marketplace tiers C | no |

## Patterns worth adopting (as ideas, not copies)

1. **Hash-only signing with native shims** (DigiCert, Venafi, EC, Azure; GaraTrust claims it). Small network payload; the artifact stays with the build. Not universal: SignPath uploads artifacts so it can deep-sign and inspect them.
2. **Purpose-typed policies** so release keys can't be used by test policies (SignPath S3).
3. **Deny-wins k-of-n approvals** (SignPath S4) that are **asynchronous**, unlike the fixed 100-second window in EC (E5).
4. **Release windows**: offline keys usable only in a named, time-boxed release with a signature cap (DigiCert D2, D3).
5. **Origin claims from the CI platform, not from the submitter** (SignPath S5). In 2026 that means OIDC workload identity tokens from GitHub Actions, GitLab and others.
6. **Short-lived certificates and durable profile identifiers** to shrink revocation blast radius (Azure A3, A4). Only achievable on a private CA we control.
7. **Crypto token abstraction** with explicit activation (SignServer K5, K7).
8. **Pre-sign verification hooks** (malware scan, reproducible rebuild, hash validation) as pluggable gates (DigiCert D4, EC E3, GaraTrust G4).

## Gaps in the market this repo targets

- No open-source, production-intended signing control plane with HSM support. SignServer CE dropped HSMs in 7.7.1 and calls itself non-production (K8, K9).
- Approval UX in several products assumes a human is watching a screen during the build.
- Public trust always depends on a CA, and usually on paid enrolment (SignPath Foundation's open-source certificates are an exception, terms unconfirmed). Every product here that offers public trust either is a CA or integrates one. An open-source product must be explicit about that line.
