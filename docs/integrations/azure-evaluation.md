# Azure Artifact Signing evaluation

Update 2026-11-12: an `artifact_signing` backend now exists, tested against a local contract mock only. See [Azure Artifact Signing backend](azure-artifact-signing.md). The original evaluation is kept below.

Original decision: document a possible future remote backend; do not create an account or implement a production adapter in Phase 9. The CSC mock is not an Azure adapter. All observations below come from the [2026-11-11 evidence register, A1–A10](../research/evidence-register.md); they are dated vendor documentation, not independently exercised service behaviour.

| Consideration | Evidence and implication |
| --- | --- |
| Custody and lifecycle | A3–A5 describe managed keys, daily certificates valid for 72 hours and a durable profile identifier. A real adapter must handle authenticated certificate rotation and verify every response against the authorised profile; static mock certificate pinning is insufficient. No private-key import/export path belongs in Brigalow. |
| Trust | A2 and A6 distinguish provider trust models and Windows trust arrangements. A resulting Brigalow record could be `external-ca` only after explicit operator anchor configuration and chain validation. Acceptance on one platform does not establish acceptance elsewhere. |
| Timestamping | A7 makes timestamps central to short-lived certificates. Evaluate the actual protocol, endpoint transport and relying-platform verification. Brigalow's current HTTPS-only TSA controls must not be weakened to accommodate a documented HTTP endpoint. |
| Eligibility and location | A8 included Australian organisations but not Australian individual developers; A10 listed no Australian region. Recheck eligibility, identity-validation steps, data location and jurisdiction before any proposed account. Do not infer availability from search snippets. |
| Cost | A9 recorded Basic US$9.99/month with 5,000 signatures, Premium US$99.99/month with 100,000, plus US$0.005 over quota. These are dated figures, not a quotation or spending approval. Model retries, timestamp calls and expected peak volumes before selection. |
| Validation claims | A5 found conflicting FIPS versions in Microsoft documentation. Resolve with the provider's specific module evidence if relevant. No provider module statement certifies Brigalow. |

A future design must establish the supported digest-signing API, identity/token audience and minimum signing role, profile-to-tenant mapping, response certificate provenance, authentication renewal, quotas, timeout semantics and provider audit correlation. Keep OIDC workload identity, policy decisions, approval exclusions, gates, window caps and append-only audit in Brigalow. Durable failure must not trigger ambiguous signing retries. No secret-bearing SDK diagnostics or private material may enter logs.

Before implementation, build a local contract mock from the chosen versioned API and test wrong account/profile, stale or substituted certificate, timeout after remote signing, quota exhaustion, expired auth and timestamp failure. Public-platform verification needs its own evidence and explicit approval for real account use; AT-PUB-01 proves only the local CSC path. Request Justin's approval before any enrolment, subscription, cloud resource, real signing request or production deployment.
