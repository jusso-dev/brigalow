# Independent security review checklist

This checklist requests review; it is not evidence that an external review has occurred. Record reviewer, exact commit/configuration, commands, findings and remediation evidence. No certification is asserted.

- Verify tenant routing, explicit predicates, forced RLS, composite references and restricted DB roles with hostile cross-tenant IDs on every registered route.
- Exercise OIDC issuer/audience/nonce/PKCE/session binding, workload claim rules, credential scope/expiry/revocation, CSRF/Origin and escaped HTML. Attempt credential/header/log disclosure.
- Demonstrate custodian/requester approval exclusions, deny/quorum races, expiry, policy/key revocation, release-window close/expiry and concurrent caps. Crash at every durable transition.
- Probe HSM non-exportability, algorithm restrictions, configured-token selection, process restart, provider ABI buffers and outage refusal without fallback. Check actual vendor firmware/module/certification claims independently.
- Attack webhook nonce/digest/HMAC bindings, TLS redirects, timeout/body limits, SSRF boundaries and fail-closed signing counts. Audit provenance source claims and consumer trust assumptions.
- Test certificate/CSR path/algorithm/time/EKU constraints, trust-tier labelling, optional CA role/key separation, immutable profiles, duplicate issuance and revocation/CRL races.
- Independently verify audit chains/checkpoints; attempt prefix substitution, suffix truncation, old-checkpoint replay and key replacement. Reconcile external retained heads after restore.
- Flood authenticated and unauthenticated entry points separately; test body/header/connection limits and multiple replicas. Verify rejected-budget audit writes are bounded.
- Review parser fuzz findings, dependency advisories, pinned workflow permissions, build provenance, SBOM contents and the limits of ephemeral lab release signatures.
- Perform isolated DB/HSM/configuration recovery and evaluate pending work, consumed caps, CA revocations and credential state before enabling signatures. Review Helm/TLS/network/secret configuration on the intended platform.
