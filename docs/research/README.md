# Research: enterprise signing products

Desk research on ten products Justin listed, done on 2026-11-11 from public sources only. It informs the scope of Brigalow. It is not a buying guide and it does not rate vendors.

- [evidence-register.md](evidence-register.md): every finding, its URL, and whether it came from vendor docs, a vendor claim, a third party, or is unknown.
- [comparison.md](comparison.md): what each product is, a capability matrix, and the patterns and gaps that shaped the design.

## Key takeaways

1. **Three different product types are on this list.** Signing engines and services (SignServer, DigiCert STM, SignPath, EC CodeSign Secure, Azure Artifact Signing, SSL.com eSigner, Aujas, GaraTrust), key governance that returns signed hashes (Venafi, now CyberArk Code Sign Manager Self-Hosted under Palo Alto Networks), and certificate lifecycle management (Sectigo SCM). Encryption Consulting is a company; its signing product is CodeSign Secure.
2. **Hash-only signing through native shims is common, not universal.** DigiCert, Venafi (now CyberArk/Palo Alto), Encryption Consulting and Azure document it, and GaraTrust claims it: the build machine keeps using SignTool, jarsigner, codesign, osslsigncode or GPG, and a local PKCS#11, KSP or CNG provider sends only a digest to the server. Exceptions in the evidence: SignPath works on uploaded artifacts for deep signing and inspection (S7), SignServer is also pitched as server-side signing of documents such as PDF and XML (K1), Sectigo SCM doesn't sign at all (C6), and Aujas's data flow is unknown.
3. **Policy is where products differ.** SignPath verifies CI origin and branch before signing. DigiCert time-boxes offline keys with release windows and signature caps. EC uses per-environment quorum but forces a 100-second approval window. Azure shrinks blast radius with 72-hour certificates.
4. **Public trust comes from a CA, usually after paid enrolment.** Publicly trusted code signing for operating systems needs a CA-issued certificate after identity validation, with the key in certified hardware. Azure Artifact Signing includes Microsoft's CA, with country limits (Australian organisations are eligible; Australian individuals are not). SSL.com publishes its prices. Most others expect you to bring a CA certificate. Exception in the evidence: SignPath Foundation provides certificates to open-source projects under its own policies (S9); this pass did not confirm its cost or eligibility terms, so don't assume it fits any given project.
5. **The open-source gap is real.** SignServer Community Edition is LGPL but, from 7.7.1, no longer supports HSMs and is labelled non-production.
6. **Evidence quality varies.** Aujas's site returned 404 and garatrust.com returned 500 on the access date. Aujas rows rely on a partner page and a review site. GaraTrust rows come from garantir.io and an AWS Marketplace listing for "GaraTrust" by Garantir, used as a **substitute source**: no page we read links garatrust.com to Garantir, so treat the attribution as likely but unconfirmed. DigiCert's requested product URL returned 404; its docs were used instead. Microsoft's own pages disagree on FIPS 140-2 vs 140-3.

## Method and limits

- Sources: vendor product pages, vendor documentation and KBs, one partner page, one review site, one acquirer press release. Fetched with a web fetch tool or a plain HTTP request.
- No accounts, trials, demos or sales contact.
- Prices appear only when a vendor page published them on the access date. Nothing is estimated.
- Product names and trademarks belong to their owners. This repo copies no code, UI or documentation from them.
