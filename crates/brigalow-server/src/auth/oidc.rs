use super::*;
use brigalow_store::{
    login::{NewPendingLogin, Sealed},
    Store,
};
pub struct Login {
    pub url: String,
    pub browser: String,
}

fn authorization_url(
    human: &HumanConfig,
    redirect: &str,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> Result<url::Url, AuthError> {
    // RFC 7636 section 4.2: S256 uses RustCrypto SHA-256 and unpadded base64url.
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut url = url::Url::parse(&human.authorization_url).map_err(|_| AuthError)?;
    url.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", human.client_id.as_str()),
        ("state", state),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("redirect_uri", redirect),
        ("scope", "openid groups"),
        ("nonce", nonce),
    ]);
    Ok(url)
}

impl Identity {
    fn redirect(&self, a: &Authority) -> String {
        format!(
            "{}/auth/{}/{}/callback",
            self.config.public_url.trim_end_matches('/'),
            a.org_id,
            a.name
        )
    }
    pub async fn login(
        &self,
        store: &Store,
        org: Uuid,
        provider: &str,
    ) -> Result<Login, AuthError> {
        let a = self.authority(org, provider)?;
        let h = a.human.as_ref().ok_or(AuthError)?;
        // Independent 256-bit OS-random secrets; the verifier is 43 RFC 7636 characters.
        let pkce = random_secret();
        let state = random_secret();
        let nonce = random_secret();
        let url = authorization_url(h, &self.redirect(a), &state, &nonce, &pkce)?;
        let browser = random_secret();
        let keys = self.login_keys.as_ref().ok_or(AuthError)?;
        let state_hash = hash(&state);
        let key_id = keys.active_id().to_owned();
        let secrets = login_keys::encode_secrets(&pkce, &nonce)?;
        let browser_hash = hash(&browser);
        // DB failure or exhausted bounds reject the login; there is no in-memory fallback.
        store
            .tenant(org)
            .create_pending_login(
                NewPendingLogin {
                    state_hash: &state_hash,
                    provider,
                    browser_hash: &browser_hash,
                    key_id: &key_id,
                    version: i16::from(login_keys::VERSION),
                },
                self.pending_limits,
                |expires_ms| {
                    let aad = login_keys::aad(
                        org,
                        provider,
                        &state_hash,
                        &browser_hash,
                        expires_ms,
                        &key_id,
                    );
                    let (nonce, ciphertext) = keys
                        .seal(&aad, &secrets)
                        .map_err(|_| brigalow_store::Error::Invalid)?;
                    Ok(Sealed {
                        nonce: nonce.to_vec(),
                        ciphertext,
                    })
                },
            )
            .await
            .map_err(|_| AuthError)?;
        Ok(Login {
            url: url.into(),
            browser,
        })
    }
    pub async fn complete(
        &self,
        store: &Store,
        org: Uuid,
        provider: &str,
        state: &str,
        code: &str,
        browser: &str,
    ) -> Result<(Principal, i64), AuthError> {
        use subtle::ConstantTimeEq;
        if state.len() > 256 || code.len() > 4096 || browser.len() > 256 {
            return Err(AuthError);
        }
        let a = self.authority(org, provider)?;
        let keys = self.login_keys.as_ref().ok_or(AuthError)?;
        let state_hash = hash(state);
        let browser_hash = hash(browser);
        // Tenant RLS transaction: lock the exact row; only a matching browser/provider whose
        // ciphertext authenticates commits the consumption, before any token exchange.
        let secrets = store
            .tenant(org)
            .consume_pending_login(&state_hash, |p| {
                if p.provider != provider
                    || p.version != i16::from(login_keys::VERSION)
                    || !bool::from(p.browser_hash.as_bytes().ct_eq(browser_hash.as_bytes()))
                {
                    return None;
                }
                let aad = login_keys::aad(
                    org,
                    provider,
                    &state_hash,
                    &p.browser_hash,
                    p.expires_ms,
                    &p.key_id,
                );
                keys.open(&p.key_id, &aad, &p.nonce, &p.ciphertext).ok()
            })
            .await
            .map_err(|_| AuthError)?
            .ok_or(AuthError)?;
        let (verifier, expected_nonce) = login_keys::decode_secrets(&secrets)?;
        let h = a.human.as_ref().ok_or(AuthError)?;
        let response = self
            .http
            .post(&h.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", h.client_id.as_str()),
                ("redirect_uri", self.redirect(a).as_str()),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|_| AuthError)?;
        let response = Self::json_response(response).await?;
        let token = response["id_token"].as_str().ok_or(AuthError)?;
        let (claims, _) = self.verified(a, token, &h.client_id).await?;
        validate_id_claims(&claims, &h.client_id, expected_nonce, now())?;
        let groups = claims["groups"].as_array().ok_or(AuthError)?;
        let mut roles = Vec::new();
        for group in groups {
            if let Some(role) = group.as_str().and_then(|g| h.group_roles.get(g)) {
                if !roles.contains(role) {
                    roles.push(*role);
                }
            }
        }
        if roles.is_empty() {
            return Err(AuthError);
        }
        Ok((
            Self::principal(a, &claims, roles, None, true)?,
            claims["exp"].as_i64().ok_or(AuthError)?.min(now() + 3600),
        ))
    }
}

/// Narrow OIDC authorization-code profile, after JWT signature/issuer/time validation.
/// As before, additional audiences are untrusted; implicit/hybrid flows are unsupported.
fn validate_id_claims(
    claims: &serde_json::Value,
    client: &str,
    expected_nonce: &str,
    now: i64,
) -> Result<(), AuthError> {
    use subtle::ConstantTimeEq;
    let audience = match &claims["aud"] {
        serde_json::Value::String(aud) => aud == client,
        serde_json::Value::Array(aud) => aud.len() == 1 && aud[0].as_str() == Some(client),
        _ => false,
    };
    let nonce = claims["nonce"].as_str().ok_or(AuthError)?;
    let issued = claims["iat"].as_i64().ok_or(AuthError)?;
    let expires = claims["exp"].as_i64().ok_or(AuthError)?;
    if !audience
        || claims
            .get("azp")
            .is_some_and(|azp| azp.as_str() != Some(client))
        || issued < 0
        || issued > now + 30
        || issued >= expires
        || !bool::from(
            hash(nonce)
                .as_bytes()
                .ct_eq(hash(expected_nonce).as_bytes()),
        )
    {
        return Err(AuthError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_request_matches_rfc7636_and_encodes_parameters() {
        // RFC 7636 Appendix B supplies an independent S256 test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let human = HumanConfig {
            client_id: "client &+=/雪".into(),
            authorization_url: "https://idp.example/authorize?tenant=one%2Btwo".into(),
            token_url: "https://idp.example/token".into(),
            group_roles: BTreeMap::new(),
        };
        let redirect = "https://brigalow.example/auth/org/provider/callback";
        let url = authorization_url(
            &human,
            redirect,
            "state&nonce=wrong",
            "nonce+value",
            verifier,
        )
        .unwrap();
        let pairs: Vec<_> = url.query_pairs().into_owned().collect();
        assert_eq!(pairs.len(), 9);
        let params: BTreeMap<_, _> = pairs.into_iter().collect();
        assert_eq!(params.len(), 9);
        assert_eq!(params["tenant"], "one+two");
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["client_id"], human.client_id);
        assert_eq!(params["redirect_uri"], redirect);
        assert_eq!(params["scope"], "openid groups");
        assert_eq!(params["state"], "state&nonce=wrong");
        assert_eq!(params["nonce"], "nonce+value");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(
            params["code_challenge"],
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(!url.as_str().contains(verifier));
    }
}
