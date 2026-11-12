use super::*;
use brigalow_store::{
    login::{NewPendingLogin, Sealed},
    Store,
};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope,
};
pub struct Login {
    pub url: String,
    pub browser: String,
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
        let client = BasicClient::new(ClientId::new(h.client_id.clone()))
            .set_auth_uri(AuthUrl::new(h.authorization_url.clone()).map_err(|_| AuthError)?)
            .set_redirect_uri(RedirectUrl::new(self.redirect(a)).map_err(|_| AuthError)?);
        let (challenge, pkce) = PkceCodeChallenge::new_random_sha256();
        let nonce = random_secret();
        let (url, state) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".into()))
            .add_scope(Scope::new("groups".into()))
            .add_extra_param("nonce", nonce.clone())
            .set_pkce_challenge(challenge)
            .url();
        let browser = random_secret();
        let keys = self.login_keys.as_ref().ok_or(AuthError)?;
        let state_hash = hash(state.secret());
        let key_id = keys.active_id().to_owned();
        let secrets = login_keys::encode_secrets(pkce.secret(), &nonce)?;
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
