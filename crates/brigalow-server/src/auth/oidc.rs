use super::*;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope,
};
pub(super) struct Pending {
    org: Uuid,
    provider: String,
    browser_hash: String,
    nonce: String,
    pkce: PkceCodeVerifier,
    expires: Instant,
}
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
    pub async fn login(&self, org: Uuid, provider: &str) -> Result<Login, AuthError> {
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
        let mut pending = self.pending.lock().await;
        pending.retain(|_, p| p.expires > Instant::now());
        if pending.len() >= 1024 {
            return Err(AuthError);
        }
        pending.insert(
            hash(state.secret()),
            Pending {
                org,
                provider: provider.into(),
                browser_hash: hash(&browser),
                nonce,
                pkce,
                expires: Instant::now() + Duration::from_secs(300),
            },
        );
        Ok(Login {
            url: url.into(),
            browser,
        })
    }
    pub async fn complete(
        &self,
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
        let mut pending = self.pending.lock().await;
        let key = hash(state);
        let p = pending.get(&key).ok_or(AuthError)?;
        if p.org != org
            || p.provider != provider
            || p.expires <= Instant::now()
            || !bool::from(p.browser_hash.as_bytes().ct_eq(hash(browser).as_bytes()))
        {
            return Err(AuthError);
        }
        let p = pending.remove(&key).ok_or(AuthError)?;
        drop(pending);
        let a = self.authority(org, provider)?;
        let h = a.human.as_ref().ok_or(AuthError)?;
        let response = self
            .http
            .post(&h.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", h.client_id.as_str()),
                ("redirect_uri", self.redirect(a).as_str()),
                ("code_verifier", p.pkce.secret()),
            ])
            .send()
            .await
            .map_err(|_| AuthError)?;
        let response = Self::json_response(response).await?;
        let token = response["id_token"].as_str().ok_or(AuthError)?;
        let (claims, _) = self.verified(a, token, &h.client_id).await?;
        validate_id_claims(&claims, &h.client_id, &p.nonce, now())?;
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
