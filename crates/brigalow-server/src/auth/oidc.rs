use super::*;
use openidconnect::{
    core::{CoreClient, CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreResponseType},
    AuthUrl, AuthenticationFlow, ClientId, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl,
};
pub(super) struct Pending {
    org: Uuid,
    provider: String,
    browser_hash: String,
    nonce: Nonce,
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
        let client = CoreClient::new(
            ClientId::new(h.client_id.clone()),
            IssuerUrl::new(a.issuer.clone()).map_err(|_| AuthError)?,
            CoreJsonWebKeySet::new(vec![]),
        )
        .set_auth_uri(AuthUrl::new(h.authorization_url.clone()).map_err(|_| AuthError)?)
        .set_redirect_uri(RedirectUrl::new(self.redirect(a)).map_err(|_| AuthError)?);
        let (challenge, pkce) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(openidconnect::Scope::new("groups".into()))
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
        let (claims, keys) = self.verified(a, token, &h.client_id).await?;
        let id: CoreIdToken = token.parse().map_err(|_| AuthError)?;
        let verifier = CoreIdTokenVerifier::new_public_client(
            ClientId::new(h.client_id.clone()),
            IssuerUrl::new(a.issuer.clone()).map_err(|_| AuthError)?,
            serde_json::from_value(keys).map_err(|_| AuthError)?,
        );
        id.claims(&verifier, &p.nonce).map_err(|_| AuthError)?;
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
