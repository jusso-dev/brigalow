use super::*;
impl Identity {
    pub async fn workload(
        &self,
        org: Uuid,
        token: &str,
        scope: &Scope,
    ) -> Result<Principal, AuthError> {
        self.verify_workload(org, token, Some(scope)).await
    }
    pub async fn verify_workload(
        &self,
        org: Uuid,
        token: &str,
        scope: Option<&Scope>,
    ) -> Result<Principal, AuthError> {
        if token.len() > 16384 {
            return Err(AuthError);
        }
        // Unverified issuer only selects from pinned configuration; it never selects a network URL.
        let raw = token.split('.').nth(1).ok_or(AuthError)?;
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(raw).map_err(|_| AuthError)?)
                .map_err(|_| AuthError)?;
        let issuer = claims["iss"].as_str().ok_or(AuthError)?;
        let a = self
            .config
            .authorities
            .iter()
            .find(|a| a.org_id == org && a.issuer == issuer && !a.workloads.is_empty())
            .ok_or(AuthError)?;
        let (claims, _) = self.verified(a, token, &format!("brigalow:{org}")).await?;
        // CI identity must be short-lived; an exp-only, arbitrarily long token is insufficient.
        let issued = claims["iat"].as_i64().ok_or(AuthError)?;
        let expires = claims["exp"].as_i64().ok_or(AuthError)?;
        if issued > now() + 30 || expires - issued > 3600 || issued >= expires {
            return Err(AuthError);
        }
        let rule = a
            .workloads
            .iter()
            .find(|r| {
                scope.is_none_or(|scope| r.project == scope.project && r.policy == scope.policy)
                    && r.claims
                        .iter()
                        .all(|(k, v)| claims.get(k).and_then(|c| c.as_str()) == Some(v.as_str()))
            })
            .ok_or(AuthError)?;
        Self::principal(
            a,
            &claims,
            vec![Role::Submitter],
            Some(Scope {
                project: rule.project,
                policy: rule.policy,
            }),
            false,
        )
    }
}
