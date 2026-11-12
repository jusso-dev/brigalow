use super::*;
impl Identity {
    /// Diagnostic only: reverify before naming a failed configured claim in the audit log.
    pub async fn rejected_claim(
        &self,
        org: Uuid,
        token: &str,
        scope: &Scope,
    ) -> Option<(String, String)> {
        for a in self
            .config
            .authorities
            .iter()
            .filter(|a| a.org_id == org && !a.workloads.is_empty())
        {
            let Ok((claims, _)) = self.verified(a, token, &format!("brigalow:{org}")).await else {
                continue;
            };
            let rule = a
                .workloads
                .iter()
                .find(|r| r.project == scope.project && r.policy == scope.policy)?;
            let name = match rule
                .claims
                .iter()
                .find(|(k, v)| claims.get(*k).and_then(|c| c.as_str()) != Some(v.as_str()))
            {
                Some((name, _)) => name.clone(),
                None => match (a.provider, &rule.gitlab) {
                    (Provider::Gitlab, Some(g)) => gitlab::normalise(g, &claims).err()?.into(),
                    _ => return None,
                },
            };
            let p = Self::principal(a, &claims, vec![], None, false).ok()?;
            return Some((p.actor, name));
        }
        None
    }
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
        let lifetime = expires.checked_sub(issued).ok_or(AuthError)?;
        if issued > now() + 30 || !(1..=3600).contains(&lifetime) {
            return Err(AuthError);
        }
        // Each rule is checked in full; GitLab rules also yield their normalised claim set.
        let (rule, normalised) = a
            .workloads
            .iter()
            .filter(|r| {
                scope.is_none_or(|scope| r.project == scope.project && r.policy == scope.policy)
                    && r.claims
                        .iter()
                        .all(|(k, v)| claims.get(k).and_then(|c| c.as_str()) == Some(v.as_str()))
            })
            .find_map(|r| match (a.provider, &r.gitlab) {
                (Provider::Github, None) => Some((r, None)),
                (Provider::Gitlab, Some(g)) => {
                    gitlab::normalise(g, &claims).ok().map(|c| (r, Some(c)))
                }
                _ => None,
            })
            .ok_or(AuthError)?;
        let mut principal = Self::principal(
            a,
            &claims,
            vec![Role::Submitter],
            Some(Scope {
                project: rule.project,
                policy: rule.policy,
            }),
            false,
        )?;
        if let Some(normalised) = normalised {
            // Replace the GitHub-shaped copy entirely; only normalised GitLab claims remain.
            principal.claims = normalised;
        }
        Ok(principal)
    }
}
