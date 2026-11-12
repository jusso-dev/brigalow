//! GitLab CI ID-token profile (test-purpose signing only).
//!
//! Pure checks applied only after signature, issuer, audience and time verification. The
//! profile is selected by operator configuration, never by token contents or host. Mapped
//! claims follow `plans/003-gitlab-outcome.md` and `docs/threat-model.md`: only `ref_path`
//! becomes canonical `ref`; repository/workflow semantics are deliberately not mapped.
use brigalow_core::policy::PROVIDER_CLAIM;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const PROFILE: &str = "gitlab";
/// GitHub-shaped canonical names whose GitLab equivalence is unproven. A GitLab token
/// carrying any of them is ambiguous and fails closed instead of being reinterpreted.
const CONFLICTING: [&str; 5] = [
    "repository",
    "workflow",
    "job_workflow_ref",
    "run_id",
    PROVIDER_CLAIM,
];
/// Sources whose source/target project relationship is unresolved; never configurable.
const REFUSED_SOURCES: [&str; 2] = ["merge_request_event", "external_pull_request_event"];

/// Operator-owned expectations for one GitLab workload rule. All matches are exact.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitlabRule {
    /// Issuer-scoped numeric project ID; must equal both `project_id` and `job_project_id`.
    pub project_id: String,
    /// Full project path; must equal both `project_path` and `job_project_path`.
    pub project_path: String,
    /// Fully qualified ref, `refs/heads/<branch>` or `refs/tags/<tag>`.
    pub ref_path: String,
    /// Exact allowed `pipeline_source` values. Merge-request sources are refused.
    pub pipeline_sources: Vec<String>,
    /// When set, the signed `environment` claim must equal it exactly.
    #[serde(default)]
    pub environment: Option<String>,
}

fn split_ref(path: &str) -> Option<(&'static str, &str)> {
    [("branch", "refs/heads/"), ("tag", "refs/tags/")]
        .into_iter()
        .find_map(|(kind, prefix)| {
            path.strip_prefix(prefix)
                .filter(|short| !short.is_empty())
                .map(|short| (kind, short))
        })
}

fn numeric(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit())
}

impl GitlabRule {
    pub fn valid(&self) -> bool {
        let path = &self.project_path;
        numeric(&self.project_id)
            && !path.is_empty()
            && path.len() <= 255
            && path.bytes().all(|b| b.is_ascii_graphic())
            && path.contains('/')
            && !path.starts_with('/')
            && !path.ends_with('/')
            && self.ref_path.len() <= 1024
            && !self.ref_path.chars().any(char::is_control)
            && split_ref(&self.ref_path).is_some()
            && !self.pipeline_sources.is_empty()
            && self.pipeline_sources.len() <= 8
            && self.pipeline_sources.iter().all(|s| {
                !s.is_empty()
                    && s.len() <= 64
                    && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                    && !REFUSED_SOURCES.contains(&s.as_str())
            })
            && self
                .environment
                .as_deref()
                .is_none_or(|e| !e.is_empty() && e.len() <= 255 && !e.chars().any(char::is_control))
    }
}

/// Signed claims must be non-empty JSON strings; any other type fails closed.
fn text<'a>(claims: &'a Map<String, Value>, name: &'static str) -> Result<&'a str, &'static str> {
    match claims.get(name) {
        Some(Value::String(s)) if !s.is_empty() && s.len() <= 1024 => Ok(s),
        _ => Err(name),
    }
}

fn exact<'a>(
    claims: &'a Map<String, Value>,
    name: &'static str,
    expected: &str,
) -> Result<&'a str, &'static str> {
    text(claims, name).and_then(|v| if v == expected { Ok(v) } else { Err(name) })
}

/// Returns the normalised principal claims, or the name of the first failed claim.
pub fn normalise(
    rule: &GitlabRule,
    claims: &Value,
) -> Result<BTreeMap<String, String>, &'static str> {
    let c = claims.as_object().ok_or("claims")?;
    if let Some(name) = CONFLICTING.into_iter().find(|n| c.contains_key(*n)) {
        return Err(name);
    }
    let iss = text(c, "iss")?;
    let sub = text(c, "sub")?;
    // Job project claims are documented from GitLab 18.4; their absence fails closed.
    exact(c, "job_project_id", &rule.project_id)?;
    exact(c, "job_project_path", &rule.project_path)?;
    // Source project must be the same project: mixed job/source pipelines are refused.
    exact(c, "project_id", &rule.project_id)?;
    exact(c, "project_path", &rule.project_path)?;
    let ref_path = text(c, "ref_path")?;
    let (kind, short) = split_ref(ref_path).ok_or("ref_path")?;
    if text(c, "ref_type")? != kind {
        return Err("ref_type");
    }
    if text(c, "ref")? != short {
        return Err("ref");
    }
    if ref_path != rule.ref_path {
        return Err("ref_path");
    }
    exact(c, "ref_protected", "true")?;
    let source = text(c, "pipeline_source")?;
    if !rule.pipeline_sources.iter().any(|s| s == source) {
        return Err("pipeline_source");
    }
    let environment = match (&rule.environment, c.get("environment")) {
        (Some(expected), _) => Some(exact(c, "environment", expected)?),
        (None, None) => None,
        (None, Some(_)) => Some(text(c, "environment")?),
    };
    let sha = text(c, "sha")?;
    if !matches!(sha.len(), 40 | 64) || !sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("sha");
    }
    let mut out = BTreeMap::from([
        (PROVIDER_CLAIM, PROFILE),
        ("iss", iss),
        ("sub", sub),
        ("ref", ref_path),
        ("ref_type", kind),
        ("sha", sha),
        ("project_id", rule.project_id.as_str()),
        ("project_path", rule.project_path.as_str()),
        ("job_project_id", rule.project_id.as_str()),
        ("job_project_path", rule.project_path.as_str()),
        ("pipeline_source", source),
    ]);
    if let Some(environment) = environment {
        out.insert("environment", environment);
    }
    // Provider identifiers are carried for review only; wrong types still fail closed.
    for name in ["pipeline_id", "job_id"] {
        if c.contains_key(name) {
            let id = text(c, name)?;
            if !numeric(id) {
                return Err(name);
            }
            out.insert(name, id);
        }
    }
    Ok(out
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn rule() -> GitlabRule {
        GitlabRule {
            project_id: "42".into(),
            project_path: "platform/app".into(),
            ref_path: "refs/heads/main".into(),
            pipeline_sources: vec!["push".into()],
            environment: Some("signing-test".into()),
        }
    }
    fn claims() -> Value {
        json!({
            "iss": "https://gitlab.test",
            "sub": "project_path:platform/app:ref_type:branch:ref:main",
            "project_id": "42",
            "project_path": "platform/app",
            "job_project_id": "42",
            "job_project_path": "platform/app",
            "ref": "main",
            "ref_type": "branch",
            "ref_path": "refs/heads/main",
            "ref_protected": "true",
            "pipeline_source": "push",
            "pipeline_id": "574",
            "job_id": "302",
            "environment": "signing-test",
            "environment_protected": "true",
            "sha": "714a629c0b401fdce83e847fc9589983fc6f46bc",
            "ci_config_ref_uri": "gitlab.test/platform/app//.gitlab-ci.yml@refs/heads/main",
            "runner_id": 1
        })
    }
    #[test]
    fn maps_only_verified_profile_claims() {
        let out = normalise(&rule(), &claims()).unwrap();
        assert_eq!(out["provider"], "gitlab");
        assert_eq!(out["ref"], "refs/heads/main");
        assert_eq!(out["environment"], "signing-test");
        assert_eq!(out["job_id"], "302");
        for absent in [
            "repository",
            "workflow",
            "ref_protected",
            "ci_config_ref_uri",
            "environment_protected",
        ] {
            assert!(!out.contains_key(absent), "{absent} must not be mapped");
        }
        let mut tag = claims();
        tag["ref"] = json!("v1.0.0");
        tag["ref_type"] = json!("tag");
        tag["ref_path"] = json!("refs/tags/v1.0.0");
        let mut r = rule();
        r.ref_path = "refs/tags/v1.0.0".into();
        assert!(normalise(&r, &tag).is_ok());
        // Unconfigured environment: absent is fine, present must still be a string.
        r = rule();
        r.environment = None;
        let mut c = claims();
        c.as_object_mut().unwrap().remove("environment");
        assert!(!normalise(&r, &c).unwrap().contains_key("environment"));
        c["environment"] = json!(7);
        assert_eq!(normalise(&r, &c), Err("environment"));
        let mut long = claims();
        long["sha"] = json!("a".repeat(64));
        assert!(normalise(&rule(), &long).is_ok());
    }
    #[test]
    fn mismatches_types_and_conflicts_fail_closed() {
        let cases: Vec<(&str, Option<Value>, &str)> = vec![
            ("job_project_id", None, "job_project_id"),
            ("job_project_path", None, "job_project_path"),
            ("job_project_id", Some(json!("43")), "job_project_id"),
            ("job_project_id", Some(json!(42)), "job_project_id"),
            ("project_id", Some(json!("43")), "project_id"),
            ("project_path", Some(json!("fork/app")), "project_path"),
            ("project_path", None, "project_path"),
            ("ref_path", Some(json!("main")), "ref_path"),
            ("ref_path", Some(json!("refs/heads/")), "ref_path"),
            ("ref_path", Some(json!("refs/heads/feature")), "ref"),
            ("ref", Some(json!("refs/heads/main")), "ref"),
            ("ref_type", Some(json!("tag")), "ref_type"),
            ("ref_type", None, "ref_type"),
            ("ref_protected", Some(json!("false")), "ref_protected"),
            ("ref_protected", Some(json!(true)), "ref_protected"),
            ("ref_protected", None, "ref_protected"),
            (
                "pipeline_source",
                Some(json!("merge_request_event")),
                "pipeline_source",
            ),
            ("pipeline_source", Some(json!(["push"])), "pipeline_source"),
            ("environment", None, "environment"),
            ("environment", Some(json!("production")), "environment"),
            ("environment", Some(Value::Null), "environment"),
            (
                "sha",
                Some(json!("714A629C0B401FDCE83E847FC9589983FC6F46BC")),
                "sha",
            ),
            ("sha", Some(json!("abc")), "sha"),
            ("sha", None, "sha"),
            ("job_id", Some(json!(302)), "job_id"),
            ("pipeline_id", Some(json!("x1")), "pipeline_id"),
            ("repository", Some(json!("platform/app")), "repository"),
            ("workflow", Some(json!(".gitlab-ci.yml")), "workflow"),
            ("job_workflow_ref", Some(json!("x")), "job_workflow_ref"),
            ("run_id", Some(json!("1")), "run_id"),
            ("provider", Some(json!("gitlab")), "provider"),
        ];
        for (field, value, failed) in cases {
            let mut c = claims();
            match value {
                Some(v) => c[field] = v,
                None => {
                    c.as_object_mut().unwrap().remove(field);
                }
            }
            assert_eq!(normalise(&rule(), &c), Err(failed), "{field}");
        }
        // A job project different from its source project cannot satisfy one rule.
        let mut mixed = claims();
        mixed["project_id"] = json!("99");
        mixed["project_path"] = json!("fork/app");
        assert_eq!(normalise(&rule(), &mixed), Err("project_id"));
    }
    #[test]
    fn configuration_is_exact_and_refuses_merge_request_sources() {
        assert!(rule().valid());
        let bad: Vec<fn(&mut GitlabRule)> = vec![
            |r| r.project_id = "".into(),
            |r| r.project_id = "4a".into(),
            |r| r.project_path = "app".into(),
            |r| r.project_path = "/platform/app".into(),
            |r| r.project_path = "platform/app ".into(),
            |r| r.ref_path = "main".into(),
            |r| r.ref_path = "refs/heads/".into(),
            |r| r.ref_path = "refs/pull/1".into(),
            |r| r.pipeline_sources.clear(),
            |r| r.pipeline_sources = vec!["merge_request_event".into()],
            |r| r.pipeline_sources = vec!["external_pull_request_event".into()],
            |r| r.pipeline_sources = vec!["Push".into()],
            |r| r.environment = Some("".into()),
        ];
        for change in bad {
            let mut r = rule();
            change(&mut r);
            assert!(!r.valid());
        }
    }
}
