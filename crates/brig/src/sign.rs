use brigalow_core::policy::{Format, Policy, RequestState, SignRequest, Submission};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
async fn bounded(response: reqwest::Response) -> Result<Vec<u8>, &'static str> {
    if !response.status().is_success() {
        return Err("server rejected request; no signature written");
    }
    let mut bytes = vec![];
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "cannot read server response")?;
        if bytes.len() + chunk.len() > 1048576 {
            return Err("server response too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "cannot create output (existing files are never overwritten)")?;
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        let _ = std::fs::remove_file(path);
        return Err("cannot write output");
    }
    Ok(())
}
pub async fn run(args: &[OsString]) -> Result<(), &'static str> {
    let mut options = BTreeMap::new();
    let mut file = None;
    let mut i = 0;
    while i < args.len() {
        let value = args[i].to_str().ok_or("arguments must be UTF-8")?;
        if value.starts_with("--") {
            if ![
                "--policy",
                "--format",
                "--project",
                "--org",
                "--server",
                "--output",
                "--ca-file",
            ]
            .contains(&value)
                || i + 1 >= args.len()
                || options
                    .insert(
                        value,
                        args[i + 1].to_str().ok_or("arguments must be UTF-8")?,
                    )
                    .is_some()
            {
                return Err("invalid or duplicate option");
            }
            i += 2;
        } else {
            if file.replace(PathBuf::from(&args[i])).is_some() {
                return Err("expected one artifact");
            }
            i += 1;
        }
    }
    let required = |name| {
        options
            .get(name)
            .copied()
            .ok_or("required: --server --org --project --policy --output and artifact")
    };
    let org: Uuid = required("--org")?
        .parse()
        .map_err(|_| "invalid organisation")?;
    let project: Uuid = required("--project")?
        .parse()
        .map_err(|_| "invalid project")?;
    let mut base = reqwest::Url::parse(required("--server")?).map_err(|_| "invalid server URL")?;
    if base.scheme() != "https"
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err("server requires HTTPS without URL credentials");
    }
    base.set_path("/");
    let token = std::env::var("BRIGALOW_TOKEN").map_err(|_| "BRIGALOW_TOKEN required")?;
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(120));
    if let Some(path) = options.get("--ca-file") {
        let cert = std::fs::read(path).map_err(|_| "cannot read server CA")?;
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&cert).map_err(|_| "invalid server CA")?,
        );
    }
    let client = builder
        .build()
        .map_err(|_| "cannot initialise HTTP client")?;
    let policy = required("--policy")?;
    let url = if let Ok(id) = policy.parse::<Uuid>() {
        base.join(&format!("v1/orgs/{org}/policies/{id}"))
    } else {
        if policy.is_empty()
            || !policy
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("invalid policy name");
        }
        base.join(&format!(
            "v1/orgs/{org}/projects/{project}/policies/{policy}"
        ))
    }
    .map_err(|_| "invalid policy URL")?;
    let policy: Policy = serde_json::from_slice(
        &bounded(
            client
                .get(url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|_| "server connection failed")?,
        )
        .await?,
    )
    .map_err(|_| "invalid policy response")?;
    if policy.project != project {
        return Err("policy does not belong to project");
    }
    let format = match options.get("--format").copied().unwrap_or("raw") {
        "raw" => Format::Raw,
        "cms" => Format::Cms,
        _ => return Err("format must be raw or cms"),
    };
    let path = file.ok_or("artifact required")?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("invalid artifact name")?
        .to_string();
    let mut reader = std::fs::File::open(path).map_err(|_| "cannot read artifact")?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = reader
            .read(&mut buffer)
            .map_err(|_| "cannot hash artifact")?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    let submission = Submission {
        request_id: Uuid::new_v4(),
        policy: policy.id,
        digest_alg: brigalow_core::keys::DigestAlgorithm::Sha256,
        digest: hash.finalize().into(),
        artifact_name: name,
        format,
        metadata: Default::default(),
    };
    let url = base
        .join(&format!("v1/orgs/{org}/projects/{project}/sign-requests"))
        .map_err(|_| "invalid signing URL")?;
    eprintln!("Submitting request {}", submission.request_id);
    let response = client
        .post(url)
        .bearer_auth(&token)
        .json(&submission)
        .send()
        .await
        .map_err(|_| "signing request interrupted; check request status before retry")?;
    let mut result: SignRequest = serde_json::from_slice(&bounded(response).await?)
        .map_err(|_| "invalid signing response")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    while result.state == RequestState::AwaitingApproval || result.state == RequestState::Signing {
        if std::time::Instant::now() >= deadline {
            return Err("approval still pending; query the submitted request ID (do not resubmit)");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let status = base
            .join(&format!("v1/orgs/{org}/requests/{}", submission.request_id))
            .map_err(|_| "invalid status URL")?;
        result = serde_json::from_slice(
            &bounded(
                client
                    .get(status)
                    .bearer_auth(&token)
                    .send()
                    .await
                    .map_err(|_| "cannot retrieve request status")?,
            )
            .await?,
        )
        .map_err(|_| "invalid request status")?;
    }
    if result.state != RequestState::Signed
        || result.submission.request_id != submission.request_id
        || result.submission.digest != submission.digest
        || result.submission.policy != policy.id
        || result.submission.format != submission.format
        || result.project != project
    {
        return Err("signature response does not match request");
    }
    let output = PathBuf::from(required("--output")?);
    let signature = result.output.ok_or("signature missing")?;
    let timestamp = PathBuf::from(format!("{}.tsr", output.display()));
    if output.exists() || (result.timestamp.is_some() && timestamp.exists()) {
        return Err("output already exists");
    }
    // All mandatory server checks complete before creating any result file.
    let wrote_timestamp = result.timestamp.is_some();
    if let Some(token) = result.timestamp {
        write_new(&timestamp, &token)?;
    }
    if let Err(error) = write_new(&output, &signature) {
        if wrote_timestamp {
            let _ = std::fs::remove_file(timestamp);
        }
        return Err(error);
    }
    println!("Signed request {}", submission.request_id);
    Ok(())
}
