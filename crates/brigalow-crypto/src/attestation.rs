//! DSSE framing is protocol encoding; signatures use the configured custody backend.
use crate::{Error, Key, KeyBackend, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use brigalow_core::policy::SignRequest;
use serde_json::{json, Value};
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub fn provenance(backend: &dyn KeyBackend, key: &Key, request: &SignRequest) -> Result<Value> {
    let claims = &request.verified_claims;
    let claim = |name| {
        claims
            .get(name)
            .filter(|s| !s.is_empty())
            .ok_or(Error::Unavailable)
    };
    let issuer = claim("iss")?;
    let actor = claim("sub")?;
    let repository = claim("repository")?;
    let commit = claim("sha")?;
    let workflow = claim("workflow")?;
    let digest = request
        .submission
        .digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let payload=serde_json::to_vec(&json!({
        "_type":"https://in-toto.io/Statement/v1",
        "subject":[{"name":request.submission.artifact_name,"digest":{"sha256":digest}}],
        "predicateType":"https://slsa.dev/provenance/v1",
        "predicate":{
            "buildDefinition":{
                "buildType":"https://github.com/jusso-dev/brigalow/blob/main/docs/attestation-v1.md",
                "externalParameters":{"repository":repository,"commit":commit,"workflow":workflow,"ref":claims.get("ref")},
                "internalParameters":{},
                "resolvedDependencies":[{"name":repository,"digest":{"gitCommit":commit}}]
            },
            "runDetails":{
                "builder":{"id":issuer},
                "metadata":{"invocationId":request.submission.request_id.to_string()},
                "byproducts":[{"name":"verified-identity","content":STANDARD.encode(serde_json::to_vec(&json!({"issuer":issuer,"subject":actor,"workflow":workflow})).map_err(|_|Error::Algorithm)?)}]
            }
        }
    })).map_err(|_|Error::Algorithm)?;
    let mut pae = format!(
        "DSSEv1 {} {} {} ",
        PAYLOAD_TYPE.len(),
        PAYLOAD_TYPE,
        payload.len()
    )
    .into_bytes();
    pae.extend_from_slice(&payload);
    let signature = backend.sign_message(key, &pae)?;
    Ok(
        json!({"payloadType":PAYLOAD_TYPE,"payload":STANDARD.encode(payload),"signatures":[{"keyid":key.id.to_string(),"sig":STANDARD.encode(signature)}]}),
    )
}
