mod sign;
use brigalow_core::audit::{Entry, ExpectedHead, Verifier};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};

const USAGE: &str = "usage: brig audit verify <export.jsonl> [--checkpoint <checkpoint.json> --public-key <trusted.der> [--expected-head <org>:<seq>:<entry-hash>]]";

struct Options {
    export: OsString,
    checkpoint: Option<(OsString, OsString)>,
    expected: Option<ExpectedHead>,
}

/// Each option at most once; an expected head is only meaningful with a signed checkpoint.
fn options(args: &[OsString]) -> Option<Options> {
    let [audit, verify, export, rest @ ..] = args else {
        return None;
    };
    if audit != "audit" || verify != "verify" || rest.len() % 2 != 0 {
        return None;
    }
    let (mut checkpoint, mut public, mut expected) = (None, None, None);
    for pair in rest.chunks(2) {
        let slot = match pair[0].to_str()? {
            "--checkpoint" => &mut checkpoint,
            "--public-key" => &mut public,
            "--expected-head" => &mut expected,
            _ => return None,
        };
        if slot.replace(pair[1].clone()).is_some() {
            return None;
        }
    }
    let expected = match expected {
        Some(text) => Some(ExpectedHead::parse(text.to_str()?)?),
        None => None,
    };
    let checkpoint = match (checkpoint, public) {
        (Some(checkpoint), Some(public)) => Some((checkpoint, public)),
        (None, None) if expected.is_none() => None,
        _ => return None,
    };
    Some(Options {
        export: export.clone(),
        checkpoint,
        expected,
    })
}

fn verify(
    path: &std::ffi::OsStr,
    checkpoint: Option<(&std::ffi::OsStr, &std::ffi::OsStr)>,
    expected: Option<&ExpectedHead>,
) -> Result<u64, String> {
    let file = std::fs::File::open(path).map_err(|_| "cannot open audit export")?;
    let mut reader = BufReader::new(file);
    let mut verifier = Verifier::default();
    loop {
        let mut line = Vec::new();
        let size = reader
            .by_ref()
            .take(1_048_577)
            .read_until(b'\n', &mut line)
            .map_err(|_| "cannot read audit export")?;
        if size == 0 {
            break;
        }
        let seq = verifier.count() + 1;
        if size > 1_048_576 {
            return Err(format!(
                "audit verification failed at seq {seq}: line too large"
            ));
        }
        let entry: Entry = serde_json::from_slice(&line)
            .map_err(|_| format!("audit verification failed at seq {seq}: invalid entry"))?;
        verifier.push(&entry).map_err(|e| e.to_string())?;
    }
    if let Some((checkpoint, public)) = checkpoint {
        let read = |path: &std::ffi::OsStr| -> Result<Vec<u8>, String> {
            let mut bytes = vec![];
            std::fs::File::open(path)
                .map_err(|_| "cannot open checkpoint input")?
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(|_| "cannot read checkpoint input")?;
            if bytes.len() > 65536 {
                return Err("checkpoint input too large".into());
            }
            Ok(bytes)
        };
        let signed: brigalow_core::audit::SignedCheckpoint =
            serde_json::from_slice(&read(checkpoint)?).map_err(|_| "invalid checkpoint")?;
        brigalow_crypto::audit::verify(&signed, &read(public)?)
            .map_err(|_| "checkpoint signature invalid")?;
        if !verifier.matches_checkpoint(&signed.checkpoint) {
            return Err("audit export does not match exact signed checkpoint".into());
        }
        if expected.is_some_and(|head| !head.matches(&signed.checkpoint)) {
            return Err("signed checkpoint does not match the expected head (older, newer or substituted checkpoint)".into());
        }
    }
    verifier.finish().map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "sign") {
        return match sign::run(&args[1..]).await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    if args.len() == 1 && args[0] == "--version" {
        println!("brig {}", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    let Some(options) = options(&args) else {
        eprintln!("{USAGE}");
        return std::process::ExitCode::FAILURE;
    };
    let checkpoint = options
        .checkpoint
        .as_ref()
        .map(|(checkpoint, public)| (checkpoint.as_os_str(), public.as_os_str()));
    match verify(&options.export, checkpoint, options.expected.as_ref()) {
        Ok(count) => {
            match (&options.checkpoint, &options.expected) {
                (Some(_), Some(head)) => println!(
                    "Verified {count} audit entries and exact signed checkpoint matching the independently retained expected head (org {}, seq {}, entry hash {}).",
                    head.org_id, head.seq, head.entry_hash
                ),
                (Some(_), None) => println!(
                    "Verified {count} audit entries and exact signed checkpoint: cryptographically valid prefix; freshness unknown (no independently retained expected head supplied)."
                ),
                _ => println!(
                    "Verified {count} audit entries (chain integrity only; no signed checkpoint)."
                ),
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
