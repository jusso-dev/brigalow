mod sign;
use brigalow_core::audit::{Entry, Verifier};
use std::io::{BufRead, BufReader, Read};

fn verify(
    path: &std::ffi::OsStr,
    checkpoint: Option<(&std::ffi::OsStr, &std::ffi::OsStr)>,
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
    let checkpoint = if args.len() == 7 && args[3] == "--checkpoint" && args[5] == "--public-key" {
        Some((args[4].as_os_str(), args[6].as_os_str()))
    } else {
        None
    };
    if (args.len() != 3 && checkpoint.is_none()) || args[0] != "audit" || args[1] != "verify" {
        eprintln!("usage: brig audit verify <export.jsonl> [--checkpoint <checkpoint.json> --public-key <trusted.der>]");
        return std::process::ExitCode::FAILURE;
    }
    match verify(&args[2], checkpoint) {
        Ok(count) => {
            if checkpoint.is_some() {
                println!("Verified {count} audit entries and exact signed checkpoint.");
            } else {
                println!(
                    "Verified {count} audit entries (chain integrity only; no signed checkpoint)."
                );
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
