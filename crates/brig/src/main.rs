use brigalow_core::audit::{Entry, Verifier};
use std::io::{BufRead, BufReader, Read};

fn verify(path: &std::ffi::OsStr) -> Result<u64, String> {
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
    verifier.finish().map_err(|e| e.to_string())
}

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--version" {
        println!("brig {}", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    if args.len() != 3 || args[0] != "audit" || args[1] != "verify" {
        eprintln!("usage: brig audit verify <export.jsonl>");
        return std::process::ExitCode::FAILURE;
    }
    match verify(&args[2]) {
        Ok(count) => {
            println!(
                "Verified {count} audit entries (chain integrity only; no signed checkpoint)."
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
