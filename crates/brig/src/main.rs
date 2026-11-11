//! `brig` CLI. Scaffold only: prints its version and exits.

fn main() {
    println!("brig {} (scaffold)", env!("CARGO_PKG_VERSION"));
    let _ = brigalow_core::TrustTier::Lab;
}
