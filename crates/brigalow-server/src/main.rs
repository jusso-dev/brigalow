//! Brigalow server. Scaffold only: prints its version and exits.

fn main() {
    println!(
        "brigalow-server {} (scaffold, not for production)",
        env!("CARGO_PKG_VERSION")
    );
    let _ = brigalow_core::Purpose::Test;
}
