//! One-time generator for the shipped, PUBLIC DigNetwork CA.
//!
//! Run ONCE to mint `src/ca/dig_ca.crt` + `src/ca/dig_ca.key` (both public — see `ca` module docs),
//! which are then compiled into the crate via `include_str!`. Re-running MINTS A NEW CA — do not run
//! it again unless the ecosystem is deliberately rotating the trust anchor (a breaking, coordinated
//! event). Provenance is documented in SPEC.md + the `canonical` skill.
//!
//! ```text
//! cargo run --example generate_ca
//! ```

use std::fs;
use std::path::Path;

use dig_tls::ca::generate_dig_ca;
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca = generate_dig_ca(OffsetDateTime::now_utc())?;
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ca");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("dig_ca.crt"), &ca.cert_pem)?;
    fs::write(dir.join("dig_ca.key"), &ca.key_pem)?;
    println!("Wrote the DigNetwork CA to {}", dir.display());
    println!("  dig_ca.crt ({} bytes)", ca.cert_pem.len());
    println!(
        "  dig_ca.key ({} bytes) — PUBLIC by design",
        ca.key_pem.len()
    );
    Ok(())
}
