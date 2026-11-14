use sequoia_openpgp as openpgp;
use openpgp::cert::CertBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::PublicKeyAlgorithmSpecification;

// Usage: cargo run --example generate-rsa-test-key -- 2048 > rsa2048-private.pgp
fn main() -> openpgp::Result<()> {
    let bits = std::env::args().nth(1)
        .ok_or_else(|| anyhow::anyhow!("Missing RSA key size"))?
        .parse()?;
    let (cert, _) = CertBuilder::new()
        .set_signing_algorithm(PublicKeyAlgorithmSpecification::rsa(bits))
        .add_userid(format!("RSA{} test key", bits))
        .generate()?;
    cert.as_tsk().armored().serialize(&mut std::io::stdout())?;
    Ok(())
}
