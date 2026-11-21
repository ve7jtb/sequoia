//! Sign one local synthetic MIME message through the existing PKCS#11 adapter.
//! This utility has no network, provisioning, certificate-write, or policy API.
//! Its caller publishes the verified output only after choosing a destination.
use anyhow::{ensure, Result};
use sequoia_openpgp as pgp;
use pgp::{Cert, parse::Parse, policy::StandardPolicy, types::{PublicKeyAlgorithm, CompressionAlgorithm},
    serialize::stream::{Message, Compressor, Signer, LiteralWriter}};
use sequoia_pqmail_piv::{Level3Signer, process::{Config, Pkcs11Operation}};
use std::{env, fs::{self, OpenOptions}, io::Write, path::PathBuf};
use zeroize::Zeroizing;

fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().collect();
    ensure!(args.len() == 4, "Usage: piv-sign-message PUBLIC_CERT MIME_INPUT NEW_OUTPUT");
    // Parse public material and use policy-validated signing flags. Never select
    // the certification-only primary or a classical compatibility signing key.
    let cert = Cert::from_file(&args[1])?;
    ensure!(!cert.is_tsk(), "Public certificate required");
    let policy = StandardPolicy::new();
    let keys: Vec<_> = cert.keys().with_policy(&policy, None).alive().revoked(false)
        .for_signing().filter(|k| k.key().pk_algo() == PublicKeyAlgorithm::MLDSA65_Ed25519)
        .map(|k| k.key().clone().role_into_unspecified()).collect();
    ensure!(keys.len() == 1 && keys[0].version() == 6, "One valid v6 hybrid signing key required");
    // The input is a synthetic local test, bounded before any PIN request. The
    // binary signature protects its exact bytes, including MIME CRLF endings.
    ensure!(fs::metadata(&args[2])?.len() <= 65536, "Test MIME exceeds 64 KiB");
    let clear = fs::read(&args[2])?;
    let path = |name| -> Result<PathBuf> { Ok(PathBuf::from(env::var(name)?)) };
    let cfg = Config { python: path("PQMAIL_PYTHON")?, adapters: path("PQMAIL_ADAPTERS")?,
        openssl: path("OPENSSL_BIN")?, provider: path("PKCS11_PROVIDER")?,
        module: path("PKCS11_MODULE")?, serial: env::var("PKCS11_SERIAL")? };
    cfg.validate()?;
    // Refuse an existing output. Do not leave a partial signature file when
    // authorization or hardware signing fails; assemble and finalize in memory.
    ensure!(!PathBuf::from(&args[3]).exists(), "Output already exists");
    eprintln!("Sequoia hybrid signing on YubiKey {}: ML-DSA-65 in 9c + Ed25519 in 84.", cfg.serial);
    eprintln!("Enter PIN here; touch if the existing policy requests it. No keys or policies change.");
    let pin = Zeroizing::new(rpassword::prompt_password("YubiKey PIN (not saved): ")?);
    let operation = Pkcs11Operation::new(cfg, Zeroizing::new(pin.as_bytes().to_vec()))?;
    drop(pin);
    let signer = Level3Signer::new(keys[0].clone(), operation)?;
    let mut output = Vec::new();
    {
        // Standard OpenPGP compression, one-pass signature, literal data and
        // signature packets make the attachment independently readable by sq.
        let compressed = Compressor::new(Message::new(&mut output)).algo(CompressionAlgorithm::Zlib).build()?;
        let signed = Signer::new(compressed, signer)?.build()?;
        let mut literal = LiteralWriter::new(signed).build()?;
        literal.write_all(&clear)?;
        literal.finalize()?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(&args[3])?;
    file.write_all(&output)?;
    file.sync_all()?;
    println!("Signed using v6 subkey {}. Verify before sending.", keys[0].fingerprint());
    Ok(())
}
