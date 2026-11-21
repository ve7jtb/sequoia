//! Explicit, local-only hardware test. No mail/network, provisioning, or
//! certificate writes to the device occur here. A wrapper takes read-only
//! before/after snapshots and supplies a public certificate matching the key.

use anyhow::{bail, ensure, Context, Result};
use pgp::{
    crypto::{SessionKey, Signer},
    packet::{signature::SignatureBuilder, PKESK, SKESK},
    parse::{
        stream::{
            DecryptionHelper, DecryptorBuilder, MessageLayer, MessageStructure, VerificationHelper,
        },
        Parse,
    },
    policy::StandardPolicy,
    serialize::{
        stream::{Encryptor, LiteralWriter, Message},
        Serialize,
    },
    types::{HashAlgorithm, PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm},
    Cert, KeyHandle,
};
use sequoia_openpgp as pgp;
use sequoia_pqmail_piv::{
    process::{Config, Pkcs11Operation},
    public_spki, Level3Decryptor, Level3Signer, Operation, PublicKey,
};
use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use zeroize::Zeroizing;

/// Refuse ambiguity instead of selecting the first matching certificate key.
/// Certification-only keys and classical fallback keys are excluded by flags
/// and algorithms. The older combined certification/signing primary is allowed
/// only if it is the sole valid hybrid signing key.
fn selected(cert: &Cert) -> Result<(PublicKey, PublicKey)> {
    let p = StandardPolicy::new();
    ensure!(!cert.is_tsk(), "Supply a public-only certificate");
    let signing: Vec<_> = cert
        .keys()
        .with_policy(&p, None)
        .alive()
        .revoked(false)
        .for_signing()
        .filter(|k| k.key().pk_algo() == PublicKeyAlgorithm::MLDSA65_Ed25519)
        .map(|k| k.key().clone().role_into_unspecified())
        .collect();
    let encryption: Vec<_> = cert
        .keys()
        .with_policy(&p, None)
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .filter(|k| k.key().pk_algo() == PublicKeyAlgorithm::MLKEM768_X25519)
        .map(|k| k.key().clone().role_into_unspecified())
        .collect();
    ensure!(
        signing.len() == 1 && encryption.len() == 1,
        "Expected exactly one valid Level 3 hybrid signing and encryption key"
    );
    ensure!(
        signing[0].version() == 6 && encryption[0].version() == 6,
        "Expected version-6 subkeys"
    );
    Ok((signing[0].clone(), encryption[0].clone()))
}

/// Export only the four expected public components, for a PIN-free comparison
/// against the live token. The wrapper will refuse the hardware test if any
/// of these differs from the corresponding slot in its before snapshot.
fn expected_keys(sign: &PublicKey, kem: &PublicKey, out: &Path) -> Result<()> {
    use pgp::crypto::mpi::PublicKey as M;
    let M::MLDSA65_Ed25519 { mldsa, eddsa } = sign.mpis() else {
        unreachable!()
    };
    let M::MLKEM768_X25519 { mlkem, ecdh } = kem.mpis() else {
        unreachable!()
    };
    for (slot, op, raw) in [
        ("9c", Operation::MlDsa65, mldsa.as_slice()),
        ("84", Operation::Ed25519, eddsa.as_slice()),
        ("9d", Operation::MlKem768, mlkem.as_slice()),
        ("85", Operation::X25519, ecdh.as_slice()),
    ] {
        fs::write(
            out.join(format!("expected-{slot}.der")),
            public_spki(op, raw)?,
        )?;
    }
    println!(
        "Validated v6 certificate; hybrid signing {}, encryption {}",
        sign.fingerprint(),
        kem.fingerprint()
    );
    Ok(())
}

fn config() -> Result<Config> {
    // These are public application paths and an explicit serial, never secrets.
    let path = |name| -> Result<PathBuf> { Ok(PathBuf::from(env::var(name)?)) };
    let cfg = Config {
        python: path("PQMAIL_PYTHON")?,
        adapters: path("PQMAIL_ADAPTERS")?,
        openssl: path("OPENSSL_BIN")?,
        provider: path("PKCS11_PROVIDER")?,
        module: path("PKCS11_MODULE")?,
        serial: env::var("PKCS11_SERIAL")?,
    };
    cfg.validate()?;
    Ok(cfg)
}

fn authorize(cfg: &Config, operation: &str) -> Result<Pkcs11Operation> {
    eprintln!(
        "{operation} on YubiKey {}. Touch when it flashes. No automatic retry.",
        cfg.serial
    );
    // rpassword reads the user's controlling terminal with echo disabled.
    // The prompt's String and the backend's byte buffer both wipe on drop.
    let pin = Zeroizing::new(rpassword::prompt_password("YubiKey PIN (not saved): ")?);
    Pkcs11Operation::new(cfg.clone(), Zeroizing::new(pin.as_bytes().to_vec()))
}

/// Strict helper for this unsigned synthetic encryption test only. Production
/// mail must implement its own certificate/trust and signature policy.
struct Reader {
    cert: Cert,
    key: Level3Decryptor<Pkcs11Operation>,
}
impl VerificationHelper for Reader {
    fn get_certs(&mut self, _: &[KeyHandle]) -> Result<Vec<Cert>> {
        Ok(Vec::new())
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        let mut encrypted = false;
        for layer in structure.iter() {
            match layer {
                MessageLayer::Encryption { aead_algo, .. } => {
                    ensure!(
                        aead_algo.is_some(),
                        "Test requires authenticated AEAD encryption"
                    );
                    encrypted = true;
                }
                MessageLayer::Compression { .. } => {}
                MessageLayer::SignatureGroup { .. } => {
                    bail!("Unexpected signature in unsigned encryption fixture")
                }
            }
        }
        ensure!(encrypted, "Test message was not encrypted");
        Ok(())
    }
}
impl DecryptionHelper for Reader {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        skesks: &[SKESK],
        hint: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<Cert>> {
        use pgp::crypto::Decryptor;
        // Avoid trying several packets with one PIN authorization. The fixture
        // must have one explicit, matching v6 recipient and no password mode.
        ensure!(
            pkesks.len() == 1 && skesks.is_empty(),
            "Unexpected recipient count or password encryption"
        );
        ensure!(matches!(&pkesks[0], PKESK::V6(_)), "Expected v6 PKESK");
        ensure!(
            pkesks[0].recipient() == Some(self.key.public().fingerprint().into()),
            "Recipient fingerprint mismatch"
        );
        let (algorithm, session) = pkesks[0]
            .decrypt(&mut self.key, hint)
            .context("Hybrid session-key recovery failed; no retry")?;
        ensure!(
            decrypt(algorithm, &session),
            "Encrypted message authentication failed"
        );
        Ok(Some(self.cert.clone()))
    }
}

fn decrypt_fixture(
    cfg: &Config,
    cert: &Cert,
    public: &PublicKey,
    ciphertext: &[u8],
    expected: &[u8],
    label: &str,
) -> Result<()> {
    let backend = authorize(cfg, label)?;
    let start = Instant::now();
    let helper = Reader {
        cert: cert.clone(),
        key: Level3Decryptor::new(public.clone(), backend)?,
    };
    let policy = StandardPolicy::new();
    let mut reader =
        DecryptorBuilder::from_bytes(ciphertext)?.with_policy(&policy, None, helper)?;
    let mut clear = Zeroizing::new(Vec::new());
    // Keep the fixture reader bounded too; a test must not turn into a general
    // attacker-controlled decompression or arbitrary file import service.
    reader.by_ref().take(64 * 1024).read_to_end(&mut clear)?;
    ensure!(clear.as_slice() == expected, "Recovered plaintext mismatch");
    println!(
        "PASS {label}: authenticated plaintext matches ({:.0} ms, including touch wait)",
        start.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().collect();
    ensure!(
        args.len() == 4,
        "Usage: piv-test inspect|test PUBLIC_CERT OUTPUT_DIRECTORY"
    );
    let cert = Cert::from_file(&args[2])?;
    let out = PathBuf::from(&args[3]);
    ensure!(out.is_dir(), "Create a new result directory first");
    let (sign, kem) = selected(&cert)?;
    expected_keys(&sign, &kem, &out)?;
    if args[1] == "inspect" {
        return Ok(());
    }
    ensure!(args[1] == "test", "Unknown command");
    let cfg = config()?;

    // A local synthetic MIME entity also lets PQ Mail's independent parser
    // check the detached signature, without loading user messages or accounts.
    let body = b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nSynthetic Sequoia YubiKey Level 3 interoperability test.\r\n";
    fs::write(out.join("message.mime"), body)?;
    let backend = authorize(&cfg, "Hybrid signing: ML-DSA-65 slot 9c + Ed25519 slot 84")?;
    let start = Instant::now();
    let mut signer = Level3Signer::new(sign.clone(), backend)?;
    let sig = SignatureBuilder::new(SignatureType::Binary)
        .set_hash_algo(HashAlgorithm::SHA384)
        .sign_message(&mut signer, body)?;
    sig.verify_message(signer.public(), body)?;
    let mut signature_file = fs::File::create(out.join("signature.pgp"))?;
    // Serialize a complete OpenPGP signature packet, including its packet
    // header; serializing Signature's body alone is not an importable file.
    pgp::Packet::Signature(sig).serialize(&mut signature_file)?;
    println!(
        "PASS hybrid signature verified by Sequoia ({:.0} ms, including touch wait)",
        start.elapsed().as_secs_f64() * 1000.0
    );

    // Sequoia performs public-key encapsulation and AEAD encryption in software;
    // only session-key recovery requires the YubiKey.
    let policy = StandardPolicy::new();
    let recipients = cert
        .keys()
        .with_policy(&policy, None)
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .filter(|k| k.key().fingerprint() == kem.fingerprint());
    let mut encrypted = Vec::new();
    let message = Encryptor::for_recipients(Message::new(&mut encrypted), recipients).build()?;
    let mut literal = LiteralWriter::new(message).build()?;
    literal.write_all(body)?;
    literal.finalize()?;
    fs::write(out.join("sequoia-encrypted.pgp"), &encrypted)?;
    decrypt_fixture(
        &cfg,
        &cert,
        &kem,
        &encrypted,
        body,
        "Sequoia encryption → PIV ML-KEM-768 slot 9d + X25519 slot 85",
    )?;

    // The wrapper prepares this independent PQ Mail/Bouncy Castle ciphertext
    // before starting. Requiring it prevents reporting cross-implementation
    // success on only a same-library round trip.
    let incoming = fs::read(out.join("pqmail-encrypted.pgp"))?;
    decrypt_fixture(
        &cfg,
        &cert,
        &kem,
        &incoming,
        body,
        "PQ Mail encryption → Sequoia/PIV hybrid decryption",
    )?;
    fs::write(
        out.join("crypto-result.txt"),
        "PASS hybrid signing and both authenticated decryption fixtures\n",
    )?;
    Ok(())
}
