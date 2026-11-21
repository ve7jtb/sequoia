//! Explicit, local-only hardware test. No mail/network, provisioning, or
//! certificate writes to the device occur here. A wrapper takes read-only
//! before/after snapshots and supplies a public certificate matching the key.

use anyhow::{ensure, Context, Result};
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
        stream::{Encryptor, Message},
        Serialize,
    },
    types::{DataFormat, HashAlgorithm, PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm},
    Cert, KeyHandle,
};
use sequoia_openpgp as pgp;
use sequoia_pqmail_piv::{
    level3_companion::{CompanionBackend, Envelope},
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
/// and algorithms. The companion envelope additionally requires separate
/// certification, signing, and encryption keys before any private operation.
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

/// Export the two hardware message public components, for a PIN-free comparison
/// against the live token. The wrapper will refuse the hardware test if any
/// of these differs from the corresponding slot in its before snapshot.
fn expected_keys(sign: &PublicKey, kem: &PublicKey, out: &Path) -> Result<()> {
    use pgp::crypto::mpi::PublicKey as M;
    let M::MLDSA65_Ed25519 { eddsa, .. } = sign.mpis() else {
        unreachable!()
    };
    let M::MLKEM768_X25519 { ecdh, .. } = kem.mpis() else {
        unreachable!()
    };
    // Only classical components are physically present in this reverse polyfill.
    // The complete, authenticated live key mapping is checked by restore/authorize.
    for (slot, op, raw) in [
        ("9c", Operation::Ed25519, eddsa.as_slice()),
        ("9d", Operation::X25519, ecdh.as_slice()),
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
    if env::var("PQMAIL_SYNTHETIC_COMPANION").as_deref() == Ok("1") {
        ensure!(cfg.serial == "123456", "Synthetic test serial required");
    }
    Ok(cfg)
}

fn authorize(
    cfg: &Config,
    operation: &str,
    expected: &Cert,
) -> Result<CompanionBackend<Pkcs11Operation>> {
    let folder = PathBuf::from(env::var("PQMAIL_COMPANION_DIR")?);
    let keys = ["82", "9c", "9d", "83"]
        .iter()
        .map(|s| Ok((s.to_string(), fs::read(folder.join(format!("{s}.der")))?)))
        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    let envelope = Envelope::parse(
        &fs::read(folder.join("companion.pqcomp"))?,
        cfg.serial.parse()?,
        &keys,
    )?;
    // A stale/mismatched local certificate or tampered cached envelope must
    // fail before requesting the PIN, not merely before the token operation.
    ensure!(
        &envelope.certificate == expected,
        "Selected certificate differs from authenticated companion"
    );
    eprintln!(
        "{operation} on YubiKey {}. Touch when it flashes. No automatic retry.",
        cfg.serial
    );
    let pin = Zeroizing::new(
        if env::var("PQMAIL_SYNTHETIC_COMPANION").as_deref() == Ok("1") {
            "123456".to_string()
        } else {
            rpassword::prompt_password("YubiKey PIN (not saved): ")?
        },
    );
    Ok(CompanionBackend::new(
        Pkcs11Operation::new_level3_polyfill(cfg.clone(), Zeroizing::new(pin.as_bytes().to_vec()))?,
        envelope,
    ))
}

/// Strict helper for this signed synthetic encryption test only. Production
/// mail must implement its own certificate/trust and signature policy.
struct Reader {
    cert: Cert,
    key: Level3Decryptor<CompanionBackend<Pkcs11Operation>>,
}
impl VerificationHelper for Reader {
    fn get_certs(&mut self, _: &[KeyHandle]) -> Result<Vec<Cert>> {
        Ok(vec![self.cert.clone()])
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        let mut encrypted = false;
        let mut signatures = 0;
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
                MessageLayer::SignatureGroup { results } => {
                    ensure!(!results.is_empty(), "Empty signature group");
                    for result in results {
                        ensure!(
                            result.is_ok(),
                            "Hybrid message signature failed: {result:?}"
                        );
                        signatures += 1;
                    }
                }
            }
        }
        ensure!(
            encrypted && signatures == 1,
            "Expected signed and encrypted test message"
        );
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
    let backend = authorize(cfg, label, cert)?;
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
        "Usage: piv-level3-companion-test inspect|test PUBLIC_CERT OUTPUT_DIRECTORY"
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
    let body = fs::read(out.join("plain.txt"))?;
    ensure!(
        !body.is_empty() && body.len() <= 65536,
        "Invalid synthetic fixture length"
    );
    let body = body.as_slice();
    fs::write(out.join("message.mime"), body)?;
    let backend = authorize(
        &cfg,
        "Hybrid signing: ML-DSA-65 companion + Ed25519 slot 9c",
        &cert,
    )?;
    let start = Instant::now();
    let mut signer = Level3Signer::new(sign.clone(), backend)?;
    let sig = SignatureBuilder::new(SignatureType::Binary)
        .set_hash_algo(HashAlgorithm::SHA512)
        .sign_message(&mut signer, body)?;
    sig.verify_message(signer.public(), body)?;
    let mut signature_file = fs::File::create(out.join("signature.pgp"))?;
    // Serialize a complete OpenPGP signature packet, including its packet
    // header; serializing Signature's body alone is not an importable file.
    pgp::Packet::Signature(sig.clone()).serialize(&mut signature_file)?;
    // Reuse that exact already-verified signature in an inline signed message;
    // this avoids a second hardware signing operation for the same fixture.
    let mut signed = Vec::new();
    pgp::Packet::OnePassSig(pgp::packet::OnePassSig::try_from(&sig)?).serialize(&mut signed)?;
    let mut literal = pgp::packet::Literal::new(DataFormat::Binary);
    literal.set_body(body.to_vec());
    pgp::Packet::Literal(literal).serialize(&mut signed)?;
    pgp::Packet::Signature(sig).serialize(&mut signed)?;
    fs::write(out.join("sequoia-signed.pgp"), &signed)?;
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
    let mut message =
        Encryptor::for_recipients(Message::new(&mut encrypted), recipients).build()?;
    message.write_all(&signed)?;
    message.finalize()?;
    fs::write(out.join("sequoia-encrypted.pgp"), &encrypted)?;
    decrypt_fixture(
        &cfg,
        &cert,
        &kem,
        &encrypted,
        body,
        "Sequoia encryption → PIV ML-KEM-768 companion + X25519 slot 9d",
    )?;

    // The wrapper prepares this independent PQ Mail/Bouncy Castle ciphertext
    // before starting. Requiring it prevents reporting cross-implementation
    // success on only a same-library round trip.
    let incoming = fs::read(out.join("java-encrypted.pgp"))?;
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
