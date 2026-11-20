//! Integration tests use real OpenSSL-generated SOFTWARE keys only. No test
//! invokes the token module, discovers a YubiKey, or modifies its contents.

use anyhow::{ensure, Result};
use pgp::{
    crypto::{mpi, Decryptor, SessionKey, Signer},
    packet::{key::Key6, pkesk::PKESK6},
    types::{HashAlgorithm, PublicKeyAlgorithm},
};
use sequoia_openpgp as pgp;
use sequoia_pqmail_piv::{
    process::{Config, Pkcs11Operation},
    public_spki, Backend, Level3Decryptor, Level3Signer, Operation, PublicKey,
};
use std::{cell::Cell, fs, path::PathBuf, process::Command, rc::Rc, time::SystemTime};
use zeroize::Zeroizing;

struct Fixture {
    _temp: tempfile::TempDir,
    config: Config,
    sign: PublicKey,
    kem: PublicKey,
}

impl Fixture {
    fn new() -> Result<Self> {
        // Pin the test executable explicitly; no implicit system OpenSSL may
        // silently skip PQ tests because its version lacks ML-DSA/ML-KEM.
        let openssl = PathBuf::from(std::env::var("PQMAIL_TEST_OPENSSL")?);
        let python =
            PathBuf::from(std::env::var("PQMAIL_TEST_PYTHON").unwrap_or("/usr/bin/python3".into()));
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        fs::write(root.join("openssl-path"), openssl.to_str().unwrap())?;
        for name in ["pkcs11-mu.py", "pkcs11-kem.py", "ykman-mu.py"] {
            fs::write(root.join(name), include_str!("software_adapter.py"))?;
        }
        let mut raw = Vec::new();
        for op in [
            Operation::MlDsa65,
            Operation::Ed25519,
            Operation::MlKem768,
            Operation::X25519,
        ] {
            let key = root.join(format!("{}.pem", op.algorithm()));
            let result = Command::new(&openssl)
                .args(["genpkey", "-algorithm", op.algorithm(), "-out"])
                .arg(&key)
                .output()?;
            ensure!(
                result.status.success(),
                "Test software key generation failed"
            );
            let der = Command::new(&openssl)
                .args(["pkey", "-in"])
                .arg(&key)
                .args(["-pubout", "-outform", "DER"])
                .output()?;
            ensure!(der.status.success(), "Test public key export failed");
            let size = match op {
                Operation::MlDsa65 => 1952,
                Operation::MlKem768 => 1184,
                _ => 32,
            };
            let bytes = der.stdout[der.stdout.len() - size..].to_vec();
            // OpenSSL's independent DER encoder validates every SPKI produced
            // by the adapter, including absent algorithm parameters.
            assert_eq!(public_spki(op, &bytes)?, der.stdout);
            raw.push(bytes);
        }
        let sign = Key6::new(
            SystemTime::now(),
            PublicKeyAlgorithm::MLDSA65_Ed25519,
            mpi::PublicKey::MLDSA65_Ed25519 {
                mldsa: Box::new(raw[0].as_slice().try_into()?),
                eddsa: Box::new(raw[1].as_slice().try_into()?),
            },
        )?
        .into();
        let kem = Key6::new(
            SystemTime::now(),
            PublicKeyAlgorithm::MLKEM768_X25519,
            mpi::PublicKey::MLKEM768_X25519 {
                mlkem: Box::new(raw[2].as_slice().try_into()?),
                ecdh: Box::new(raw[3].as_slice().try_into()?),
            },
        )?
        .into();
        // Provider/module paths are validated but not loaded by the software
        // fixture. There is no token library in this test configuration.
        let config = Config {
            python,
            adapters: root.to_owned(),
            provider: openssl.clone(),
            module: openssl.clone(),
            openssl,
            serial: "12345678".into(),
        };
        Ok(Self {
            _temp: temp,
            config,
            sign,
            kem,
        })
    }

    fn backend(&self) -> Result<Pkcs11Operation> {
        Pkcs11Operation::new(self.config.clone(), Zeroizing::new(b"123456".to_vec()))
    }
}

#[test]
fn real_external_mu_signatures_verify_and_reject_tampering() -> Result<()> {
    let f = Fixture::new()?;
    for hash in [HashAlgorithm::SHA384, HashAlgorithm::SHA512] {
        let digest = vec![0x42; hash.digest_size()?];
        let mut signer = Level3Signer::new(f.sign.clone(), f.backend()?)?;
        let signature = signer.sign(hash, &digest)?;
        f.sign.verify(&signature, hash, &digest)?;
        // Either component's failure invalidates the whole hybrid signature.
        let mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa } = signature else {
            unreachable!()
        };
        let mut bad_ed = eddsa.clone();
        bad_ed[0] ^= 1;
        assert!(f
            .sign
            .verify(
                &mpi::Signature::MLDSA65_Ed25519 {
                    eddsa: bad_ed,
                    mldsa: mldsa.clone()
                },
                hash,
                &digest
            )
            .is_err());
        let mut bad_ml = mldsa;
        bad_ml[0] ^= 1;
        assert!(f
            .sign
            .verify(
                &mpi::Signature::MLDSA65_Ed25519 {
                    eddsa,
                    mldsa: bad_ml
                },
                hash,
                &digest
            )
            .is_err());
        // Successful completion consumed authorization; another sign cannot
        // reuse the PIN silently, even with the same adapter object.
        assert!(signer.sign(hash, &digest).is_err());
    }
    Ok(())
}

#[test]
fn sequoia_encapsulation_decrypts_via_component_protocol() -> Result<()> {
    let f = Fixture::new()?;
    for n in [16, 24, 32] {
        let expected = SessionKey::new(n)?;
        let packet = PKESK6::for_recipient(&expected, &f.kem)?;
        let mut decryptor = Level3Decryptor::new(f.kem.clone(), f.backend()?)?;
        let actual = decryptor.decrypt(packet.esk(), Some(n))?;
        assert_eq!(actual, expected);
        assert!(decryptor.decrypt(packet.esk(), Some(n)).is_err());
    }
    Ok(())
}

#[test]
fn tampered_encapsulation_and_wrap_are_rejected() -> Result<()> {
    let f = Fixture::new()?;
    let packet = PKESK6::for_recipient(&SessionKey::new(32)?, &f.kem)?;
    for component in 0..3 {
        let mut ct = packet.esk().clone();
        let mpi::Ciphertext::MLKEM768_X25519 {
            ref mut ecdh,
            ref mut mlkem,
            ref mut esk,
        } = ct
        else {
            unreachable!()
        };
        // ML-KEM implicit rejection and wrong ECDH shares must both fail AES
        // unwrap, as must a modified wrapped session key itself.
        match component {
            0 => mlkem[0] ^= 1,
            1 => ecdh[0] ^= 1,
            _ => esk[0] ^= 1,
        }
        assert!(Level3Decryptor::new(f.kem.clone(), f.backend()?)?
            .decrypt(&ct, Some(32))
            .is_err());
    }
    Ok(())
}

/// Records calls without performing cryptography, to assert malformed input
/// is rejected BEFORE reaching an authenticated private-key operation.
struct Guard {
    calls: Rc<Cell<usize>>,
    finished: Rc<Cell<bool>>,
}
impl Backend for Guard {
    fn execute(&mut self, _: Operation, _: &[u8], _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.calls.set(self.calls.get() + 1);
        anyhow::bail!("unexpected backend call")
    }
    fn finish(&mut self) {
        self.finished.set(true);
    }
}

#[test]
fn invalid_input_finishes_authorization_without_token_calls() -> Result<()> {
    let f = Fixture::new()?;
    let calls = Rc::new(Cell::new(0));
    let finished = Rc::new(Cell::new(false));
    let guard = || Guard {
        calls: calls.clone(),
        finished: finished.clone(),
    };
    let mut signer = Level3Signer::new(f.sign.clone(), guard())?;
    assert!(signer.sign(HashAlgorithm::SHA256, &[0; 32]).is_err());
    assert!(finished.get());
    finished.set(false);
    let bad = mpi::Ciphertext::MLKEM768_X25519 {
        ecdh: Box::new([0; 32]),
        mlkem: Box::new([0; 1088]),
        esk: vec![0; 40].into(),
    };
    assert!(Level3Decryptor::new(f.kem.clone(), guard())?
        .decrypt(&bad, None)
        .is_err());
    assert!(finished.get());
    assert_eq!(calls.get(), 0);
    assert!(Level3Signer::new(f.kem.clone(), guard()).is_err());
    assert!(Level3Decryptor::new(f.sign.clone(), guard()).is_err());
    Ok(())
}

#[test]
fn wrong_live_public_key_fails_and_clears_pin() -> Result<()> {
    let f = Fixture::new()?;
    let mut backend = f.backend()?;
    let wrong = public_spki(Operation::Ed25519, &[0; 32])?;
    assert!(backend
        .execute(Operation::Ed25519, &wrong, &[0; 48])
        .is_err());
    assert!(backend.is_finished());
    assert!(backend
        .execute(Operation::Ed25519, &wrong, &[0; 48])
        .is_err());
    Ok(())
}

#[test]
fn malformed_adapter_responses_are_rejected_and_clear_pin() -> Result<()> {
    let f = Fixture::new()?;
    // The child consumes the request but returns malformed data. Exercise
    // both protocol forms plus the bounded-output guard without token access.
    for (op, response) in [
        (Operation::Ed25519, "b'not base64\\n'"),
        (Operation::Ed25519, "b'AA==\\nAA==\\n'"),
        (Operation::MlKem768, "b'x' * 31"),
        (Operation::MlKem768, "b'x' * 9000"),
    ] {
        let name = if op.is_signature() {
            "pkcs11-mu.py"
        } else {
            "pkcs11-kem.py"
        };
        fs::write(
            f.config.adapters.join(name),
            format!("import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write({response})\n"),
        )?;
        let mut backend = f.backend()?;
        assert!(backend.execute(op, &[0; 44], &[0; 64]).is_err());
        assert!(backend.is_finished());
    }
    Ok(())
}

#[test]
fn nonzero_length_but_all_zero_ecdh_secret_is_rejected() -> Result<()> {
    struct ZeroShares(Rc<Cell<bool>>);
    impl Backend for ZeroShares {
        fn execute(&mut self, _: Operation, _: &[u8], _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(vec![0; 32]))
        }
        fn finish(&mut self) {
            self.0.set(true);
        }
    }
    let f = Fixture::new()?;
    let finished = Rc::new(Cell::new(false));
    let packet = PKESK6::for_recipient(&SessionKey::new(32)?, &f.kem)?;
    let error = Level3Decryptor::new(f.kem, ZeroShares(finished.clone()))?
        .decrypt(packet.esk(), Some(32))
        .unwrap_err();
    assert!(error.to_string().contains("all-zero X25519"));
    assert!(finished.get());
    Ok(())
}

#[test]
fn invalid_pin_and_configuration_fail_before_starting_adapter() -> Result<()> {
    let f = Fixture::new()?;
    for bad in [b"short".as_slice(), b"123456\n", b"123456789", b"12345\xff"] {
        assert!(Pkcs11Operation::new(f.config.clone(), Zeroizing::new(bad.to_vec())).is_err());
    }
    let mut config = f.config.clone();
    config.serial = "".into();
    assert!(Pkcs11Operation::new(config, Zeroizing::new(b"123456".to_vec())).is_err());
    assert!(public_spki(Operation::MlDsa65, &[0; 32]).is_err());
    Ok(())
}
