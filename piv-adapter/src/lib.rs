//! Experimental YubiKey 6 PIV integration for Sequoia's external-key interfaces.
//!
//! This crate implements the RFC 9980 Level 3 OpenPGP combinations, which are
//! ML-DSA-65 + Ed25519 and ML-KEM-768 + X25519. PIV's independent component keys
//! stay on the token. Sequoia constructs/hashes OpenPGP packets; this adapter
//! performs component private operations and constructs the composite result.
//!
//! There are deliberately no key-generation, certificate-write, management-key,
//! reset, or policy-change operations. This is an integration prototype, not an
//! upstream-endorsed API or a replacement for PQ Mail's installed mail backend.

use anyhow::{bail, ensure, Result};
use openpgp::crypto::{ecdh::aes_key_unwrap, mpi, Decryptor, SessionKey, Signer};
use openpgp::packet::{key, Key};
use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp as openpgp;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroizing;

pub mod process;
pub mod companion;
pub mod restore;

/// Only public key material is held by either adapter.
pub type PublicKey = Key<key::PublicParts, key::UnspecifiedRole>;

/// A closed set of operations prevents untrusted OpenPGP input from selecting
/// arbitrary helper algorithms, token slots, or provisioning commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// ML-DSA-65 in 9c: input is the 64-byte FIPS 204 external representative μ.
    MlDsa65,
    MlDsa87,
    MlKem1024,
    Ed448,
    X448,
    P384,
    /// Ed25519 in 84: input is the OpenPGP digest treated as an ordinary message.
    Ed25519,
    /// ML-KEM-768 in 9d: input is the 1088-byte encapsulation ciphertext.
    MlKem768,
    /// X25519 in 85: input is the ephemeral public key encoded as DER SPKI.
    X25519,
}

impl Operation {
    /// The existing Python adapters use these exact algorithm names.
    pub fn algorithm(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::MlKem1024 => "ML-KEM-1024",
            Self::Ed448 => "Ed448",
            Self::X448 => "X448",
            Self::P384 => "ECDH-P384",
            Self::Ed25519 => "Ed25519",
            Self::MlKem768 => "ML-KEM-768",
            Self::X25519 => "X25519",
        }
    }

    /// RFC 8410/FIPS algorithm identifiers, without optional NULL parameters.
    /// The public key is a BIT STRING of the raw algorithm-specific octets.
    fn oid(self) -> &'static [u8] {
        match self {
            Self::MlDsa87 => &[0x60,0x86,0x48,1,0x65,3,4,3,0x13],
            Self::MlKem1024 => &[0x60,0x86,0x48,1,0x65,3,4,4,3],
            Self::Ed448 => &[0x2b,0x65,0x71],
            Self::X448 => &[0x2b,0x65,0x6f],
            Self::P384 => &[], // P-384 uses a complete, validated SPKI, never this encoder.
            Self::MlDsa65 => &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 0x12],
            Self::MlKem768 => &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 4, 2],
            Self::Ed25519 => &[0x2b, 0x65, 0x70],
            Self::X25519 => &[0x2b, 0x65, 0x6e],
        }
    }

    fn public_size(self) -> usize {
        match self {
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
            Self::MlKem1024 => 1568,
            Self::Ed448 => 57,
            Self::X448 => 56,
            Self::P384 => 0,
            Self::MlKem768 => 1184,
            _ => 32,
        }
    }

    /// Whether the subprocess returns base64 signatures or raw shared secrets.
    pub fn is_signature(self) -> bool {
        matches!(self, Self::MlDsa65 | Self::MlDsa87 | Self::Ed25519 | Self::Ed448)
    }

    /// Exact response lengths reject truncated or ambiguously framed output.
    pub fn output_size(self) -> usize {
        match self {
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
            Self::Ed448 => 114,
            Self::X448 => 56,
            Self::P384 => 48,
            Self::Ed25519 => 64,
            _ => 32,
        }
    }
}

/// Boundary between OpenPGP and private-key transport. Implementations must
/// check the live public key against `spki` before using its private component.
/// Shared secrets and PINs must not be logged or persisted. Production callers
/// use [`process::Pkcs11Operation`]; tests can supply genuine software crypto.
pub trait Backend {
    /// Performs one component operation, returning a wipe-on-drop buffer.
    fn execute(
        &mut self,
        operation: Operation,
        spki: &[u8],
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;

    /// Separate, explicitly authorized certification operation, fixed to the
    /// existing ML-DSA-87 key in slot 86. Ordinary message backends reject it by
    /// default. Ultra-certificate reconstruction derives the external μ only
    /// after independently validating the certificate packet structure.
    fn certify(&mut self, _spki: &[u8], _mu: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        bail!("This backend does not authorize certification signing")
    }

    /// Ends the logical composite operation on success *or* failure. The
    /// production backend deletes its operation-scoped PIN here, so it cannot
    /// silently authorize a subsequent signature or message decryption.
    fn finish(&mut self);
}

/// Minimal DER encoder for our four fixed public-only algorithm identifiers.
/// It never parses arbitrary ASN.1 and never handles secret key material.
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else if body.len() <= 255 {
        out.extend([0x81, body.len() as u8]);
    } else {
        out.extend([0x82, (body.len() >> 8) as u8, body.len() as u8]);
    }
    out.extend_from_slice(body);
    out
}

/// Encodes an expected component public key for the existing PKCS#11 helper's
/// live-key comparison. Rejecting wrong lengths also prevents accidental use
/// of a Level 5 key with this Level 3 adapter.
pub fn public_spki(operation: Operation, raw: &[u8]) -> Result<Vec<u8>> {
    ensure!(operation != Operation::P384, "P384 requires a complete SPKI");
    ensure!(
        raw.len() == operation.public_size(),
        "Wrong component public key length"
    );
    let mut body = der(0x30, &der(0x06, operation.oid()));
    let mut bits = vec![0]; // DER BIT STRING: zero unused bits.
    bits.extend_from_slice(raw);
    body.extend(der(0x03, &bits));
    Ok(der(0x30, &body))
}

/// FIPS 204 pure ML-DSA, empty context: μ = H(H(pk,64) || 0 || 0 || M,64).
/// Here M is Sequoia's already-computed OpenPGP digest. The two zero octets
/// mean pure ML-DSA and a zero-length context, NOT HashML-DSA. Ed25519 signs
/// that same OpenPGP digest as a message; neither component rehashes OpenPGP
/// packets or changes Sequoia's version-6 signature salt handling.
pub fn external_mu(public: &[u8], message: &[u8]) -> [u8; 64] {
    let mut tr = [0; 64];
    let mut hash = Shake256::default();
    hash.update(public);
    hash.finalize_xof().read(&mut tr);
    let mut hash = Shake256::default();
    hash.update(&tr);
    hash.update(&[0, 0]);
    hash.update(message);
    let mut mu = [0; 64];
    hash.finalize_xof().read(&mut mu);
    mu
}

/// A signing subkey using existing slots 9c/84. Certification slots 86/87 are
/// intentionally not exposed: this adapter signs messages without altering
/// or reissuing the user's certificate.
pub struct Level3Signer<B: Backend> {
    public: PublicKey,
    backend: B,
}

impl<B: Backend> Level3Signer<B> {
    /// Validates the public algorithm before any private operation is possible.
    pub fn new(public: PublicKey, backend: B) -> Result<Self> {
        ensure!(
            matches!(public.mpis(), mpi::PublicKey::MLDSA65_Ed25519 { .. }),
            "Expected an ML-DSA-65 + Ed25519 public signing key"
        );
        Ok(Self { public, backend })
    }
}

impl<B: Backend> Signer for Level3Signer<B> {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    // These are the OpenPGP digest lengths supported by the existing Ed25519
    // adapter; restricting negotiation avoids any unexpected digest coercion.
    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &[HashAlgorithm::SHA512, HashAlgorithm::SHA384]
    }

    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<mpi::Signature> {
        // A closure gives every error path the same PIN-cleanup epilogue.
        let result = (|| {
            ensure!(
                self.acceptable_hashes().contains(&hash),
                "Unsupported OpenPGP hash"
            );
            ensure!(
                digest.len() == hash.digest_size()?,
                "Incorrect OpenPGP digest length"
            );
            let mpi::PublicKey::MLDSA65_Ed25519 { eddsa, mldsa } = self.public.mpis() else {
                unreachable!("validated by constructor")
            };
            let mu = external_mu(mldsa.as_ref(), digest);
            let ml = self.backend.execute(
                Operation::MlDsa65,
                &public_spki(Operation::MlDsa65, mldsa.as_ref())?,
                &mu,
            )?;
            ensure!(ml.len() == 3309, "Incorrect ML-DSA-65 signature length");
            let ed = self.backend.execute(
                Operation::Ed25519,
                &public_spki(Operation::Ed25519, eddsa.as_ref())?,
                digest,
            )?;
            ensure!(ed.len() == 64, "Incorrect Ed25519 signature length");
            let signature = mpi::Signature::MLDSA65_Ed25519 {
                eddsa: Box::new(ed.as_slice().try_into()?),
                mldsa: Box::new(ml.as_slice().try_into()?),
            };
            // Verify the COMPLETE composite before releasing it. This catches
            // wrong μ construction and either bad component, even if a backend
            // has reported success. There is no classical-only fallback.
            self.public.verify(&signature, hash, digest)?;
            Ok(signature)
        })();
        self.backend.finish();
        result
    }
}

/// A decryption subkey using existing slots 9d/85. Only component shared
/// secrets leave the token; the private keys remain in their PIV slots.
pub struct Level3Decryptor<B: Backend> {
    public: PublicKey,
    backend: B,
}

impl<B: Backend> Level3Decryptor<B> {
    /// Rejects other OpenPGP encryption algorithms before contacting hardware.
    pub fn new(public: PublicKey, backend: B) -> Result<Self> {
        ensure!(
            matches!(public.mpis(), mpi::PublicKey::MLKEM768_X25519 { .. }),
            "Expected an ML-KEM-768 + X25519 public encryption key"
        );
        Ok(Self { public, backend })
    }
}

impl<B: Backend> Decryptor for Level3Decryptor<B> {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> Result<SessionKey> {
        let result = (|| {
            let mpi::PublicKey::MLKEM768_X25519 {
                ecdh: public_ec,
                mlkem: public_ml,
            } = self.public.mpis()
            else {
                unreachable!("validated by constructor")
            };
            let mpi::Ciphertext::MLKEM768_X25519 {
                ecdh: ephemeral,
                mlkem: ct,
                esk,
            } = ciphertext
            else {
                bail!("Ciphertext algorithm does not match recipient")
            };
            // Only AES-sized session keys are valid for these OpenPGP packets.
            // The AES key-wrap overhead is eight octets. Reject malformed
            // framing before a PIN-authorized private-key operation.
            ensure!(
                [24, 32, 40].contains(&esk.len()),
                "Invalid wrapped session key length"
            );
            ensure!(
                ephemeral.iter().any(|b| *b != 0),
                "Invalid X25519 public input"
            );
            let ml = self.backend.execute(
                Operation::MlKem768,
                &public_spki(Operation::MlKem768, public_ml.as_ref())?,
                ct.as_ref(),
            )?;
            let ec = self.backend.execute(
                Operation::X25519,
                &public_spki(Operation::X25519, public_ec.as_ref())?,
                &public_spki(Operation::X25519, ephemeral.as_ref())?,
            )?;
            ensure!(
                ml.len() == 32 && ec.len() == 32,
                "Incorrect shared secret length"
            );
            ensure!(
                ec.iter().any(|b| *b != 0),
                "Rejected all-zero X25519 shared secret"
            );

            // RFC 9980's combiner binds BOTH shared secrets, the ephemeral
            // X25519 key, recipient X25519 key, algorithm ID, and domain tag.
            // This is SHA3-256, not HKDF and not concatenation used as an AES
            // key. It matches Sequoia's internal multi_key_combine exactly.
            let mut hash = HashAlgorithm::SHA3_256.context()?.for_digest();
            hash.update(&ml);
            hash.update(&ec);
            hash.update(ephemeral.as_ref());
            hash.update(public_ec.as_ref());
            hash.update(&[PublicKeyAlgorithm::MLKEM768_X25519.into()]);
            hash.update(b"OpenPGPCompositeKDFv1\x15");
            let mut kek = SessionKey::from(vec![0; 32]);
            hash.digest(&mut kek)?;

            // Sequoia checks RFC 3394's integrity value during unwrapping.
            // Implicit ML-KEM rejection therefore cannot yield a usable key.
            let plain = aes_key_unwrap(SymmetricAlgorithm::AES256, kek.as_protected(), esk)?;
            if let Some(n) = plaintext_len {
                ensure!(plain.len() == n, "Unexpected recovered session key length");
            }
            Ok(plain.into()) // Protected/SessionKey and temporary shares wipe on drop.
        })();
        self.backend.finish();
        result
    }
}

// Level 5 uses the same RFC 9980 interfaces; companion::CompanionBackend
// supplies only the software Edwards components and delegates PQ operations.
pub struct Level5Signer<B: Backend> {
    public: PublicKey,
    backend: B,
}

impl<B: Backend> Level5Signer<B> {
    /// Validates the public algorithm before any private operation is possible.
    pub fn new(public: PublicKey, backend: B) -> Result<Self> {
        ensure!(
            matches!(public.mpis(), mpi::PublicKey::MLDSA87_Ed448 { .. }),
            "Expected an ML-DSA-87 + Ed448 public signing key"
        );
        Ok(Self { public, backend })
    }
}

impl<B: Backend> Signer for Level5Signer<B> {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    // These are the OpenPGP digest lengths supported by the existing Ed448
    // adapter; restricting negotiation avoids any unexpected digest coercion.
    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &[HashAlgorithm::SHA512, HashAlgorithm::SHA384]
    }

    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<mpi::Signature> {
        // A closure gives every error path the same PIN-cleanup epilogue.
        let result = (|| {
            ensure!(
                self.acceptable_hashes().contains(&hash),
                "Unsupported OpenPGP hash"
            );
            ensure!(
                digest.len() == hash.digest_size()?,
                "Incorrect OpenPGP digest length"
            );
            let mpi::PublicKey::MLDSA87_Ed448 { eddsa, mldsa } = self.public.mpis() else {
                unreachable!("validated by constructor")
            };
            let mu = external_mu(mldsa.as_ref(), digest);
            let ml = self.backend.execute(
                Operation::MlDsa87,
                &public_spki(Operation::MlDsa87, mldsa.as_ref())?,
                &mu,
            )?;
            ensure!(ml.len() == 4627, "Incorrect ML-DSA-87 signature length");
            let ed = self.backend.execute(
                Operation::Ed448,
                &public_spki(Operation::Ed448, eddsa.as_ref())?,
                digest,
            )?;
            ensure!(ed.len() == 114, "Incorrect Ed448 signature length");
            let signature = mpi::Signature::MLDSA87_Ed448 {
                eddsa: Box::new(ed.as_slice().try_into()?),
                mldsa: Box::new(ml.as_slice().try_into()?),
            };
            // Verify the COMPLETE composite before releasing it. This catches
            // wrong μ construction and either bad component, even if a backend
            // has reported success. There is no classical-only fallback.
            self.public.verify(&signature, hash, digest)?;
            Ok(signature)
        })();
        self.backend.finish();
        result
    }
}

/// A decryption subkey using existing slots 9d/85. Only component shared
/// secrets leave the token; the private keys remain in their PIV slots.
pub struct Level5Decryptor<B: Backend> {
    public: PublicKey,
    backend: B,
}

impl<B: Backend> Level5Decryptor<B> {
    /// Rejects other OpenPGP encryption algorithms before contacting hardware.
    pub fn new(public: PublicKey, backend: B) -> Result<Self> {
        ensure!(
            matches!(public.mpis(), mpi::PublicKey::MLKEM1024_X448 { .. }),
            "Expected an ML-KEM-1024 + X448 public encryption key"
        );
        Ok(Self { public, backend })
    }
}

impl<B: Backend> Decryptor for Level5Decryptor<B> {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> Result<SessionKey> {
        let result = (|| {
            let mpi::PublicKey::MLKEM1024_X448 {
                ecdh: public_ec,
                mlkem: public_ml,
            } = self.public.mpis()
            else {
                unreachable!("validated by constructor")
            };
            let mpi::Ciphertext::MLKEM1024_X448 {
                ecdh: ephemeral,
                mlkem: ct,
                esk,
            } = ciphertext
            else {
                bail!("Ciphertext algorithm does not match recipient")
            };
            // Only AES-sized session keys are valid for these OpenPGP packets.
            // The AES key-wrap overhead is eight octets. Reject malformed
            // framing before a PIN-authorized private-key operation.
            ensure!(
                [24, 32, 40].contains(&esk.len()),
                "Invalid wrapped session key length"
            );
            ensure!(
                ephemeral.iter().any(|b| *b != 0),
                "Invalid X448 public input"
            );
            let ml = self.backend.execute(
                Operation::MlKem1024,
                &public_spki(Operation::MlKem1024, public_ml.as_ref())?,
                ct.as_ref(),
            )?;
            let ec = self.backend.execute(
                Operation::X448,
                &public_spki(Operation::X448, public_ec.as_ref())?,
                &public_spki(Operation::X448, ephemeral.as_ref())?,
            )?;
            ensure!(
                ml.len() == 32 && ec.len() == 56,
                "Incorrect shared secret length"
            );
            ensure!(
                ec.iter().any(|b| *b != 0),
                "Rejected all-zero X448 shared secret"
            );

            // RFC 9980's combiner binds BOTH shared secrets, the ephemeral
            // X448 key, recipient X448 key, algorithm ID, and domain tag.
            // This is SHA3-256, not HKDF and not concatenation used as an AES
            // key. It matches Sequoia's internal multi_key_combine exactly.
            let mut hash = HashAlgorithm::SHA3_256.context()?.for_digest();
            hash.update(&ml);
            hash.update(&ec);
            hash.update(ephemeral.as_ref());
            hash.update(public_ec.as_ref());
            hash.update(&[PublicKeyAlgorithm::MLKEM1024_X448.into()]);
            hash.update(b"OpenPGPCompositeKDFv1\x15");
            let mut kek = SessionKey::from(vec![0; 32]);
            hash.digest(&mut kek)?;

            // Sequoia checks RFC 3394's integrity value during unwrapping.
            // Implicit ML-KEM rejection therefore cannot yield a usable key.
            let plain = aes_key_unwrap(SymmetricAlgorithm::AES256, kek.as_protected(), esk)?;
            if let Some(n) = plaintext_len {
                ensure!(plain.len() == n, "Unexpected recovered session key length");
            }
            Ok(plain.into()) // Protected/SessionKey and temporary shares wipe on drop.
        })();
        self.backend.finish();
        result
    }
}
