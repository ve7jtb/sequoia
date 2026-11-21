//! Level 5 software companion, opened using the existing slot-82 PKCS#11 key.
//! No password, decrypted P12, or software private key is written to disk.
//! The configured OpenSSL child only converts the inner PFX to PEM over pipes;
//! Sequoia's Rust adapter performs Ed448/X448 operations in process.
use crate::{public_spki, Backend, Operation};
use anyhow::{ensure, Context, Result};
use flate2::{Decompress, FlushDecompress, Status};
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::{Signer, Verifier},
    symm::{decrypt_aead, Cipher},
};
use sequoia_openpgp::cert::amalgamation::key::PrimaryKey;
use sequoia_openpgp::{
    crypto::mpi, parse::Parse, policy::StandardPolicy, types::RevocationStatus, Cert,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const MAX: usize = 65536;
const COMPRESSED_MAGIC: &[u8; 8] = b"PQMCZ001";

/// Expand the optional storage wrapper without modifying the authenticated
/// inner envelope. Compression removes duplicated public encodings, not the
/// ciphertext's protection: the ORIGINAL hardware signature, AEAD AAD, HKDF
/// input, public certificate, and encrypted P12 remain byte-for-byte intact.
///
/// The wrapper itself is untrusted. Bound both input and expanded sizes before
/// allocation, accept exactly one complete zlib stream, and reject nesting.
/// Signature and live-key validation still run on the expanded envelope below.
fn expand_companion(stored: &[u8]) -> Result<Vec<u8>> {
    ensure!(stored.len() <= MAX, "Oversized companion storage wrapper");
    if !stored.starts_with(COMPRESSED_MAGIC) {
        return Ok(stored.to_vec());
    }
    ensure!(stored.len() >= 12, "Truncated compressed companion header");
    let size = u32::from_be_bytes(stored[8..12].try_into()?) as usize;
    ensure!((1..=MAX).contains(&size), "Invalid expanded companion size");
    // One extra output byte detects streams exceeding their declared length,
    // including a stream that would otherwise stop exactly at the buffer end.
    let mut expanded = vec![0; size + 1];
    let mut decoder = Decompress::new(true);
    let status = decoder.decompress(&stored[12..], &mut expanded, FlushDecompress::Finish)?;
    ensure!(
        status == Status::StreamEnd
            && decoder.total_out() == size as u64
            && decoder.total_in() == (stored.len() - 12) as u64,
        "Invalid compressed companion boundary"
    );
    expanded.truncate(size);
    ensure!(
        !expanded.starts_with(COMPRESSED_MAGIC),
        "Nested companion compression rejected"
    );
    Ok(expanded)
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.0.len(), "Truncated companion");
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn number(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?) as usize)
    }
    fn field(&mut self) -> Result<&'a [u8]> {
        let n = self.number()?;
        ensure!(n <= MAX, "Oversized companion field");
        self.take(n)
    }
    fn end(&self) -> Result<()> {
        ensure!(self.0.is_empty(), "Trailing companion bytes");
        Ok(())
    }
}
fn p384(point: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        point.len() == 97 && point[0] == 4,
        "Expected uncompressed P384 point"
    );
    let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let mut ctx = BigNumContext::new()?;
    let p = EcPoint::from_bytes(&group, point, &mut ctx)?;
    ensure!(
        !p.is_infinity(&group) && p.is_on_curve(&group, &mut ctx)?,
        "Invalid P384 point"
    );
    Ok(PKey::from_ec_key(EcKey::from_public_key(&group, &p)?)?.public_key_to_der()?)
}
/// Independent raw-packet validation for the deliberately narrow ultra profile.
mod ultra;

/// Parsed, authenticated storage fields. This type is private so callers cannot
/// bypass signature/live-key checks or supply a different AAD to P12 opening.
struct AuthenticatedEnvelope {
    serial: u32,
    keys: BTreeMap<String, Vec<u8>>,
    certificate: Vec<u8>,
    manifest: Vec<u8>,
    ultra: bool,
    ephemeral: Vec<u8>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
}
struct Components {
    ed: Vec<u8>,
    x: Vec<u8>,
    certification: Vec<u8>,
}

impl AuthenticatedEnvelope {
    fn parse(encoded: &[u8], serial: u32, expected: &BTreeMap<String, Vec<u8>>) -> Result<Self> {
        ensure!(expected.len() == 4, "Invalid companion mapping");
        let expanded = expand_companion(encoded)?;
        let mut outer = Reader(&expanded);
        let body = outer.field()?;
        let sig = outer.field()?;
        outer.end()?;
        ensure!(sig.len() == 4627, "Invalid envelope signature size");
        let cert_key =
            PKey::public_key_from_der(expected.get("86").context("Missing certification key")?)?;
        let mut verifier = Verifier::new_without_digest(&cert_key)?;
        ensure!(
            verifier.verify_oneshot(sig, body)?,
            "Companion signature rejected"
        );
        let mut r = Reader(body);
        let magic = r.take(8)?;
        ensure!(
            [b"PQMCP001".as_slice(), b"PQMCP002".as_slice()].contains(&magic)
                && r.number()? == serial as usize,
            "Companion serial/format mismatch"
        );
        let mut keys = BTreeMap::new();
        for slot in ["86", "9c", "9d", "82"] {
            let spki = r.field()?;
            ensure!(
                Some(spki) == expected.get(slot).map(Vec::as_slice),
                "Live key mismatch in {slot}"
            );
            keys.insert(slot.into(), spki.to_vec());
        }
        let certificate = r.field()?.to_vec();
        let manifest = r.field()?.to_vec();
        let ephemeral = p384(r.take(97)?)?;
        let salt = r.take(32)?.to_vec();
        let nonce = r.take(12)?.to_vec();
        let aad = body[..body.len() - r.0.len()].to_vec();
        let ciphertext = r.field()?.to_vec();
        r.end()?;
        ensure!(ciphertext.len() >= 16, "Truncated AEAD ciphertext");
        let wrapping = PKey::public_key_from_der(&keys["82"])?;
        ensure!(
            wrapping.ec_key()?.group().curve_name() == Some(Nid::SECP384R1),
            "Wrapping key must be P384"
        );
        Ok(Self {
            serial,
            keys,
            certificate,
            manifest,
            ultra: magic == b"PQMCP002",
            ephemeral,
            salt,
            nonce,
            aad,
            ciphertext,
        })
    }
    /// Require the exact canonical manifest, not merely selected JSON values.
    /// Unknown fields, alternate order, whitespace and duplicate keys therefore
    /// cannot create implementation-dependent routing interpretations.
    fn check_manifest(&self, public: &Components) -> Result<()> {
        let components = [
            (
                "certification-pq",
                "ML-DSA-87",
                "piv",
                "86",
                &self.keys["86"],
            ),
            ("signing-pq", "ML-DSA-87", "piv", "9c", &self.keys["9c"]),
            (
                "decryption-pq",
                "ML-KEM-1024",
                "piv",
                "9d",
                &self.keys["9d"],
            ),
            ("companion-wrap", "P-384", "piv", "82", &self.keys["82"]),
            (
                "certification-classical",
                "Ed448",
                "companion",
                "",
                &public.certification,
            ),
            ("signing-classical", "Ed448", "companion", "", &public.ed),
            ("decryption-classical", "X448", "companion", "", &public.x),
        ];
        let entries=components.iter().map(|(role,algorithm,storage,slot,spki)|{
            let digest=Sha256::digest(spki).iter().map(|b|format!("{b:02x}")).collect::<String>();
            format!("{{\"role\":\"{role}\",\"algorithm\":\"{algorithm}\",\"storage\":\"{storage}\",\"slot\":\"{slot}\",\"sha256\":\"{digest}\"}}")
        }).collect::<Vec<_>>().join(",");
        let canonical = format!(
            "{{\"version\":1,\"serial\":{},\"profile\":\"LEVEL5_COMPANION\",\"components\":[{}]}}",
            self.serial, entries
        );
        ensure!(
            self.manifest == canonical.as_bytes(),
            "Noncanonical or unsupported companion manifest"
        );
        Ok(())
    }
    /// AES-GCM is the P12 protection boundary; the empty password is not a
    /// credential. The new format uses its own exact AAD with the same v1 HKDF
    /// context. A format change therefore requires authenticated re-encryption.
    fn open(
        &self,
        public: &Components,
        backend: &mut impl Backend,
        openssl: &Path,
    ) -> Result<SoftwareKeys> {
        let secret = backend.execute(Operation::P384, &self.keys["82"], &self.ephemeral)?;
        ensure!(
            secret.len() == 48 && secret.iter().any(|b| *b != 0),
            "Invalid wrapping secret"
        );
        let hmac = |key: &[u8], data: &[u8]| -> Result<Zeroizing<Vec<u8>>> {
            let k = PKey::hmac(key)?;
            let mut h = Signer::new(MessageDigest::sha256(), &k)?;
            h.update(data)?;
            Ok(Zeroizing::new(h.sign_to_vec()?))
        };
        let prk = hmac(&self.salt, &secret)?;
        let mut info = b"PQMail companion P384 v1".to_vec();
        info.extend(Sha256::digest(&self.aad));
        info.push(1);
        let key = hmac(&prk, &info)?;
        let n = self.ciphertext.len() - 16;
        let plain = Zeroizing::new(decrypt_aead(
            Cipher::aes_256_gcm(),
            &key,
            Some(&self.nonce),
            &self.aad,
            &self.ciphertext[..n],
            &self.ciphertext[n..],
        )?);
        let mut r = Reader(&plain);
        let p12 = r.field()?;
        r.end()?;
        let pem = convert_p12(openssl, p12)?;
        let mut keys = Vec::new();
        let mut at = 0;
        let begin = b"-----BEGIN PRIVATE KEY-----";
        let end = b"-----END PRIVATE KEY-----";
        while let Some(start) = pem[at..].windows(begin.len()).position(|w| w == begin) {
            let start = at + start;
            let stop = start
                + pem[start..]
                    .windows(end.len())
                    .position(|w| w == end)
                    .context("Truncated PEM key")?
                + end.len();
            keys.push(PKey::private_key_from_pem(&pem[start..stop])?);
            at = stop;
        }
        ensure!(keys.len() == 3, "Expected exactly three companion keys");
        let take = |expected: &[u8]| -> Result<PKey<Private>> {
            let found: Vec<_> = keys
                .iter()
                .filter(|k| k.public_key_to_der().is_ok_and(|v| v == expected))
                .collect();
            ensure!(found.len() == 1, "Companion private/public mismatch");
            Ok(found[0].clone())
        };
        Ok(SoftwareKeys {
            certification: take(&public.certification)?,
            ed: take(&public.ed)?,
            x: take(&public.x)?,
        })
    }
}

/// Authenticated, fully verified public certificate plus encrypted companion.
/// Ultra envelopes need a matching verified public cache or explicit one-time
/// reconstruction; normal message operations never rebuild certifications.
pub struct Envelope {
    pub certificate: Cert,
    pub serial: u32,
    data: AuthenticatedEnvelope,
    public: Components,
    verified_certificate: Vec<u8>,
}
impl Envelope {
    /// Exact verified packet bytes for a public-only disk cache. Avoid general
    /// certificate serialization changing packet order/framing during restore.
    pub fn certificate_bytes(&self) -> &[u8] {
        &self.verified_certificate
    }
    pub fn parse(
        encoded: &[u8],
        serial: u32,
        expected: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self> {
        let data = AuthenticatedEnvelope::parse(encoded, serial, expected)?;
        ensure!(!data.ultra,"Ultra companion requires a verified public cache or explicit first-host reconstruction");
        let full = data.certificate.clone();
        Self::from_certificate(data, &full)
    }
    /// A public disk cache is untrusted input. Verify both the exact normalized
    /// template and all actual signatures/current policies on every load.
    pub fn parse_with_cache(
        encoded: &[u8],
        serial: u32,
        expected: &BTreeMap<String, Vec<u8>>,
        cached: &[u8],
    ) -> Result<Self> {
        let data = AuthenticatedEnvelope::parse(encoded, serial, expected)?;
        if data.ultra {
            ultra::Template::parse(&data.certificate)?.verify_cache(cached)?;
        } else {
            // Full envelopes already contain their authenticated certificate;
            // they do not need or trust an external cache at all.
            let full = data.certificate.clone();
            return Self::from_certificate(data, &full);
        }
        Self::from_certificate(data, cached)
    }
    fn from_certificate(data: AuthenticatedEnvelope, encoded: &[u8]) -> Result<Self> {
        ensure!(encoded.len() <= MAX, "Oversized public certificate cache");
        let certificate = Cert::from_bytes(encoded)?;
        ensure!(!certificate.is_tsk(), "Expected public certificate");
        let policy = StandardPolicy::new();
        let checked = certificate.with_policy(&policy, None)?;
        checked.alive()?;
        ensure!(
            matches!(
                checked.revocation_status(),
                RevocationStatus::NotAsFarAsWeKnow
            ),
            "Revoked companion certificate"
        );
        let mpi::PublicKey::MLDSA87_Ed448 { mldsa, eddsa } = certificate.primary_key().key().mpis()
        else {
            anyhow::bail!("Expected Level 5 primary")
        };
        ensure!(
            public_spki(Operation::MlDsa87, mldsa.as_ref())? == data.keys["86"],
            "Certification binding mismatch"
        );
        let certification = public_spki(Operation::Ed448, eddsa.as_ref())?;
        let signers: Vec<_> = checked
            .keys()
            .alive()
            .revoked(false)
            .for_signing()
            .collect();
        let recipients: Vec<_> = checked
            .keys()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .collect();
        ensure!(
            signers.len() == 1 && recipients.len() == 1 && !signers[0].primary(),
            "Expected separated Level 5 subkeys"
        );
        let mpi::PublicKey::MLDSA87_Ed448 { mldsa, eddsa } = signers[0].key().mpis() else {
            anyhow::bail!("Expected Level 5 signer")
        };
        ensure!(
            public_spki(Operation::MlDsa87, mldsa.as_ref())? == data.keys["9c"],
            "Signing binding mismatch"
        );
        let ed = public_spki(Operation::Ed448, eddsa.as_ref())?;
        let mpi::PublicKey::MLKEM1024_X448 { mlkem, ecdh } = recipients[0].key().mpis() else {
            anyhow::bail!("Expected Level 5 encryption")
        };
        ensure!(
            public_spki(Operation::MlKem1024, mlkem.as_ref())? == data.keys["9d"],
            "Encryption binding mismatch"
        );
        let x = public_spki(Operation::X448, ecdh.as_ref())?;
        let public = Components {
            certification,
            ed,
            x,
        };
        data.check_manifest(&public)?;
        Ok(Self {
            serial: data.serial,
            certificate,
            data,
            public,
            verified_certificate: encoded.to_vec(),
        })
    }
}

/// Authenticated reconstruction request; not an OpenPGP certificate. All packet
/// structure/role/digest constraints are checked independently before PIN use.
pub struct PendingEnvelope {
    data: AuthenticatedEnvelope,
    template: ultra::Template,
    public: Components,
}
impl PendingEnvelope {
    pub fn parse(
        encoded: &[u8],
        serial: u32,
        expected: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self> {
        let data = AuthenticatedEnvelope::parse(encoded, serial, expected)?;
        ensure!(data.ultra, "Expected ultra companion");
        let template = ultra::Template::parse(&data.certificate)?;
        let (certification, cert_pq) = ultra::components(&template.primary)?;
        let (ed, sign_pq) = ultra::components(&template.signing)?;
        let (x, kem_pq) = ultra::components(&template.encryption)?;
        ensure!(
            cert_pq == data.keys["86"] && sign_pq == data.keys["9c"] && kem_pq == data.keys["9d"],
            "Ultra template hardware mapping mismatch"
        );
        let public = Components {
            certification,
            ed,
            x,
        };
        data.check_manifest(&public)?;
        Ok(Self {
            data,
            template,
            public,
        })
    }
    /// Reconstruct once per host with one operation-scoped PIN. The hardware
    /// backend's certification operation is fixed to 86; its ordinary ML-DSA-87
    /// operation is fixed to 9c. No caller controls a raw signing message/slot.
    /// Return only verified public bytes; private software keys drop on all exits.
    pub fn reconstruct(
        self,
        backend: &mut impl Backend,
        openssl: &Path,
    ) -> Result<(Envelope, Vec<u8>)> {
        let result = (|| {
            // Authorization may have taken time. Recheck expiration and the
            // complete structural policy before even the slot-82 unwrap.
            ultra::Template::parse(&self.data.certificate)?;
            let keys = self.data.open(&self.public, backend, openssl)?;
            let full = self.template.reconstruct(|certification, digest| {
                let (key_body, ed, slot) = if certification {
                    (&self.template.primary, &keys.certification, "86")
                } else {
                    (&self.template.signing, &keys.ed, "9c")
                };
                let mu = crate::external_mu(&key_body[67..], digest);
                let ml = if certification {
                    backend.certify(&self.data.keys[slot], &mu)?
                } else {
                    backend.execute(Operation::MlDsa87, &self.data.keys[slot], &mu)?
                };
                ensure!(
                    ml.len() == 4627,
                    "Invalid reconstructed ML-DSA-87 signature"
                );
                let mut signer = Signer::new_without_digest(ed)?;
                let mut signature = signer.sign_oneshot_to_vec(digest)?;
                ensure!(
                    signature.len() == 114,
                    "Invalid reconstructed Ed448 signature"
                );
                signature.extend(ml.as_slice());
                Ok(signature)
            })?;
            let envelope = Envelope::from_certificate(self.data, &full)?;
            Ok((envelope, full))
        })();
        backend.finish();
        result
    }
}
struct SoftwareKeys {
    certification: PKey<Private>,
    ed: PKey<Private>,
    x: PKey<Private>,
}
/// Owns a single logical operation. Software components are decrypted lazily
/// and released along with the PIN on finish, including every error path.
pub struct CompanionBackend<B: Backend> {
    hardware: B,
    envelope: Envelope,
    openssl: PathBuf,
    software: Option<SoftwareKeys>,
    finished: bool,
}
impl<B: Backend> CompanionBackend<B> {
    pub fn new(hardware: B, envelope: Envelope, openssl: PathBuf) -> Result<Self> {
        ensure!(
            openssl.is_absolute() && openssl.is_file(),
            "Explicit OpenSSL executable required"
        );
        Ok(Self {
            hardware,
            envelope,
            openssl,
            software: None,
            finished: false,
        })
    }
}
impl<B: Backend> Backend for CompanionBackend<B> {
    fn execute(&mut self, op: Operation, spki: &[u8], input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let result = (|| {
            ensure!(!self.finished, "Companion operation ended");
            match op {
                Operation::MlDsa87 | Operation::MlKem1024 => {
                    let slot = if op == Operation::MlDsa87 { "9c" } else { "9d" };
                    ensure!(
                        spki == self.envelope.data.keys[slot],
                        "Hardware component mismatch"
                    );
                    self.hardware.execute(op, spki, input)
                }
                Operation::Ed448 | Operation::X448 => {
                    ensure!(
                        spki == if op == Operation::Ed448 {
                            &self.envelope.public.ed
                        } else {
                            &self.envelope.public.x
                        },
                        "Software component mismatch"
                    );
                    if self.software.is_none() {
                        self.software = Some(self.envelope.data.open(
                            &self.envelope.public,
                            &mut self.hardware,
                            &self.openssl,
                        )?)
                    }
                    let keys = self.software.as_ref().unwrap();
                    if op == Operation::Ed448 {
                        ensure!([48, 64].contains(&input.len()), "Expected OpenPGP digest");
                        let mut s = Signer::new_without_digest(&keys.ed)?;
                        Ok(Zeroizing::new(s.sign_oneshot_to_vec(input)?))
                    } else {
                        let peer = PKey::public_key_from_der(input)?;
                        ensure!(peer.id() == openssl::pkey::Id::X448, "Expected X448 peer");
                        let mut derive = Deriver::new(&keys.x)?;
                        derive.set_peer(&peer)?;
                        let share = Zeroizing::new(derive.derive_to_vec()?);
                        ensure!(
                            share.len() == 56 && share.iter().any(|b| *b != 0),
                            "Invalid X448 share"
                        );
                        Ok(share)
                    }
                }
                _ => anyhow::bail!("Operation outside companion profile"),
            }
        })();
        if result.is_err() {
            self.finish()
        }
        result
    }
    fn finish(&mut self) {
        self.finished = true;
        self.software.take();
        self.hardware.finish();
    }
}
impl<B: Backend> Drop for CompanionBackend<B> {
    fn drop(&mut self) {
        self.finish()
    }
}
/// Convert through anonymous pipes, with output/time limits and no shell. The
/// empty passphrase is intentionally public; no secret appears in argv/env.
fn convert_p12(executable: &Path, p12: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut child = Command::new(executable)
        .args(["pkcs12", "-nodes", "-passin", "pass:"])
        .env_remove("OPENSSL_CONF")
        .env_remove("OPENSSL_MODULES")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || -> std::io::Result<Zeroizing<Vec<u8>>> {
        let mut b = Zeroizing::new(Vec::new());
        stdout.take(16385).read_to_end(&mut b)?;
        Ok(b)
    });
    let write = child.stdin.take().unwrap().write_all(p12);
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if write.is_err() || start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let pem = reader
        .join()
        .map_err(|_| anyhow::anyhow!("P12 pipe failed"))??;
    write?;
    ensure!(
        status.success() && pem.len() <= 16384,
        "P12 conversion failed"
    );
    Ok(pem)
}

/// Read a companion with its live slot mapping. No PIN or write is involved;
/// the PC/SC reader must be dropped before starting a PKCS#11 operation.
pub enum RestoreState {
    Ready(Envelope),
    Pending(PendingEnvelope),
}

/// Read and authenticate either form. The Pending branch carries only validated
/// public reconstruction metadata; it cannot perform a private operation until
/// the caller explicitly obtains authorization and drops the PC/SC reader.
pub fn read_card_for_restore(
    card: &mut impl crate::restore::Card,
) -> Result<(Vec<u8>, BTreeMap<String, Vec<u8>>, RestoreState)> {
    let serial = card.serial()?;
    let mut keys = BTreeMap::new();
    for slot in [0x86, 0x9c, 0x9d, 0x82] {
        keys.insert(
            format!("{slot:02x}"),
            card.public_key(slot)?
                .context("Missing hardware component")?,
        );
    }
    let manifest = card
        .object(0x5f5200)?
        .context("No encrypted companion manifest")?;
    let mut r = Reader(&manifest);
    ensure!(r.take(8)? == b"PQCIDX01", "Invalid companion manifest");
    let size = r.number()?;
    let digest = r.take(32)?;
    r.end()?;
    ensure!((1..=MAX).contains(&size), "Invalid companion length");
    let mut encoded = Vec::with_capacity(size);
    for i in 0..size.div_ceil(2048) {
        let chunk = card
            .object(0x5f5201 + i as u32)?
            .context("Incomplete companion")?;
        let mut c = Reader(&chunk);
        ensure!(
            c.take(8)? == b"PQCCHK01" && c.number()? == i,
            "Invalid companion chunk"
        );
        let n = 2048.min(size - i * 2048);
        encoded.extend(c.take(n)?);
        c.end()?;
    }
    ensure!(
        Sha256::digest(&encoded).as_slice() == digest,
        "Companion manifest digest mismatch"
    );
    ensure!(
        card.object(0x5f5200)?.as_deref() == Some(manifest.as_slice()) && card.serial()? == serial,
        "Companion changed while reading"
    );
    let data = AuthenticatedEnvelope::parse(&encoded, serial, &keys)?;
    let state = if data.ultra {
        RestoreState::Pending(PendingEnvelope::parse(&encoded, serial, &keys)?)
    } else {
        RestoreState::Ready(Envelope::parse(&encoded, serial, &keys)?)
    };
    Ok((encoded, keys, state))
}

/// Existing PIN-free callers remain explicit: they cannot accidentally trigger
/// reconstruction or a private operation when a card switches to ultra format.
pub fn read_card(
    card: &mut impl crate::restore::Card,
) -> Result<(Vec<u8>, BTreeMap<String, Vec<u8>>, Envelope)> {
    let (encoded, keys, state) = read_card_for_restore(card)?;
    let RestoreState::Ready(envelope) = state else {
        anyhow::bail!("Ultra companion needs first-host reconstruction; use the restore command")
    };
    Ok((encoded, keys, envelope))
}

#[cfg(test)]
mod compression_tests {
    use super::{expand_companion, COMPRESSED_MAGIC, MAX};
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    /// The compressor is a test fixture only. Readers need not reproduce a
    /// particular compressed byte sequence to preserve the signed plaintext.
    fn packed(plain: &[u8]) -> Vec<u8> {
        let mut encoded = COMPRESSED_MAGIC.to_vec();
        encoded.extend((plain.len() as u32).to_be_bytes());
        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(plain).unwrap();
        encoded.extend(zlib.finish().unwrap());
        encoded
    }

    #[test]
    fn storage_compression_preserves_exact_inner_bytes() {
        let plain: Vec<_> = (0..4096).map(|i| (i % 251) as u8).collect();
        assert_eq!(expand_companion(&plain).unwrap(), plain);
        assert_eq!(expand_companion(&packed(&plain)).unwrap(), plain);
        let maximum = vec![0x42; MAX];
        assert_eq!(expand_companion(&packed(&maximum)).unwrap(), maximum);
    }

    #[test]
    fn compressed_boundaries_and_nesting_fail_closed() {
        let plain = vec![0x42; 4096];
        let encoded = packed(&plain);
        for end in 8..encoded.len() {
            assert!(
                expand_companion(&encoded[..end]).is_err(),
                "accepted truncation at {end}"
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(expand_companion(&trailing).is_err());
        let mut concatenated = encoded.clone();
        concatenated.extend(&encoded[12..]);
        assert!(expand_companion(&concatenated).is_err());
        for size in [0, 4095, 4097, MAX as u32 + 1, u32::MAX] {
            let mut wrong = encoded.clone();
            wrong[8..12].copy_from_slice(&size.to_be_bytes());
            assert!(
                expand_companion(&wrong).is_err(),
                "accepted declared size {size}"
            );
        }
        assert!(expand_companion(&packed(&encoded)).is_err());
        let mut damaged = encoded;
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(expand_companion(&damaged).is_err());
    }

    #[test]
    fn input_and_expansion_limits_apply_before_parsing() {
        assert!(expand_companion(&vec![0; MAX + 1]).is_err());
        assert!(expand_companion(&packed(&vec![0x42; MAX + 1])).is_err());
        assert!(expand_companion(COMPRESSED_MAGIC).is_err());
    }

    #[test]
    fn changed_card_manifest_stops_before_envelope_use() -> anyhow::Result<()> {
        use super::{read_card_for_restore, Digest, Sha256};
        // Deliberately not a valid envelope: the changed commit marker must be
        // rejected before envelope parsing can start. This models a concurrent
        // writer or removal/reinsertion between the initial and final reads.
        struct Card {
            reads: usize,
        }
        impl crate::restore::Card for Card {
            fn serial(&mut self) -> anyhow::Result<u32> {
                Ok(123456)
            }
            fn public_key(&mut self, _slot: u8) -> anyhow::Result<Option<Vec<u8>>> {
                Ok(Some(vec![0]))
            }
            fn object(&mut self, tag: u32) -> anyhow::Result<Option<Vec<u8>>> {
                if tag == 0x5f5200 {
                    self.reads += 1;
                    let mut manifest = b"PQCIDX01".to_vec();
                    manifest.extend(1u32.to_be_bytes());
                    manifest.extend(Sha256::digest([0]));
                    if self.reads > 1 {
                        manifest[43] ^= 1;
                    }
                    Ok(Some(manifest))
                } else if tag == 0x5f5201 {
                    let mut chunk = b"PQCCHK01".to_vec();
                    chunk.extend(0u32.to_be_bytes());
                    chunk.push(0);
                    Ok(Some(chunk))
                } else {
                    Ok(None)
                }
            }
        }
        let mut card = Card { reads: 0 };
        let error = match read_card_for_restore(&mut card) {
            Ok(_) => anyhow::bail!("Accepted changed companion manifest"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("changed while reading"));
        assert_eq!(card.reads, 2);
        Ok(())
    }
}
