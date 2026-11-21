//! Level 3 reverse-polyfill: classical private keys remain in PIV while the
//! independent ML-DSA-65/ML-KEM-768 seeds are encrypted in an on-card companion.
//!
//! P-384 in slot 83 unwraps the seed container without touch (PIN required).
//! Message operations still need the touch-required Ed25519/X25519 key. This
//! provides hybrid message algorithms, but CLASSICAL protection at rest. No
//! seed, plaintext P12, PIN, or wrapping key is persisted by this module.
use crate::{public_spki, Backend, Operation};
use anyhow::{bail, ensure, Context, Result};
use flate2::{Decompress, FlushDecompress, Status};
use openssl::{
    asn1::Asn1Time,
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::{Signer, Verifier},
    symm::{Cipher, Crypter, Mode},
    x509::X509,
};
use ossl::{
    asymcipher::{EncOp, OsslAsymcipher},
    pkey::{EvpPkey, EvpPkeyType, MlkeyData, PkeyData},
    signature::{mldsa_with_mu, OsslSignature, SigAlg, SigOp},
    OsslContext, OsslSecret,
};
use sequoia_openpgp::{
    cert::amalgamation::key::PrimaryKey, crypto::mpi, parse::Parse, policy::StandardPolicy,
    types::RevocationStatus, Cert,
};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const MAX: usize = 65536;
const SLOTS: [&str; 4] = ["82", "9c", "9d", "83"];
const SIGN_DOMAIN: &[u8] = b"PQMail Level3 companion signature v1";
const KDF_DOMAIN: &[u8] = b"PQMail companion L3 P384 v1";

/// All framing is bounded before allocating. The compressed wrapper is the
/// same storage encoding used by other companions, but its inner magic and
/// cryptographic domains are distinct and cannot be reinterpreted as Level 5.
fn expand(encoded: &[u8]) -> Result<Vec<u8>> {
    ensure!(encoded.len() <= MAX, "Oversized Level 3 companion");
    if !encoded.starts_with(b"PQMCZ001") {
        return Ok(encoded.to_vec());
    }
    ensure!(encoded.len() >= 12, "Truncated compression header");
    let size = u32::from_be_bytes(encoded[8..12].try_into()?) as usize;
    ensure!(
        (1..=MAX).contains(&size),
        "Invalid companion expansion size"
    );
    let mut out = vec![0; size + 1];
    let mut d = Decompress::new(true);
    ensure!(
        d.decompress(&encoded[12..], &mut out, FlushDecompress::Finish)? == Status::StreamEnd
            && d.total_in() as usize == encoded.len() - 12
            && d.total_out() as usize == size,
        "Invalid companion compression boundary"
    );
    out.truncate(size);
    ensure!(
        !out.starts_with(b"PQMCZ001"),
        "Nested companion compression"
    );
    Ok(out)
}
struct Read<'a>(&'a [u8]);
impl<'a> Read<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.0.len(), "Truncated companion");
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?) as usize)
    }
    fn blob(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()?;
        ensure!(n <= MAX, "Oversized field");
        self.take(n)
    }
    fn end(&self) -> Result<()> {
        ensure!(self.0.is_empty(), "Trailing companion data");
        Ok(())
    }
}
fn p384(point: &[u8]) -> Result<Vec<u8>> {
    ensure!(point.len() == 97 && point[0] == 4, "Expected P-384 point");
    let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, point, &mut ctx)?;
    ensure!(
        !point.is_infinity(&group) && point.is_on_curve(&group, &mut ctx)?,
        "Invalid P-384 point"
    );
    Ok(PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)?.public_key_to_der()?)
}
fn typed(spki: &[u8], op: Operation) -> Result<()> {
    let key = PKey::public_key_from_der(spki)?;
    ensure!(
        key.public_key_to_der()? == spki,
        "Noncanonical component SPKI"
    );
    let raw = key.raw_public_key()?;
    ensure!(public_spki(op, &raw)? == spki, "Wrong component algorithm");
    Ok(())
}

/// A verified public envelope. Every field needed for private operations is
/// private; constructors check the certificate and BOTH envelope signatures,
/// canonical role manifest and expected live public keys before any unwrap.
pub struct Envelope {
    pub serial: u32,
    pub certificate: Cert,
    keys: BTreeMap<String, Vec<u8>>,
    pq: BTreeMap<String, Vec<u8>>,
    certificate_bytes: Vec<u8>,
    anchors: [Vec<u8>; 2],
    ephemeral: Vec<u8>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
}
impl Envelope {
    pub fn certificate_bytes(&self) -> &[u8] {
        &self.certificate_bytes
    }
    pub fn anchors(&self) -> &[Vec<u8>; 2] {
        &self.anchors
    }
    pub fn parse(
        encoded: &[u8],
        serial: u32,
        expected: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self> {
        ensure!(
            serial > 0
                && serial <= i32::MAX as u32
                && expected.len() == 4
                && SLOTS.iter().all(|s| expected.contains_key(*s)),
            "Invalid Level 3 mapping"
        );
        typed(&expected["82"], Operation::Ed25519)?;
        typed(&expected["9c"], Operation::Ed25519)?;
        typed(&expected["9d"], Operation::X25519)?;
        ensure!(
            expected["82"] != expected["9c"],
            "Certification and signing keys must be separate"
        );
        let wrap = PKey::public_key_from_der(&expected["83"])?;
        ensure!(
            wrap.ec_key()?.group().curve_name() == Some(Nid::SECP384R1)
                && wrap.public_key_to_der()? == expected["83"],
            "Expected canonical P-384 wrapping key"
        );
        let raw = expand(encoded)?;
        let mut outer = Read(&raw);
        let body = outer.blob()?;
        let signature = outer.blob()?;
        outer.end()?;
        ensure!(
            signature.len() == 3373,
            "Wrong hybrid envelope signature length"
        );
        let mut hash = Sha512::new();
        hash.update(SIGN_DOMAIN);
        hash.update(body);
        let digest = hash.finalize();
        // The expected hardware certification key authenticates the envelope
        // before parsing its self-contained PQ certificate component.
        let ed = PKey::public_key_from_der(&expected["82"])?;
        ensure!(
            Verifier::new_without_digest(&ed)?.verify_oneshot(&signature[..64], &digest)?,
            "Hardware envelope signature rejected"
        );
        let mut r = Read(body);
        ensure!(
            r.take(8)? == b"PQMCP003" && r.u32()? == serial as usize,
            "Wrong Level 3 companion format/serial"
        );
        let mut keys = BTreeMap::new();
        for slot in SLOTS {
            let key = r.blob()?;
            ensure!(key == expected[slot], "Live key mismatch in {slot}");
            keys.insert(slot.to_string(), key.to_vec());
        }
        let cert_bytes = r.blob()?.to_vec();
        let anchors = [r.blob()?.to_vec(), r.blob()?.to_vec()];
        let manifest = r.blob()?.to_vec();
        let ephemeral = p384(r.take(97)?)?;
        let salt = r.take(32)?.to_vec();
        let nonce = r.take(12)?.to_vec();
        let aad = body[..body.len() - r.0.len()].to_vec();
        let ciphertext = r.blob()?.to_vec();
        r.end()?;
        ensure!(ciphertext.len() >= 16, "Truncated companion ciphertext");
        let certificate = Cert::from_bytes(&cert_bytes)?;
        ensure!(
            !certificate.is_tsk(),
            "Public certificate contains secret packets"
        );
        let policy = StandardPolicy::new();
        let valid = certificate.with_policy(&policy, None)?;
        valid.alive()?;
        ensure!(
            matches!(
                valid.revocation_status(),
                RevocationStatus::NotAsFarAsWeKnow
            ),
            "Revoked companion identity"
        );
        let mpi::PublicKey::MLDSA65_Ed25519 { mldsa, eddsa } =
            certificate.primary_key().key().mpis()
        else {
            bail!("Expected Level 3 certification primary")
        };
        ensure!(
            public_spki(Operation::Ed25519, eddsa.as_ref())? == keys["82"],
            "Certification key mismatch"
        );
        let mut pq = BTreeMap::new();
        pq.insert(
            "cert-pq".into(),
            public_spki(Operation::MlDsa65, mldsa.as_ref())?,
        );
        let primary = PKey::public_key_from_der(&pq["cert-pq"])?;
        ensure!(
            Verifier::new_without_digest(&primary)?.verify_oneshot(&signature[64..], &digest)?,
            "PQ envelope signature rejected"
        );
        let sign: Vec<_> = valid.keys().alive().revoked(false).for_signing().collect();
        let kem: Vec<_> = valid
            .keys()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .collect();
        ensure!(
            sign.len() == 1
                && kem.len() == 1
                && !sign[0].primary()
                && !kem[0].primary()
                && certificate.keys().count() == 3,
            "Expected separate certification/signing/encryption keys"
        );
        ensure!(
            certificate.primary_key().key().version() == 6
                && sign[0].key().version() == 6
                && kem[0].key().version() == 6,
            "Expected v6 companion keys"
        );
        let mpi::PublicKey::MLDSA65_Ed25519 { mldsa, eddsa } = sign[0].key().mpis() else {
            bail!("Expected Level 3 signing key")
        };
        ensure!(
            public_spki(Operation::Ed25519, eddsa.as_ref())? == keys["9c"],
            "Signing key mismatch"
        );
        pq.insert(
            "sign-pq".into(),
            public_spki(Operation::MlDsa65, mldsa.as_ref())?,
        );
        ensure!(
            pq["cert-pq"] != pq["sign-pq"],
            "PQ certification and signing keys must be separate"
        );
        let mpi::PublicKey::MLKEM768_X25519 { mlkem, ecdh } = kem[0].key().mpis() else {
            bail!("Expected Level 3 encryption key")
        };
        ensure!(
            public_spki(Operation::X25519, ecdh.as_ref())? == keys["9d"],
            "Encryption key mismatch"
        );
        pq.insert(
            "kem-pq".into(),
            public_spki(Operation::MlKem768, mlkem.as_ref())?,
        );
        let canonical = manifest_bytes(serial, &keys, &pq);
        ensure!(
            canonical == manifest,
            "Unsupported or noncanonical Level 3 role manifest"
        );
        let anchor_sign = PKey::public_key_from_der(&pq["sign-pq"])?;
        let uri = format!(
            "https://github.com/ve7jtb/pq-mail/profile/level3-polyfill/v1/{}",
            certificate.fingerprint().to_hex().to_lowercase()
        );
        let now = Asn1Time::days_from_now(0)?;
        // Identity carriers are OpenPGP-only. Every SAN email must be one of
        // the authenticated v6 User IDs, so desktop routing cannot acquire an
        // unrelated email address merely because the envelope is well signed.
        let emails = valid
            .userids()
            .map(|u| u.userid().email().map(|e| e.map(str::to_ascii_lowercase)))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<BTreeSet<_>>();
        ensure!(!emails.is_empty(), "Missing certified email identity");
        let issuer = X509::from_der(&anchors[0])?.subject_name().to_der()?;
        for (i, der) in anchors.iter().enumerate() {
            let cert = X509::from_der(der)?;
            ensure!(cert.to_der()? == *der, "Noncanonical identity anchor");
            ensure!(
                cert.version() == 2 && cert.issuer_name().to_der()? == issuer,
                "Wrong identity anchor version/signature/issuer"
            );
            non_ca_anchor(der)?;
            ensure!(
                cert.public_key()?.public_key_to_der()?
                    == pq[if i == 0 { "sign-pq" } else { "kem-pq" }]
                    && cert.verify(&anchor_sign)?,
                "Invalid identity anchor key/signature"
            );
            ensure!(
                cert.not_before() <= now && cert.not_after() >= now,
                "Expired/not-yet-valid identity anchor"
            );
            let names = cert
                .subject_alt_names()
                .context("Missing identity anchor SAN")?;
            let mut carrier_emails = BTreeSet::new();
            let mut markers = 0;
            for name in &names {
                if let Some(email) = name.email() {
                    ensure!(
                        carrier_emails.insert(email.to_ascii_lowercase()),
                        "Duplicate identity anchor email"
                    );
                } else {
                    ensure!(
                        name.uri() == Some(uri.as_str()),
                        "Unexpected identity anchor SAN"
                    );
                    markers += 1;
                }
            }
            ensure!(
                markers == 1 && carrier_emails == emails,
                "Identity anchor email/fingerprint bindings mismatch"
            );
            let units = cert
                .subject_name()
                .entries_by_nid(Nid::ORGANIZATIONALUNITNAME)
                .collect::<Vec<_>>();
            ensure!(
                units.len() == 1 && units[0].data().as_slice() == b"OpenPGP-only companion",
                "Invalid OpenPGP-only carrier marker"
            );
        }
        Ok(Self {
            serial,
            certificate,
            keys,
            pq,
            certificate_bytes: cert_bytes,
            anchors,
            ephemeral,
            salt,
            nonce,
            aad,
            ciphertext,
        })
    }
    fn open(&self, hardware: &mut impl Backend) -> Result<SoftwareKeys> {
        let secret = hardware.execute(Operation::P384, &self.keys["83"], &self.ephemeral)?;
        ensure!(
            secret.len() == 48 && secret.iter().any(|b| *b != 0),
            "Invalid P-384 wrapping secret"
        );
        let hmac = |key: &[u8], data: &[u8]| -> Result<Zeroizing<Vec<u8>>> {
            let key = PKey::hmac(key)?;
            let mut h = Signer::new(MessageDigest::sha256(), &key)?;
            h.update(data)?;
            Ok(Zeroizing::new(h.sign_to_vec()?))
        };
        let prk = hmac(&self.salt, &secret)?;
        let mut info = KDF_DOMAIN.to_vec();
        info.extend(Sha256::digest(&self.aad));
        info.push(1);
        let key = hmac(&prk, &info)?;
        let split = self.ciphertext.len() - 16;
        // Own the output allocation before decryption begins. In particular,
        // a rejected GCM tag must wipe any tentative plaintext, not merely the
        // successfully returned P12. Parsing starts only after finalization.
        let cipher = Cipher::aes_256_gcm();
        let mut plain = Zeroizing::new(vec![0; split + cipher.block_size()]);
        let mut decryptor = Crypter::new(cipher, Mode::Decrypt, &key, Some(&self.nonce))?;
        decryptor.aad_update(&self.aad)?;
        decryptor.set_tag(&self.ciphertext[split..])?;
        let written = decryptor.update(&self.ciphertext[..split], &mut plain)?;
        let tail = decryptor.finalize(&mut plain[written..])?;
        plain.truncate(written + tail);
        let mut r = Read(&plain);
        let p12 = r.blob()?;
        r.end()?;
        let seeds = parse_seed_p12(p12)?;
        let context = OsslContext::new_lib_ctx_checked()?;
        let mut keys = BTreeMap::new();
        for (role, seed) in seeds {
            let kind = if role == "kem-pq" {
                EvpPkeyType::MlKem768
            } else {
                EvpPkeyType::Mldsa65
            };
            let key = EvpPkey::import(
                &context,
                kind,
                PkeyData::Mlkey(MlkeyData {
                    pubkey: None,
                    prikey: None,
                    seed: Some(OsslSecret::from_slice(seed.as_slice())),
                }),
            )?;
            let PkeyData::Mlkey(public) = key.export_public()? else {
                bail!("Wrong imported PQ key")
            };
            let op = if role == "kem-pq" {
                Operation::MlKem768
            } else {
                Operation::MlDsa65
            };
            ensure!(
                public_spki(
                    op,
                    public
                        .pubkey
                        .as_deref()
                        .context("Missing derived public key")?
                )? == self.pq[&role],
                "Seed does not match certified public key"
            );
            keys.insert(role, key);
        }
        Ok(SoftwareKeys { keys, context })
    }
}

fn manifest_bytes(
    serial: u32,
    hardware: &BTreeMap<String, Vec<u8>>,
    pq: &BTreeMap<String, Vec<u8>>,
) -> Vec<u8> {
    let entries = [
        (
            "certification-classical",
            "Ed25519",
            "piv",
            "82",
            &hardware["82"],
        ),
        ("signing-classical", "Ed25519", "piv", "9c", &hardware["9c"]),
        (
            "decryption-classical",
            "X25519",
            "piv",
            "9d",
            &hardware["9d"],
        ),
        ("companion-wrap", "P-384", "piv", "83", &hardware["83"]),
        (
            "certification-pq",
            "ML-DSA-65",
            "companion",
            "",
            &pq["cert-pq"],
        ),
        ("signing-pq", "ML-DSA-65", "companion", "", &pq["sign-pq"]),
        (
            "decryption-pq",
            "ML-KEM-768",
            "companion",
            "",
            &pq["kem-pq"],
        ),
    ];
    let components=entries.iter().map(|(role,algorithm,storage,slot,spki)|{let hash=Sha256::digest(spki).iter().map(|b|format!("{b:02x}")).collect::<String>();format!("{{\"role\":\"{role}\",\"algorithm\":\"{algorithm}\",\"storage\":\"{storage}\",\"slot\":\"{slot}\",\"sha256\":\"{hash}\"}}")}).collect::<Vec<_>>().join(",");
    format!("{{\"version\":1,\"serial\":{serial},\"profile\":\"LEVEL3_POLYFILL\",\"components\":[{components}]}}").into_bytes()
}

/// Minimal canonical DER parser for this deliberately narrow private container.
/// No generic OpenSSL P12 conversion may normalize away duplicate roles, extra
/// bags, expanded secrets or parameters that violate the portable seed format.
struct Der<'a>(&'a [u8]);
impl<'a> Der<'a> {
    fn value(&mut self, tag: u8) -> Result<&'a [u8]> {
        ensure!(
            self.0.len() >= 2 && self.0[0] == tag,
            "Unexpected P12 DER tag"
        );
        let first = self.0[1];
        let (length, head) = if first < 128 {
            (first as usize, 2)
        } else {
            let n = (first & 127) as usize;
            ensure!(
                (1..=3).contains(&n) && self.0.len() >= 2 + n && self.0[2] != 0,
                "Invalid DER length"
            );
            let mut size = 0usize;
            for b in &self.0[2..2 + n] {
                size = (size << 8) | *b as usize;
            }
            ensure!(
                size >= 128 && (n == 1 || size >= (1usize << (8 * (n - 1)))),
                "Nonminimal DER length"
            );
            (size, 2 + n)
        };
        ensure!(
            length <= MAX && head + length <= self.0.len(),
            "Truncated P12 DER"
        );
        let data = &self.0[head..head + length];
        self.0 = &self.0[head + length..];
        Ok(data)
    }
    fn end(&self) -> Result<()> {
        ensure!(self.0.is_empty(), "Unexpected extra P12 data");
        Ok(())
    }
}
/// These catalog carriers must never claim CA capability. Inspect the simple
/// DER extension list directly, since OpenSSL's high-level X509 interface does
/// not expose the CA flag. Duplicate extensions and optional unique identifiers
/// are outside this fixed carrier format and fail closed.
fn non_ca_anchor(encoded: &[u8]) -> Result<()> {
    let mut outer = Der(encoded);
    let mut certificate = Der(outer.value(0x30)?);
    outer.end()?;
    let mut tbs = Der(certificate.value(0x30)?);
    let mut signature = Der(certificate.value(0x30)?);
    ensure!(
        signature.value(6)? == Operation::MlDsa65.oid(),
        "Wrong carrier signature algorithm"
    );
    signature.end()?;
    certificate.value(3)?;
    certificate.end()?;
    let mut version = Der(tbs.value(0xa0)?);
    ensure!(version.value(2)? == [2], "Expected v3 carrier");
    version.end()?;
    tbs.value(2)?;
    for _ in 0..5 {
        tbs.value(0x30)?;
    }
    let mut explicit = Der(tbs.value(0xa3)?);
    tbs.end()?;
    let mut extensions = Der(explicit.value(0x30)?);
    explicit.end()?;
    let mut found = false;
    let mut seen = BTreeSet::new();
    while !extensions.0.is_empty() {
        let mut extension = Der(extensions.value(0x30)?);
        let oid = extension.value(6)?;
        ensure!(seen.insert(oid.to_vec()), "Duplicate carrier extension");
        if extension.0.first() == Some(&1) {
            let critical = extension.value(1)?;
            ensure!(critical == [0xff], "Noncanonical extension critical flag");
        }
        let value = extension.value(4)?;
        extension.end()?;
        if oid == [0x55, 0x1d, 0x13] {
            ensure!(value == [0x30, 0], "Carrier cannot be a CA");
            found = true;
        }
    }
    ensure!(found, "Missing non-CA carrier constraint");
    Ok(())
}

const DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1];
const BAG_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 12, 10, 1, 1];
const NAME_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 20];
fn data_content<'a>(input: &mut Der<'a>) -> Result<&'a [u8]> {
    let mut info = Der(input.value(0x30)?);
    ensure!(
        info.value(6)? == DATA_OID,
        "P12 content must be unencrypted data"
    );
    let mut explicit = Der(info.value(0xa0)?);
    let data = explicit.value(4)?;
    explicit.end()?;
    info.end()?;
    Ok(data)
}
fn parse_seed_p12(p12: &[u8]) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>> {
    ensure!(p12.len() <= 4096, "Seed P12 exceeds limit");
    let mut der = Der(p12);
    let mut pfx = Der(der.value(0x30)?);
    der.end()?;
    ensure!(pfx.value(2)? == [3], "Expected PFX version 3");
    let authenticated = data_content(&mut pfx)?;
    pfx.end()?;
    let mut top = Der(authenticated);
    let mut infos = Der(top.value(0x30)?);
    top.end()?;
    let mut result = BTreeMap::new();
    while !infos.0.is_empty() {
        let contents = data_content(&mut infos)?;
        let mut der = Der(contents);
        let mut bags = Der(der.value(0x30)?);
        der.end()?;
        let mut bag = Der(bags.value(0x30)?);
        bags.end()?;
        ensure!(bag.value(6)? == BAG_OID, "Expected unencrypted seed keyBag");
        let mut key_explicit = Der(bag.value(0xa0)?);
        let mut private = Der(key_explicit.value(0x30)?);
        key_explicit.end()?;
        ensure!(private.value(2)? == [0], "Expected version-0 seed PKCS8");
        let mut alg = Der(private.value(0x30)?);
        let oid = alg.value(6)?;
        alg.end()?;
        let secret = private.value(4)?;
        private.end()?;
        let mut attrs = Der(bag.value(0x31)?);
        bag.end()?;
        let mut attr = Der(attrs.value(0x30)?);
        attrs.end()?;
        ensure!(attr.value(6)? == NAME_OID, "Unexpected seed bag attribute");
        let mut names = Der(attr.value(0x31)?);
        attr.end()?;
        let name = names.value(0x1e)?;
        names.end()?;
        ensure!(
            name.len() % 2 == 0 && name.chunks_exact(2).all(|v| v[0] == 0 && v[1].is_ascii()),
            "Invalid seed bag name"
        );
        let role = String::from_utf8(name.chunks_exact(2).map(|v| v[1]).collect())?;
        ensure!(
            ["cert-pq", "sign-pq", "kem-pq"].contains(&role.as_str())
                && !result.contains_key(&role),
            "Duplicate or unknown seed role"
        );
        let op = if role == "kem-pq" {
            Operation::MlKem768
        } else {
            Operation::MlDsa65
        };
        ensure!(oid == op.oid(), "Wrong seed role algorithm");
        let mut seed = Der(secret);
        let raw = seed.value(0x80)?;
        seed.end()?;
        ensure!(
            raw.len() == if role == "kem-pq" { 64 } else { 32 },
            "Wrong PQ seed length"
        );
        result.insert(role, Zeroizing::new(raw.to_vec()));
    }
    ensure!(result.len() == 3, "Incomplete seed P12");
    Ok(result)
}

// Keys are dropped before their context. OpenSSL owns and clears expanded
// private allocations; all Rust seed/plaintext intermediates use Zeroizing.
struct SoftwareKeys {
    keys: BTreeMap<String, EvpPkey>,
    context: OsslContext,
}
pub struct CompanionBackend<B: Backend> {
    hardware: B,
    envelope: Envelope,
    software: Option<SoftwareKeys>,
    finished: bool,
}
impl<B: Backend> CompanionBackend<B> {
    pub fn new(hardware: B, envelope: Envelope) -> Self {
        Self {
            hardware,
            envelope,
            software: None,
            finished: false,
        }
    }
    fn unlock(&mut self) -> Result<()> {
        if self.software.is_none() {
            self.software = Some(self.envelope.open(&mut self.hardware)?);
        }
        Ok(())
    }
}
impl<B: Backend> Backend for CompanionBackend<B> {
    fn execute(&mut self, op: Operation, spki: &[u8], input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let result = (|| {
            ensure!(!self.finished, "Companion operation ended");
            match op {
                Operation::MlDsa65 | Operation::MlKem768 => {
                    let role = if op == Operation::MlDsa65 {
                        "sign-pq"
                    } else {
                        "kem-pq"
                    };
                    ensure!(spki == self.envelope.pq[role], "Wrong software component");
                    ensure!(
                        input.len() == if op == Operation::MlDsa65 { 64 } else { 1088 },
                        "Wrong PQ operation input"
                    );
                    self.unlock()?;
                    let software = self.software.as_mut().unwrap();
                    let key = software.keys.get_mut(role).unwrap();
                    if op == Operation::MlDsa65 {
                        let mut signer = OsslSignature::new(
                            &software.context,
                            SigOp::Sign,
                            SigAlg::Mldsa65,
                            key,
                            mldsa_with_mu(None, false)?.as_ref(),
                        )?;
                        let mut signature = Zeroizing::new(vec![0; 3309]);
                        let size = signer.sign(input, Some(&mut signature))?;
                        ensure!(size == 3309, "Wrong ML-DSA signature size");
                        Ok(signature)
                    } else {
                        let mut decapsulator =
                            OsslAsymcipher::new(&software.context, EncOp::Decapsulate, key, None)?;
                        let secret = Zeroizing::new(decapsulator.decapsulate(input)?);
                        ensure!(secret.len() == 32, "Wrong ML-KEM secret size");
                        Ok(Zeroizing::new(secret.to_vec()))
                    }
                }
                Operation::Ed25519 | Operation::X25519 => {
                    let slot = if op == Operation::Ed25519 { "9c" } else { "9d" };
                    ensure!(
                        spki == self.envelope.keys[slot],
                        "Wrong hardware message key"
                    );
                    if op == Operation::Ed25519 {
                        ensure!([48, 64].contains(&input.len()), "Expected OpenPGP digest");
                    } else {
                        typed(input, Operation::X25519)?;
                    }
                    self.hardware.execute(op, spki, input)
                }
                _ => bail!("Operation outside Level 3 companion profile"),
            }
        })();
        if result.is_err() {
            self.finish();
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
        self.finish();
    }
}

/// Inspect only the bounded format discriminator for generic restore routing.
/// This is NOT authentication: callers must then run the selected profile's
/// complete read/verify path, which rereads the card and checks all live keys.
/// Unknown formats never fall back to either profile or a private operation.
pub fn is_level3_card(card: &mut impl crate::restore::Card) -> Result<bool> {
    let (_, stored) = read_storage(card)?;
    let raw = expand(&stored)?;
    let mut outer = Read(&raw);
    let body = outer.blob()?;
    outer.blob()?;
    outer.end()?;
    let mut body = Read(body);
    match body.take(8)? {
        b"PQMCP003" => Ok(true),
        b"PQMCP001" | b"PQMCP002" => Ok(false),
        _ => bail!("Unsupported companion format"),
    }
}

/// Common bounded public-storage read used for dispatch and authenticated restore.
/// The manifest is checked twice and the serial must remain stable throughout.
fn read_storage(card: &mut impl crate::restore::Card) -> Result<(u32, Vec<u8>)> {
    let serial = card.serial()?;
    let manifest = card.object(0x5f5200)?.context("No companion manifest")?;
    let mut r = Read(&manifest);
    ensure!(r.take(8)? == b"PQCIDX01", "Invalid companion manifest");
    let size = r.u32()?;
    let digest = r.take(32)?;
    r.end()?;
    ensure!((1..=MAX).contains(&size), "Invalid companion size");
    let mut encoded = Vec::with_capacity(size);
    for i in 0..size.div_ceil(2048) {
        let chunk = card
            .object(0x5f5201 + i as u32)?
            .context("Incomplete companion")?;
        let mut c = Read(&chunk);
        ensure!(
            c.take(8)? == b"PQCCHK01" && c.u32()? == i,
            "Invalid companion chunk"
        );
        encoded.extend(c.take(2048.min(size - i * 2048))?);
        c.end()?;
    }
    ensure!(
        Sha256::digest(&encoded).as_slice() == digest,
        "Companion digest mismatch"
    );
    ensure!(
        card.object(0x5f5200)?.as_deref() == Some(manifest.as_slice()) && card.serial()? == serial,
        "Companion changed while reading"
    );
    Ok((serial, encoded))
}

/// PIN-free read and certificate authentication, never a provisioning path.
pub fn read_card(
    card: &mut impl crate::restore::Card,
) -> Result<(Vec<u8>, BTreeMap<String, Vec<u8>>, Envelope)> {
    let (serial, encoded) = read_storage(card)?;
    let mut keys = BTreeMap::new();
    for slot in [0x82, 0x9c, 0x9d, 0x83] {
        keys.insert(
            format!("{slot:02x}"),
            card.public_key(slot)?
                .context("Missing Level 3 hardware key")?,
        );
    }
    ensure!(
        card.serial()? == serial,
        "Card changed while reading live keys"
    );
    // Keep the storage snapshot coherent through the subsequent live-key
    // reads as well; a concurrent backup must cause retry, not a stale import.
    let committed = [
        b"PQCIDX01".as_slice(),
        &(encoded.len() as u32).to_be_bytes(),
        Sha256::digest(&encoded).as_slice(),
    ]
    .concat();
    ensure!(
        card.object(0x5f5200)?.as_deref() == Some(committed.as_slice()),
        "Companion changed while reading live keys"
    );
    let envelope = Envelope::parse(&encoded, serial, &keys)?;
    Ok((encoded, keys, envelope))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    // Synthetic test seeds only. Build the exact constrained PKCS#12 grammar,
    // independently from the Java generator, to exercise parser boundaries.
    fn d(tag: u8, body: &[u8]) -> Vec<u8> {
        crate::der(tag, body)
    }
    fn data(body: &[u8]) -> Vec<u8> {
        d(0x30, &[d(6, DATA_OID), d(0xa0, &d(4, body))].concat())
    }
    fn bag(role: &str, algorithm: Operation, seed: &[u8]) -> Vec<u8> {
        let key = d(
            0x30,
            &[
                d(2, &[0]),
                d(0x30, &d(6, algorithm.oid())),
                d(4, &d(0x80, seed)),
            ]
            .concat(),
        );
        let name = role.bytes().flat_map(|b| [0, b]).collect::<Vec<_>>();
        let attr = d(
            0x31,
            &d(0x30, &[d(6, NAME_OID), d(0x31, &d(0x1e, &name))].concat()),
        );
        data(&d(
            0x30,
            &d(0x30, &[d(6, BAG_OID), d(0xa0, &key), attr].concat()),
        ))
    }
    fn p12(bags: Vec<Vec<u8>>) -> Vec<u8> {
        d(0x30, &[d(2, &[3]), data(&d(0x30, &bags.concat()))].concat())
    }
    fn three() -> Vec<Vec<u8>> {
        vec![
            bag("cert-pq", Operation::MlDsa65, &[1; 32]),
            bag("sign-pq", Operation::MlDsa65, &[2; 32]),
            bag("kem-pq", Operation::MlKem768, &[3; 64]),
        ]
    }
    #[test]
    fn exact_seed_roles_and_lengths_are_required() -> Result<()> {
        let parsed = parse_seed_p12(&p12(three()))?;
        assert_eq!(parsed["cert-pq"].as_slice(), [1; 32]);
        assert_eq!(parsed["sign-pq"].as_slice(), [2; 32]);
        assert_eq!(parsed["kem-pq"].as_slice(), [3; 64]);
        for replacement in [
            bag("unknown", Operation::MlDsa65, &[2; 32]),
            bag("cert-pq", Operation::MlDsa65, &[2; 32]),
            bag("sign-pq", Operation::MlKem768, &[2; 64]),
            bag("sign-pq", Operation::MlDsa65, &[2; 31]),
        ] {
            let mut bags = three();
            bags[1] = replacement;
            assert!(parse_seed_p12(&p12(bags)).is_err());
        }
        let mut bags = three();
        bags.pop();
        assert!(parse_seed_p12(&p12(bags)).is_err());
        let mut bags = three();
        bags.push(bag("cert-pq", Operation::MlDsa65, &[4; 32]));
        assert!(parse_seed_p12(&p12(bags)).is_err());
        Ok(())
    }
    #[test]
    fn p12_der_cannot_hide_trailing_or_noncanonical_fields() {
        let valid = p12(three());
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(parse_seed_p12(&trailing).is_err());
        for length in 0..valid.len() {
            assert!(parse_seed_p12(&valid[..length]).is_err());
        }
        assert!(Der(&[0x04, 0x81, 1, 0]).value(4).is_err());
        assert!(Der(&[0x04, 0x80, 0, 0]).value(4).is_err());
        assert!(Der(&[0x04, 0x82, 0, 128]).value(4).is_err());
    }
    /// Public classification is intentionally separate from authentication.
    /// The fake card rejects key reads, proving this step cannot run a private
    /// or profile-specific operation before the authenticated parser is chosen.
    #[test]
    fn dispatch_recognizes_only_closed_formats_without_key_operations() -> Result<()> {
        struct Card {
            objects: BTreeMap<u32, Vec<u8>>,
        }
        impl crate::restore::Card for Card {
            fn serial(&mut self) -> Result<u32> {
                Ok(123456)
            }
            fn public_key(&mut self, _: u8) -> Result<Option<Vec<u8>>> {
                bail!("Unexpected key access during dispatch")
            }
            fn object(&mut self, tag: u32) -> Result<Option<Vec<u8>>> {
                Ok(self.objects.get(&tag).cloned())
            }
        }
        for (magic, expected) in [
            (b"PQMCP001", Some(false)),
            (b"PQMCP002", Some(false)),
            (b"PQMCP003", Some(true)),
            (b"PQMCP999", None),
        ] {
            let raw = [
                8u32.to_be_bytes().as_slice(),
                magic,
                0u32.to_be_bytes().as_slice(),
            ]
            .concat();
            let stored = compressed(&raw);
            let manifest = [
                b"PQCIDX01".as_slice(),
                &(stored.len() as u32).to_be_bytes(),
                Sha256::digest(&stored).as_slice(),
            ]
            .concat();
            let chunk = [b"PQCCHK01".as_slice(), &0u32.to_be_bytes(), &stored].concat();
            let mut card = Card {
                objects: BTreeMap::from([(0x5f5200, manifest), (0x5f5201, chunk)]),
            };
            let result = is_level3_card(&mut card);
            match expected {
                Some(value) => assert_eq!(result?, value),
                None => assert!(result.is_err()),
            }
            // Even a recognized discriminator cannot pass the real reader.
            assert!(read_card(&mut card).is_err());
        }
        Ok(())
    }
    fn compressed(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(data).unwrap();
        [
            b"PQMCZ001".as_slice(),
            &(data.len() as u32).to_be_bytes(),
            &z.finish().unwrap(),
        ]
        .concat()
    }
    #[test]
    fn compression_is_single_bounded_stream() -> Result<()> {
        let data = b"PQMCP003 synthetic framing";
        let valid = compressed(data);
        assert_eq!(expand(&valid)?, data);
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(expand(&trailing).is_err());
        let mut truncated = valid.clone();
        truncated.pop();
        assert!(expand(&truncated).is_err());
        assert!(expand(&compressed(&valid)).is_err());
        let mut wrong = valid.clone();
        wrong[11] += 1;
        assert!(expand(&wrong).is_err());
        assert!(expand(&compressed(&vec![0; MAX + 1])).is_err());
        Ok(())
    }
}
