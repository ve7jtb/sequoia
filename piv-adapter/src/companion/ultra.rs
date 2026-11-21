//! Narrow, independently validated certificate reconstruction templates.
//!
//! A template is NOT an OpenPGP certificate. Its own signature values, salts and
//! two-byte digest checks are zero. Before a private operation we validate every
//! packet, role, issuer and metadata field and derive the digest ourselves.
//! Unknown extensions, revocations and third-party certifications must stay in
//! the full-certificate format; none are silently removed by this reader.

use crate::{public_spki, Operation};
use anyhow::{bail, ensure, Context, Result};
use openssl::{pkey::PKey, sign::Verifier};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    time::{SystemTime, UNIX_EPOCH},
};

const LIMIT: usize = 65536;
const SIGNATURE: usize = 4741;

#[derive(Clone)]
struct Packet {
    tag: u8,
    body: Vec<u8>,
}

/// Keep all offsets into the original signature body. Rebuilding metadata with
/// a general-purpose signature builder could alter salts, subpacket ordering or
/// timestamps. Salt placeholders are deliberately filled from a CSPRNG for each
/// new signature; all other retained metadata remains exact.
struct SignatureLayout {
    header_end: usize,
    prefix: Range<usize>,
    salt: Range<usize>,
    value: Range<usize>,
    embedded: Option<Range<usize>>,
}

/// Public packet bodies are authoritative for fingerprints and role bindings.
/// No signature or digest supplied by a caller can select a different key/slot.
pub(super) struct Template {
    encoded: Vec<u8>,
    packets: Vec<Packet>,
    pub primary: Vec<u8>,
    pub signing: Vec<u8>,
    pub encryption: Vec<u8>,
    signing_index: usize,
    encryption_index: usize,
}

struct Read<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Read<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        ensure!(
            count <= self.bytes.len().saturating_sub(self.at),
            "Truncated ultra certificate"
        );
        let value = &self.bytes[self.at..self.at + count];
        self.at += count;
        Ok(value)
    }
    fn one(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn number(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?) as usize)
    }
    fn length(&mut self) -> Result<usize> {
        Ok(match self.one()? {
            a @ 0..=191 => a as usize,
            a @ 192..=223 => ((a as usize - 192) << 8) + self.one()? as usize + 192,
            255 => self.number()?,
            _ => bail!("Partial lengths are forbidden in ultra certificates"),
        })
    }
    fn end(&self) -> Result<()> {
        ensure!(
            self.at == self.bytes.len(),
            "Trailing ultra certificate bytes"
        );
        Ok(())
    }
}

fn packets(bytes: &[u8]) -> Result<Vec<Packet>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= LIMIT,
        "Invalid ultra certificate size"
    );
    let mut r = Read::new(bytes);
    let mut out = Vec::new();
    while r.at < bytes.len() {
        ensure!(out.len() < 16, "Too many ultra certificate packets");
        let tag = r.one()?;
        ensure!(tag & 0xc0 == 0xc0, "Expected new-format OpenPGP packets");
        let n = r.length()?;
        ensure!(n <= LIMIT, "Oversized certificate packet");
        out.push(Packet {
            tag: tag & 63,
            body: r.take(n)?.to_vec(),
        });
    }
    Ok(out)
}

/// Canonicalization changes packet framing only; all packet bodies are retained.
fn encode(packets: &[Packet]) -> Vec<u8> {
    let mut out = Vec::new();
    for packet in packets {
        out.extend([0xc0 | packet.tag, 255]);
        out.extend((packet.body.len() as u32).to_be_bytes());
        out.extend(&packet.body);
    }
    out
}

fn key_hash(body: &[u8]) -> Vec<u8> {
    let mut b = vec![0x9b];
    b.extend((body.len() as u32).to_be_bytes());
    b.extend(body);
    b
}
fn fingerprint(body: &[u8]) -> Vec<u8> {
    Sha256::digest(key_hash(body)).to_vec()
}
fn timestamp(body: &[u8]) -> u64 {
    u32::from_be_bytes(body[1..5].try_into().unwrap()) as u64
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// The only accepted public packet layouts have fixed-length RFC 9980 material.
/// OpenSSL additionally decodes the classical component before any key use.
fn key(body: &[u8], algorithm: u8, current: u64) -> Result<()> {
    let size = if algorithm == 31 {
        57 + 2592
    } else {
        56 + 1568
    };
    ensure!(
        body.len() == 10 + size && body[0] == 6 && body[5] == algorithm,
        "Unexpected ultra public-key profile"
    );
    ensure!(
        u32::from_be_bytes(body[6..10].try_into()?) as usize == size,
        "Invalid v6 public-key material length"
    );
    ensure!(
        timestamp(body) > 0 && timestamp(body) <= current + 300,
        "Invalid public-key creation time"
    );
    let (ed, ml) = components(body)?;
    PKey::public_key_from_der(&ed)?;
    PKey::public_key_from_der(&ml)?;
    Ok(())
}

/// Returns classical then PQ SPKI, in the same order as RFC 9980 wire material.
pub(super) fn components(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(body.len() >= 10, "Truncated component key");
    match body[5] {
        31 => {
            ensure!(body.len() == 2659, "Wrong signing material size");
            Ok((
                public_spki(Operation::Ed448, &body[10..67])?,
                public_spki(Operation::MlDsa87, &body[67..])?,
            ))
        }
        36 => {
            ensure!(body.len() == 1634, "Wrong encryption material size");
            Ok((
                public_spki(Operation::X448, &body[10..66])?,
                public_spki(Operation::MlKem1024, &body[66..])?,
            ))
        }
        _ => bail!("Unsupported ultra key algorithm"),
    }
}

fn email(uid: &[u8]) -> Result<String> {
    ensure!(
        !uid.is_empty() && uid.len() <= 1024,
        "Invalid User ID length"
    );
    let text = std::str::from_utf8(uid)?;
    ensure!(
        !text.chars().any(char::is_control),
        "Control character in User ID"
    );
    let address = if text.ends_with('>') {
        let start = text.rfind('<').context("Malformed User ID email")?;
        &text[start + 1..text.len() - 1]
    } else {
        text
    };
    ensure!(address.len() <= 254, "Email too long");
    let (local, domain) = address.split_once('@').context("Expected email User ID")?;
    ensure!(
        !local.is_empty()
            && local
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&b)),
        "Invalid email local part"
    );
    let (_, suffix) = domain.rsplit_once('.').context("Expected email domain")?;
    ensure!(
        suffix.len() >= 2
            && suffix.bytes().all(|b| b.is_ascii_alphabetic())
            && domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)),
        "Invalid email domain"
    );
    Ok(address.to_ascii_lowercase())
}

fn value32(value: &[u8]) -> Result<u64> {
    ensure!(value.len() == 4, "Expected four-byte time value");
    Ok(u32::from_be_bytes(value.try_into()?) as u64)
}

/// Validate one signature's semantics before deriving any digest. Authenticated
/// metadata alone is insufficient: these checks prevent reconstruction from
/// becoming an arbitrary-message signature oracle on slots 86 or 9c.
fn layout(
    body: &[u8],
    kind: u8,
    issuer: &[u8],
    subject: &[u8],
    current: u64,
    zero: bool,
    flags: Option<u8>,
    cross: bool,
) -> Result<SignatureLayout> {
    let mut r = Read::new(body);
    ensure!(
        r.take(4)? == [6, kind, 31, 10],
        "Unsupported reconstructed signature profile"
    );
    let n = r.number()?;
    ensure!(n <= 8192, "Signature metadata too large");
    let start = r.at;
    let hashed = r.take(n)?;
    let header_end = r.at;
    ensure!(
        r.number()? == 0,
        "Unhashed metadata is forbidden in ultra signatures"
    );
    let prefix = r.at..r.at + 2;
    r.take(2)?;
    ensure!(r.one()? == 32, "Expected SHA-512 v6 signature salt");
    let salt = r.at..r.at + 32;
    r.take(32)?;
    let value = r.at..r.at + SIGNATURE;
    r.take(SIGNATURE)?;
    r.end()?;
    if zero {
        ensure!(
            body[prefix.clone()]
                .iter()
                .chain(body[value.clone()].iter())
                .chain(body[salt.clone()].iter())
                .all(|b| *b == 0),
            "Template contains nonzero signature, salt or digest placeholders"
        );
    }
    let mut subs = BTreeMap::new();
    let mut sub = Read::new(hashed);
    let mut embedded = None;
    while sub.at < hashed.len() {
        let count = sub.length()?;
        ensure!(count > 0, "Empty signature subpacket");
        let tag = sub.one()?;
        let id = tag & 127;
        let at = start + sub.at;
        let data = sub.take(count - 1)?;
        let allowed = matches!(id, 2 | 3 | 33)
            || match kind {
                0x1f => matches!(id, 9 | 11 | 21 | 22 | 27 | 30 | 39),
                0x13 => matches!(id, 11 | 21 | 22 | 30 | 39),
                0x18 => matches!(id, 9 | 27) || (cross && id == 32),
                0x19 => false,
                _ => false,
            };
        ensure!(
            allowed && (id != 32 || tag & 128 == 0),
            "Unsupported/critical ultra signature subpacket"
        );
        ensure!(
            subs.insert(id, data).is_none(),
            "Duplicate signature subpacket"
        );
        if id == 32 {
            embedded = Some(at..at + data.len());
        }
    }
    let mut expected = vec![6];
    expected.extend(fingerprint(issuer));
    ensure!(
        subs.get(&33).copied() == Some(expected.as_slice()),
        "Wrong signature issuer fingerprint"
    );
    let created = value32(subs.get(&2).context("Missing signature creation time")?)?;
    ensure!(
        created >= timestamp(issuer) && created >= timestamp(subject) && created <= current + 300,
        "Invalid reconstructed signature creation time"
    );
    if let Some(expiry) = subs.get(&3) {
        let seconds = value32(expiry)?;
        ensure!(
            seconds == 0 || created + seconds >= current,
            "Expired signature"
        );
    }
    if let Some(expiry) = subs.get(&9) {
        let seconds = value32(expiry)?;
        ensure!(
            seconds == 0 || timestamp(subject) + seconds >= current,
            "Expired key"
        );
    }
    match flags {
        Some(flag) => ensure!(
            subs.get(&27).copied() == Some(&[flag][..]),
            "Unexpected certificate key flags"
        ),
        None => ensure!(!subs.contains_key(&27), "Unexpected key flags"),
    }
    ensure!(
        embedded.is_some() == cross,
        "Missing/unexpected signing cross-certification"
    );
    for (tag, allowed) in [
        (11, &[7, 8, 9][..]),
        (21, &[8, 9, 10, 12, 14][..]),
        (22, &[0, 1, 2][..]),
    ] {
        if let Some(value) = subs.get(&tag) {
            ensure!(
                !value.is_empty() && value.len() <= 32 && value.iter().all(|b| allowed.contains(b)),
                "Unsupported algorithm preference"
            );
        }
    }
    if let Some(value) = subs.get(&30) {
        ensure!(
            value.len() == 1 && value[0] & !15 == 0,
            "Unsupported feature flags"
        );
    }
    if let Some(value) = subs.get(&39) {
        ensure!(
            !value.is_empty()
                && value.len() <= 32
                && value.len() % 2 == 0
                && value
                    .chunks(2)
                    .all(|v| [7, 8, 9].contains(&v[0]) && [1, 2, 3].contains(&v[1])),
            "Unsupported AEAD preferences"
        );
    }
    Ok(SignatureLayout {
        header_end,
        prefix,
        salt,
        value,
        embedded,
    })
}

fn digest(body: &[u8], layout: &SignatureLayout, data: &[u8]) -> Vec<u8> {
    let mut hash = Sha512::new();
    hash.update(&body[layout.salt.clone()]);
    hash.update(data);
    hash.update(&body[..layout.header_end]);
    hash.update([6, 255]);
    hash.update((layout.header_end as u32).to_be_bytes());
    hash.finalize().to_vec()
}

/// Verify BOTH components and the digest check, including during cache import.
fn verify(body: &[u8], layout: &SignatureLayout, data: &[u8], issuer: &[u8]) -> Result<()> {
    let hashed = digest(body, layout, data);
    ensure!(
        body[layout.prefix.clone()] == hashed[..2],
        "Reconstructed signature digest check failed"
    );
    let (ed, ml) = components(issuer)?;
    let value = &body[layout.value.clone()];
    for (spki, sig) in [(&ed, value[..114].as_ref()), (&ml, value[114..].as_ref())] {
        let key = PKey::public_key_from_der(spki)?;
        let mut verifier = Verifier::new_without_digest(&key)?;
        ensure!(
            verifier.verify_oneshot(sig, &hashed)?,
            "Reconstructed composite signature rejected"
        );
    }
    Ok(())
}

impl Template {
    /// Parse the complete bounded shape before unwrapping or signing anything.
    pub(super) fn parse(encoded: &[u8]) -> Result<Self> {
        Self::parse_mode(encoded, true)
    }
    fn parse_mode(encoded: &[u8], zero: bool) -> Result<Self> {
        let packets = packets(encoded)?;
        let current = now()?;
        ensure!(
            packets.len() >= 8 && packets[0].tag == 6 && packets[1].tag == 2,
            "Expected primary and direct signature"
        );
        let primary = packets[0].body.clone();
        key(&primary, 31, current)?;
        let mut i = 2;
        let mut emails = BTreeSet::new();
        while i + 1 < packets.len() && packets[i].tag == 13 {
            ensure!(
                emails.len() < 5 && packets[i + 1].tag == 2,
                "Expected 1–5 certified User IDs"
            );
            ensure!(
                emails.insert(email(&packets[i].body)?),
                "Duplicate User ID email"
            );
            i += 2;
        }
        ensure!(
            !emails.is_empty()
                && i + 4 == packets.len()
                && [
                    packets[i].tag,
                    packets[i + 1].tag,
                    packets[i + 2].tag,
                    packets[i + 3].tag
                ] == [14, 2, 14, 2],
            "Unsupported certificate packet shape"
        );
        let signing = packets[i].body.clone();
        let encryption = packets[i + 2].body.clone();
        key(&signing, 31, current)?;
        key(&encryption, 36, current)?;
        ensure!(
            primary[10..67] != signing[10..67] && primary[67..] != signing[67..],
            "Certification and signing components must use distinct keys"
        );
        let canonical = encode(&packets);
        if zero {
            ensure!(canonical == encoded, "Noncanonical ultra packet framing");
        }
        let result = Self {
            encoded: canonical,
            packets,
            primary,
            signing,
            encryption,
            signing_index: i,
            encryption_index: i + 2,
        };
        result.check_signatures(zero, current)?;
        Ok(result)
    }
    fn data(&self, index: usize) -> Vec<u8> {
        let mut out = key_hash(&self.primary);
        if index >= self.signing_index {
            out.extend(key_hash(&self.packets[index - 1].body));
        } else if index > 1 {
            let uid = &self.packets[index - 1].body;
            out.push(0xb4);
            out.extend((uid.len() as u32).to_be_bytes());
            out.extend(uid);
        }
        out
    }
    fn signature_layout(
        &self,
        index: usize,
        body: &[u8],
        zero: bool,
        current: u64,
    ) -> Result<SignatureLayout> {
        let (kind, subject, flags, cross) = if index == 1 {
            (0x1f, self.primary.as_slice(), Some(1), false)
        } else if index == self.signing_index + 1 {
            (0x18, self.signing.as_slice(), Some(2), true)
        } else if index == self.encryption_index + 1 {
            (0x18, self.encryption.as_slice(), Some(12), false)
        } else {
            (0x13, self.primary.as_slice(), None, false)
        };
        layout(
            body,
            kind,
            &self.primary,
            subject,
            current,
            zero,
            flags,
            cross,
        )
    }
    fn check_signatures(&self, zero: bool, current: u64) -> Result<()> {
        for (i, packet) in self.packets.iter().enumerate().filter(|(_, p)| p.tag == 2) {
            let l = self.signature_layout(i, &packet.body, zero, current)?;
            let data = self.data(i);
            if let Some(range) = &l.embedded {
                let b = &packet.body[range.clone()];
                let nested = layout(
                    b,
                    0x19,
                    &self.signing,
                    &self.primary,
                    current,
                    zero,
                    None,
                    false,
                )?;
                if !zero {
                    verify(b, &nested, &data, &self.signing)?;
                }
            }
            if !zero {
                verify(&packet.body, &l, &data, &self.primary)?;
            }
        }
        Ok(())
    }
    /// Match a cached full certificate to the exact authenticated template.
    /// Canonical packet framing may differ. Fresh salts and signature values are
    /// normalized; retained metadata and exact public-key packet bytes may not.
    pub(super) fn verify_cache(&self, certificate: &[u8]) -> Result<()> {
        let full = Self::parse_mode(certificate, false)?;
        ensure!(
            full.normalized()? == self.encoded,
            "Cached certificate does not match authenticated reconstruction template"
        );
        Ok(())
    }
    fn normalized(&self) -> Result<Vec<u8>> {
        let mut packets = self.packets.clone();
        let current = now()?;
        for (i, p) in packets.iter_mut().enumerate().filter(|(_, p)| p.tag == 2) {
            let l = self.signature_layout(i, &p.body, false, current)?;
            if let Some(range) = l.embedded {
                let b = &mut p.body[range];
                let nested = layout(
                    b,
                    0x19,
                    &self.signing,
                    &self.primary,
                    current,
                    false,
                    None,
                    false,
                )?;
                b[nested.prefix].fill(0);
                b[nested.value].fill(0);
                b[nested.salt].fill(0);
            }
            p.body[l.prefix].fill(0);
            p.body[l.value].fill(0);
            p.body[l.salt].fill(0);
        }
        Ok(encode(&packets))
    }
    /// The callback receives only a digest derived from a validated certificate
    /// structure and a closed boolean role: certification (86) or cross-signing
    /// (9c). It cannot supply raw messages or choose slots. Each result is checked
    /// immediately before it can influence an enclosing binding's digest.
    pub(super) fn reconstruct(
        &self,
        mut sign: impl FnMut(bool, &[u8]) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        self.check_signatures(true, now()?)?;
        let mut packets = self.packets.clone();
        let current = now()?;
        for (i, packet) in packets.iter_mut().enumerate().filter(|(_, p)| p.tag == 2) {
            let l = self.signature_layout(i, &packet.body, true, current)?;
            let data = self.data(i);
            if let Some(range) = &l.embedded {
                let body = &mut packet.body[range.clone()];
                let nested = layout(
                    body,
                    0x19,
                    &self.signing,
                    &self.primary,
                    current,
                    true,
                    None,
                    false,
                )?;
                openssl::rand::rand_bytes(&mut body[nested.salt.clone()])?;
                let hashed = digest(body, &nested, &data);
                let signature = sign(false, &hashed)?;
                ensure!(
                    signature.len() == SIGNATURE,
                    "Invalid reconstructed cross-signature length"
                );
                body[nested.prefix.clone()].copy_from_slice(&hashed[..2]);
                body[nested.value.clone()].copy_from_slice(&signature);
                verify(body, &nested, &data, &self.signing)?;
            }
            // The embedded signature is now complete, so hash its actual bytes.
            openssl::rand::rand_bytes(&mut packet.body[l.salt.clone()])?;
            let hashed = digest(&packet.body, &l, &data);
            let signature = sign(true, &hashed)?;
            ensure!(
                signature.len() == SIGNATURE,
                "Invalid reconstructed certification signature length"
            );
            packet.body[l.prefix.clone()].copy_from_slice(&hashed[..2]);
            packet.body[l.value.clone()].copy_from_slice(&signature);
            verify(&packet.body, &l, &data, &self.primary)?;
        }
        let encoded = encode(&packets);
        self.verify_cache(&encoded)?;
        Ok(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        pkey::{KeyType, Private},
        sign::Signer,
    };
    use sequoia_openpgp::{parse::Parse, policy::StandardPolicy, Cert};

    /// Test keys are generated in RAM and never load a token provider or card. Each
    /// test owns distinct certification/signing components, as production does.
    struct Fixture {
        template: Vec<u8>,
        cert_ml: PKey<Private>,
        cert_ed: PKey<Private>,
        sign_ml: PKey<Private>,
        sign_ed: PKey<Private>,
    }
    fn sub(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![255];
        out.extend(((value.len() + 1) as u32).to_be_bytes());
        out.push(tag);
        out.extend(value);
        out
    }
    fn key_body(
        algorithm: u8,
        ml: &PKey<Private>,
        ed: &PKey<Private>,
        created: u32,
    ) -> Result<Vec<u8>> {
        let mut material = ed.raw_public_key()?;
        material.extend(ml.raw_public_key()?);
        let mut body = vec![6];
        body.extend(created.to_be_bytes());
        body.push(algorithm);
        body.extend((material.len() as u32).to_be_bytes());
        body.extend(material);
        Ok(body)
    }
    fn signature(kind: u8, issuer: &[u8], created: u32, extra: &[u8]) -> Vec<u8> {
        let mut issuer_fp = vec![6];
        issuer_fp.extend(fingerprint(issuer));
        let mut subs = sub(2, &created.to_be_bytes());
        subs.extend(sub(33, &issuer_fp));
        subs.extend(extra);
        let mut body = vec![6, kind, 31, 10];
        body.extend((subs.len() as u32).to_be_bytes());
        body.extend(subs);
        body.extend(0u32.to_be_bytes());
        body.extend([0, 0, 32]);
        body.extend([0; 32]);
        body.extend(vec![0; SIGNATURE]);
        body
    }
    impl Fixture {
        fn new() -> Result<Self> {
            let mut seed = [0; 32];
            openssl::rand::rand_bytes(&mut seed)?;
            let cert_ml = PKey::private_key_from_seed(None, KeyType::ML_DSA_87, None, &seed)?;
            openssl::rand::rand_bytes(&mut seed)?;
            let sign_ml = PKey::private_key_from_seed(None, KeyType::ML_DSA_87, None, &seed)?;
            let mut kem_seed = [0; 64];
            openssl::rand::rand_bytes(&mut kem_seed)?;
            let kem = PKey::private_key_from_seed(None, KeyType::ML_KEM_1024, None, &kem_seed)?;
            let cert_ed = PKey::generate_ed448()?;
            let sign_ed = PKey::generate_ed448()?;
            let x = PKey::generate_x448()?;
            let time = (now()? - 60) as u32;
            let primary = key_body(31, &cert_ml, &cert_ed, time)?;
            let signing = key_body(31, &sign_ml, &sign_ed, time)?;
            let encryption = key_body(36, &kem, &x, time)?;
            let cross = signature(0x19, &signing, time, &[]);
            let mut bind = sub(27, &[2]);
            bind.extend(sub(32, &cross));
            let packets = vec![
                Packet {
                    tag: 6,
                    body: primary.clone(),
                },
                Packet {
                    tag: 2,
                    body: signature(0x1f, &primary, time, &sub(27, &[1])),
                },
                Packet {
                    tag: 13,
                    body: b"fixture@example.test".to_vec(),
                },
                Packet {
                    tag: 2,
                    body: signature(0x13, &primary, time, &[]),
                },
                Packet {
                    tag: 14,
                    body: signing,
                },
                Packet {
                    tag: 2,
                    body: signature(0x18, &primary, time, &bind),
                },
                Packet {
                    tag: 14,
                    body: encryption,
                },
                Packet {
                    tag: 2,
                    body: signature(0x18, &primary, time, &sub(27, &[12])),
                },
            ];
            Ok(Self {
                template: encode(&packets),
                cert_ml,
                cert_ed,
                sign_ml,
                sign_ed,
            })
        }
        fn sign(&self, cert: bool, digest: &[u8]) -> Result<Vec<u8>> {
            let (ed, ml) = if cert {
                (&self.cert_ed, &self.cert_ml)
            } else {
                (&self.sign_ed, &self.sign_ml)
            };
            let mut s = Signer::new_without_digest(ed)?;
            let mut signature = s.sign_oneshot_to_vec(digest)?;
            let mut s = Signer::new_without_digest(ml)?;
            signature.extend(s.sign_oneshot_to_vec(digest)?);
            Ok(signature)
        }
    }

    #[test]
    fn reconstruction_uses_fresh_salts_preserves_fingerprints_and_verifies() -> Result<()> {
        let fixture = Fixture::new()?;
        let template = Template::parse(&fixture.template)?;
        let mut calls = Vec::new();
        let full = template.reconstruct(|role, digest| {
            calls.push(role);
            fixture.sign(role, digest)
        })?;
        ensure!(
            calls == [true, true, false, true, true],
            "Unexpected certificate signing role order"
        );
        let second = template.reconstruct(|role, digest| fixture.sign(role, digest))?;
        ensure!(
            full != second,
            "Reconstruction did not create fresh signatures"
        );
        template.verify_cache(&full)?;
        template.verify_cache(&second)?;
        let one = Template::parse_mode(&full, false)?;
        let two = Template::parse_mode(&second, false)?;
        for (a, b) in one
            .packets
            .iter()
            .zip(&two.packets)
            .filter(|(p, _)| p.tag == 2)
        {
            let i = one.packets.iter().position(|p| std::ptr::eq(p, a)).unwrap();
            let x = one.signature_layout(i, &a.body, false, now()?)?;
            let y = two.signature_layout(i, &b.body, false, now()?)?;
            ensure!(a.body[x.salt] != b.body[y.salt], "Reused signature salt");
        }
        ensure!(
            one.primary == template.primary
                && one.signing == template.signing
                && one.encryption == template.encryption,
            "Public-key packet changed"
        );
        let cert = Cert::from_bytes(&full)?;
        let policy = StandardPolicy::new();
        cert.with_policy(&policy, None)?.alive()?;
        ensure!(
            cert.fingerprint().as_bytes() == fingerprint(&template.primary),
            "Primary fingerprint changed"
        );
        Ok(())
    }

    #[test]
    fn malformed_templates_are_rejected_before_any_signature_callback() -> Result<()> {
        let fixture = Fixture::new()?;
        let parsed = Template::parse(&fixture.template)?;
        let mut variants = Vec::new();
        for index in [1, 3, 5, 7] {
            let l = parsed.signature_layout(index, &parsed.packets[index].body, true, now()?)?;
            for at in [l.prefix.start, l.salt.start, l.value.start] {
                let mut p = parsed.packets.clone();
                p[index].body[at] = 1;
                variants.push(encode(&p));
            }
        }
        let mut p = parsed.packets.clone();
        p[1].body[1] = 0;
        variants.push(encode(&p)); // Arbitrary-message signature request.
                                   // An authenticated template must still reject unknown metadata, even
                                   // when marked noncritical, and duplicates of understood fields.
        for extra in [
            sub(100, &[1]),
            sub(0x80 | 100, &[1]),
            sub(2, &1u32.to_be_bytes()),
            sub(3, &1u32.to_be_bytes()),
        ] {
            let mut p = parsed.packets.clone();
            let size = u32::from_be_bytes(p[1].body[4..8].try_into()?) as usize;
            p[1].body.splice(8 + size..8 + size, extra.iter().copied());
            p[1].body[4..8].copy_from_slice(&((size + extra.len()) as u32).to_be_bytes());
            variants.push(encode(&p));
        }
        let mut p = parsed.packets.clone();
        let direct = parsed.signature_layout(1, &p[1].body, true, now()?)?;
        p[1].body[direct.header_end - 1] = 2; // Certification key cannot become a message signer.
        variants.push(encode(&p));
        let mut p = parsed.packets.clone();
        p[1].body[25] ^= 1; // Foreign issuer fingerprint in the authenticated metadata.
        variants.push(encode(&p));
        let mut p = parsed.packets.clone();
        p[1].body[4..8].copy_from_slice(&8193u32.to_be_bytes());
        variants.push(encode(&p));
        let mut p = parsed.packets.clone();
        p[2].body = b"not-an-email".to_vec();
        variants.push(encode(&p));
        let mut p = parsed.packets.clone();
        p.push(Packet {
            tag: 21,
            body: vec![0],
        });
        variants.push(encode(&p));
        let mut p = parsed.packets.clone();
        p.push(Packet {
            tag: 10,
            body: b"PGP".to_vec(),
        });
        variants.push(encode(&p));
        let mut p = parsed.packets.clone();
        p[4].body[10..67].copy_from_slice(&parsed.primary[10..67]);
        variants.push(encode(&p));
        let mut partial = fixture.template.clone();
        partial[1] = 224;
        variants.push(partial);
        let mut old = fixture.template.clone();
        old[0] = 0x98;
        variants.push(old);
        for variant in variants {
            ensure!(
                Template::parse(&variant).is_err(),
                "Accepted malformed reconstruction request"
            );
        }
        // A bad device response must also stop, after exactly one request.
        let mut calls = 0;
        ensure!(
            parsed
                .reconstruct(|_, _| {
                    calls += 1;
                    Ok(vec![0; SIGNATURE])
                })
                .is_err(),
            "Accepted bad private-operation response"
        );
        ensure!(calls == 1, "Retried failed signature");
        Ok(())
    }

    #[test]
    fn cached_certificate_tampering_and_unknown_signatures_fail() -> Result<()> {
        let fixture = Fixture::new()?;
        let template = Template::parse(&fixture.template)?;
        let full = template.reconstruct(|role, digest| fixture.sign(role, digest))?;
        let mut p = packets(&full)?;
        p[2].body = b"attacker@example.test".to_vec();
        ensure!(
            template.verify_cache(&encode(&p)).is_err(),
            "Trusted modified User ID"
        );
        let mut p = packets(&full)?;
        let last = p[1].body.len() - 1;
        p[1].body[last] ^= 1;
        ensure!(
            template.verify_cache(&encode(&p)).is_err(),
            "Trusted damaged cached signature"
        );
        let mut p = packets(&full)?;
        p.push(p[1].clone());
        ensure!(
            template.verify_cache(&encode(&p)).is_err(),
            "Ignored extra certificate signature"
        );
        ensure!(
            template.verify_cache(&fixture.template).is_err(),
            "Used skeleton as full certificate"
        );
        Ok(())
    }
}
