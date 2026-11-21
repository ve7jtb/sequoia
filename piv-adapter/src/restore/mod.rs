//! Restore Level 3 public OpenPGP identities from PQ Mail's signed PIV bundle.
//!
//! No PIN, private key, management authentication, trust grant, or card write
//! is involved. A restored identity is usable only after its certificate
//! bindings, envelope signature, serial and live public components all match.
//! This reader deliberately supports the current Level 3 P-384 S/MIME wrapper
//! and separated RFC 9980 OpenPGP profile, not every PQ Mail profile.
mod der;
mod card;
pub use card::ObjectReader;
use crate::{public_spki, Operation, PublicKey};
use anyhow::{bail, ensure, Context, Result};
use flate2::{Decompress, FlushDecompress, Status};
use ossl::{OsslContext, pkey::{EvpPkey, EvpPkeyType, PkeyData, MlkeyData, EccData}, signature::{mldsa_params, OsslSignature, SigAlg, SigOp}};
use sequoia_openpgp as pgp;
use pgp::cert::amalgamation::key::PrimaryKey;
use pgp::{Cert, crypto::mpi, parse::Parse, policy::StandardPolicy, serialize::Serialize, types::{PublicKeyAlgorithm, Curve}};
use sha2::{Digest, Sha256, Sha512};
use std::{collections::{BTreeMap, BTreeSet}, fs, io::Write, path::Path};

const MAX: usize = 65536;
const BANKS: [u32; 2] = [0x5f5000, 0x5f5100];
/// A narrow transport trait also enables deterministic software-only tests.
/// None means an absent object/slot, never a transport or permission failure.
pub trait Card {
    fn serial(&mut self) -> Result<u32>;
    fn public_key(&mut self, slot: u8) -> Result<Option<Vec<u8>>>;
    fn object(&mut self, tag: u32) -> Result<Option<Vec<u8>>>;
}

/// Checked public data. Fields stay private so callers cannot manufacture a
/// "verified" restore or mutate its serial/mapping before writing it to disk.
pub struct Restored {
    serial: u32,
    generation: u64,
    bank: u32,
    stored: Vec<u8>,
    profiles: Vec<Profile>,
    cert: Cert,
    compatibility: Option<Cert>,
    keys: BTreeMap<u8, Vec<u8>>,
    signing: PublicKey,
    encryption: PublicKey,
    pub warnings: Vec<String>,
}
struct Profile { serial: u32, slots: [u8;4], sign: Vec<u8>, enc: Vec<u8>, pgp: Vec<u8>, compat: Vec<u8> }
impl Restored {
    pub fn serial(&self) -> u32 { self.serial }
    pub fn certificate(&self) -> &Cert { &self.cert }
    pub fn signing_key(&self) -> &PublicKey { &self.signing }
    pub fn encryption_key(&self) -> &PublicKey { &self.encryption }
    /// Public mapping for the existing PKCS#11 connector. The supported profile
    /// is checked to use these exact slots, so no silent remapping is possible.
    pub fn review(&self) -> serde_json::Value {
        serde_json::json!({"format":"sequoia-pqmail-piv-public","version":1,
            "serial":self.serial,"generation":self.generation,"bank":format!("{:06x}",self.bank),
            "fingerprint":self.cert.fingerprint().to_hex(),"compatibilityFingerprint":self.compatibility.as_ref().map(|c|c.fingerprint().to_hex()),
            "emails":emails(&self.cert).unwrap_or_default(),
            "slots":{"signing":["9c","84"],"decryption":["9d","85"],"certification":if self.keys.contains_key(&0x86){vec!["86","87"]}else{vec!["9c","84"]},"classical":if self.keys.contains_key(&0x88){vec!["88","89"]}else{vec![]},"smimeClassical":["83","82"]},
            "publicKeySha256":self.keys.iter().map(|(s,k)|(format!("{s:02x}"),hex(&Sha256::digest(k)))).collect::<BTreeMap<_,_>>(),
            "bundleSignatureVerified":true,"liveKeysMatched":true,"trusted":false,"warnings":self.warnings})
    }
    /// Create a new directory only; never overwrite an identity or trust store.
    /// A failed write removes only files created by this invocation. The final
    /// manifest is written last, so a crash cannot masquerade as a full import.
    pub fn save(&self, destination: &Path) -> Result<()> {
        fs::create_dir(destination).context("Choose a new restore directory")?;
        let mut created = Vec::new();
        let result = (|| -> Result<()> {
            let mut write = |name: &str, bytes: &[u8]| -> Result<()> {
                let path = destination.join(name);
                let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
                created.push(path);
                file.write_all(bytes)?; file.sync_all()?; Ok(())
            };
            write(if self.stored.starts_with(b"PQMZIP01"){"certificate-bundle.pqmzip"}else{"certificate-bundle.pqkey"}, &self.stored)?;
            let mut bytes=Vec::new(); self.cert.armored().serialize(&mut bytes)?; write("openpgp-v6.asc", &bytes)?;
            if let Some(compatibility)=&self.compatibility {
            bytes.clear(); compatibility.armored().serialize(&mut bytes)?; write("openpgp-v4-hybrid.asc", &bytes)?;
            // A classical-only view shares the v4 primary and certifications;
            // retain only its certified ECDH subkey, never synthesize a binding.
            let classical=compatibility.clone().retain_subkeys(|k| k.key().pk_algo()==PublicKeyAlgorithm::ECDH);
            bytes.clear(); classical.armored().serialize(&mut bytes)?; write("openpgp-v4-classical.asc", &bytes)?;
            }
            for (i,p) in self.profiles.iter().enumerate() {
                write(&format!("profile-{i}-signing.der"),&p.sign)?;
                write(&format!("profile-{i}-encryption.der"),&p.enc)?;
            }
            for (slot,key) in &self.keys { write(&format!("slot-{slot:02x}-public.der"),key)?; }
            write("identity.json", &serde_json::to_vec_pretty(&self.review())?)?;
            Ok(())
        })();
        if result.is_err() { for path in created { let _=fs::remove_file(path); } let _=fs::remove_dir(destination); }
        result
    }
}
fn hex(bytes:&[u8])->String { bytes.iter().map(|b|format!("{b:02x}")).collect() }

/// Length-prefixed fields are bounded before allocation or slicing.
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self,n:usize)->Result<&'a [u8]> { ensure!(n<=self.0.len(),"Truncated bundle field");let (a,b)=self.0.split_at(n);self.0=b;Ok(a) }
    fn magic(&mut self,m:&[u8])->Result<()> { ensure!(self.take(m.len())?==m,"Unsupported bundle format");Ok(()) }
    fn u32(&mut self)->Result<u32> { Ok(u32::from_be_bytes(self.take(4)?.try_into()?)) }
    fn u64(&mut self)->Result<u64> { Ok(u64::from_be_bytes(self.take(8)?.try_into()?)) }
    fn blob(&mut self)->Result<&'a [u8]> { let n=self.u32()? as usize;ensure!(n<=MAX,"Oversized bundle field");self.take(n) }
    fn end(self)->Result<()> { ensure!(self.0.is_empty(),"Trailing bundle bytes");Ok(()) }
}

/// The zlib boundary and declared size must both match exactly. The allocation
/// limit applies to decompressed data, not just the small compressed input.
fn unpack(stored:&[u8])->Result<Vec<u8>> {
    ensure!(stored.len()<=MAX,"Oversized stored bundle");
    if stored.starts_with(b"PQMAILS1") { return Ok(stored.to_vec()); }
    let mut r=Reader(stored);r.magic(b"PQMZIP01")?;
    let size=r.u32()? as usize;ensure!((1..=MAX).contains(&size),"Invalid expanded bundle size");
    let mut output=vec![0;size+1];let mut z=Decompress::new(true);
    let status=z.decompress(r.0,&mut output,FlushDecompress::Finish)?;
    ensure!(status==Status::StreamEnd && z.total_out()==size as u64 && z.total_in()==r.0.len() as u64,"Invalid compressed bundle boundary");
    output.truncate(size);Ok(output)
}

/// Invalid bank data permits recovery from the other committed bank. Transport
/// errors do not: a disconnected key must not be misreported as an empty bank.
fn read_bank(card:&mut impl Card,tag:u32)->Result<Option<(u64,Vec<u8>)>> {
    let Some(manifest)=card.object(tag)? else {return Ok(None)};
    let parsed=(||->Result<(u64,usize,Vec<u8>)>{
        let mut r=Reader(&manifest);r.magic(b"PQMIDX01")?;let generation=r.u64()?;let size=r.u32()? as usize;
        let hash=r.take(32)?.to_vec();r.end()?;
        ensure!(generation>0 && generation<=i64::MAX as u64 && (1..=MAX).contains(&size),"Invalid manifest");Ok((generation,size,hash))
    })();
    let Ok((generation,size,digest))=parsed else{return Ok(None)};
    let mut bytes=Vec::with_capacity(size);
    for i in 0..size.div_ceil(2048) {
        let Some(chunk)=card.object(tag+1+i as u32)? else{return Ok(None)};
        let parsed=(||->Result<&[u8]>{let mut r=Reader(&chunk);r.magic(b"PQMCHK01")?;ensure!(r.u64()?==generation&&r.u32()?==i as u32,"Stale chunk");ensure!(r.0.len()==2048.min(size-i*2048),"Truncated chunk");Ok(r.0)})();
        let Ok(data)=parsed else{return Ok(None)};bytes.extend(data);
    }
    if Sha256::digest(&bytes).as_slice()!=digest {return Ok(None)}
    Ok(Some((generation,bytes)))
}

fn add(keys:&mut BTreeMap<u8,Vec<u8>>,slot:u8,spki:Vec<u8>)->Result<()> {
    if let Some(old)=keys.insert(slot,spki.clone()){ensure!(old==spki,"Conflicting public keys in slot {slot:02x}");}Ok(())
}
fn x509_bindings(p:&Profile,keys:&mut BTreeMap<u8,Vec<u8>>)->Result<bool> {
    ensure!(p.slots==[0x9c,0x83,0x9d,0x82],"Unsupported Level 3 slot mapping; restore does not migrate keys");
    let sign=der::certificate_spki(&p.sign)?;let enc=der::certificate_spki(&p.enc)?;
    let (sa,s)=der::spki(&sign)?;let (ea,e)=der::spki(&enc)?;
    if sa==der::MLDSA65 && ea==der::MLKEM768 {
        add(keys,0x9c,public_spki(Operation::MlDsa65,s)?)?;add(keys,0x9d,public_spki(Operation::MlKem768,e)?)?;Ok(false)
    } else {
        ensure!(sa==der::COMPOSITE_SIGN && ea==der::COMPOSITE_KEM,"Unsupported bundle profile (requires Level 3 ML-DSA-65/P-384)");
        ensure!(s.len()==1952+97 && e.len()==1184+97,"Invalid composite public-key lengths");
        add(keys,0x9c,public_spki(Operation::MlDsa65,&s[..1952])?)?;add(keys,0x83,der::p384(&s[1952..])?)?;
        add(keys,0x9d,public_spki(Operation::MlKem768,&e[..1184])?)?;add(keys,0x82,der::p384(&e[1184..])?)?;Ok(true)
    }
}

/// Match PQ Mail's LAMPS composite representative, including its ML-DSA
/// context string. Both signature components must pass; checking only the
/// envelope hash or only the PQ component would not authenticate the bundle.
fn verify_envelope(payload:&[u8],signature:&[u8],profile:&Profile)->Result<()> {
    let spki=der::certificate_spki(&profile.sign)?;let (alg,raw)=der::spki(&spki)?;
    let hybrid=alg==der::COMPOSITE_SIGN;
    ensure!(hybrid||alg==der::MLDSA65,"Unsupported bundle signing algorithm");
    let ctx=OsslContext::new_lib_ctx_checked()?;
    let pq=if hybrid { &raw[..1952] } else {raw};
    let key=EvpPkey::import(&ctx,EvpPkeyType::Mldsa65,PkeyData::Mlkey(MlkeyData{pubkey:Some(pq.to_vec()),prikey:None,seed:None}))?;
    let domain=b"COMPSIG-MLDSA65-ECDSA-P384-SHA512".to_vec();
    let message=if hybrid {let mut m=b"CompositeAlgorithmSignatures2025".to_vec();m.extend(&domain);m.push(0);m.extend(Sha512::digest(payload));m} else {payload.to_vec()};
    ensure!(if hybrid {signature.len()>3309} else {signature.len()==3309},"Invalid bundle signature length");
    let params=mldsa_params(false,if hybrid {Some(&domain)}else{None},false)?;
    OsslSignature::new(&ctx,SigOp::Verify,SigAlg::Mldsa65,&key,params.as_ref())?.verify(&message,Some(&signature[..3309])).context("Bundle ML-DSA signature failed")?;
    if hybrid {
        let key=EvpPkey::import(&ctx,EvpPkeyType::P384,PkeyData::Ecc(EccData{pubkey:Some(raw[1952..].to_vec()),prikey:None}))?;
        OsslSignature::new(&ctx,SigOp::Verify,SigAlg::EcdsaSha2_384,&key,None)?.verify(&message,Some(&signature[3309..])).context("Bundle ECDSA signature failed")?;
    }Ok(())
}

fn emails(cert:&Cert)->Result<BTreeSet<String>> {
    let p=StandardPolicy::new();let valid=cert.with_policy(&p,None)?;
    let mut emails=BTreeSet::new();
    for uid in valid.userids() { if let Some(email)=uid.userid().email_normalized()? {emails.insert(email);} }
    ensure!(!emails.is_empty(),"Certificate has no certified email");Ok(emails)
}

/// Validate bindings under Sequoia's policy before considering any key usable.
/// Primary certification and classical keys are matched as well, so a bundle
/// cannot smuggle a different compatibility identity into the local restore.
fn pgp_bindings(cert:&Cert,compat:Option<&Cert>,keys:&mut BTreeMap<u8,Vec<u8>>)->Result<(PublicKey,PublicKey)> {
    ensure!(!cert.is_tsk()&&compat.is_none_or(|c|!c.is_tsk()),"Private key material is not allowed in a public bundle");
    ensure!(cert.primary_key().key().version()==6&&compat.is_none_or(|c|c.primary_key().key().version()==4),"Expected v6 identity and v4 compatibility certificate");
    let policy=StandardPolicy::new();
    let valid=cert.with_policy(&policy,None)?;valid.alive()?;ensure!(!matches!(valid.revocation_status(),pgp::types::RevocationStatus::Revoked(_)),"Revoked v6 certificate");
    ensure!(valid.primary_key().for_certification(),"Primary key cannot certify");
    let separated=!valid.primary_key().for_signing();
    let mut sign=None;let mut kem=None;let mut slots=BTreeSet::new();
    for key in cert.keys().with_policy(&policy,None).alive().revoked(false) {
        let k=key.key();ensure!(k.version()==6,"Mixed key versions");
        let components:Vec<(u8,Operation,&[u8])>=match k.mpis() {
            mpi::PublicKey::MLDSA65_Ed25519{mldsa,eddsa} if key.primary()&&separated=>vec![(0x86,Operation::MlDsa65,mldsa.as_slice()),(0x87,Operation::Ed25519,eddsa.as_slice())],
            mpi::PublicKey::MLDSA65_Ed25519{mldsa,eddsa} if key.for_signing()=>{ensure!(sign.is_none(),"Ambiguous signing subkey");sign=Some(k.clone());vec![(0x9c,Operation::MlDsa65,mldsa.as_slice()),(0x84,Operation::Ed25519,eddsa.as_slice())]},
            mpi::PublicKey::MLKEM768_X25519{mlkem,ecdh} if key.for_transport_encryption()=>{ensure!(kem.is_none(),"Ambiguous encryption subkey");kem=Some(k.clone());vec![(0x9d,Operation::MlKem768,mlkem.as_slice()),(0x85,Operation::X25519,ecdh.as_slice())]},
            mpi::PublicKey::Ed25519{a} if key.for_signing()=>vec![(0x88,Operation::Ed25519,a.as_slice())],
            mpi::PublicKey::X25519{u} if key.for_transport_encryption()=>vec![(0x89,Operation::X25519,u.as_slice())],
            _=>bail!("Unsupported or wrongly flagged v6 key"),
        };
        for (slot,op,raw) in components {ensure!(slots.insert(slot),"Duplicate OpenPGP role");add(keys,slot,public_spki(op,raw)?)?;}
    }
    ensure!(slots.len()==if separated{8}else{4} && cert.keys().count()==if separated{5}else{2},"Incomplete or invalid Level 3 certificate");
    if let Some(compat)=compat {
    ensure!(separated,"Legacy combined primary cannot carry separated compatibility keys");
    let cv=compat.with_policy(&policy,None)?;cv.alive()?;ensure!(!matches!(cv.revocation_status(),pgp::types::RevocationStatus::Revoked(_)),"Revoked v4 certificate");
    let mut count=0;
    for key in compat.keys().with_policy(&policy,None).alive().revoked(false) {
        ensure!(key.key().version()==4,"Mixed v4 key versions");
        match key.key().mpis() {
            mpi::PublicKey::EdDSA{curve,q} if key.primary() && key.for_signing() && *curve==Curve::Ed25519 => {
                ensure!(q.value().len()==33&&q.value()[0]==0x40,"Invalid legacy Ed25519 point");add(keys,0x88,public_spki(Operation::Ed25519,&q.value()[1..])?)?;
            },
            mpi::PublicKey::MLKEM768_X25519{mlkem,ecdh} if !key.primary()&&key.for_transport_encryption()=>{add(keys,0x9d,public_spki(Operation::MlKem768,mlkem.as_slice())?)?;add(keys,0x85,public_spki(Operation::X25519,ecdh.as_slice())?)?;},
            mpi::PublicKey::ECDH{curve,q,..} if !key.primary()&&key.for_transport_encryption()&&*curve==Curve::Cv25519=>{
                ensure!(q.value().len()==33&&q.value()[0]==0x40,"Invalid legacy X25519 point");add(keys,0x89,public_spki(Operation::X25519,&q.value()[1..])?)?;
            },
            _=>bail!("Unsupported v4 compatibility key"),
        }count+=1;
    }
    ensure!(count==3&&compat.keys().count()==3,"Incomplete v4 compatibility bindings");
    ensure!(emails(compat)?.is_subset(&emails(cert)?),"Compatibility email mismatch");
    }
    emails(cert)?;
    Ok((sign.context("Missing signing key")?,kem.context("Missing encryption key")?))
}

fn decode(stored:Vec<u8>,generation:u64,bank:u32)->Result<Restored> {
    let bytes=unpack(&stored)?;let mut r=Reader(&bytes);r.magic(b"PQMAILS1")?;
    let payload=r.blob()?;let signer=r.u32()? as usize;let signature=r.blob()?;r.end()?;
    let mut r=Reader(payload);let version=r.take(8)?;ensure!(version==b"PQMAILB1"||version==b"PQMAILB2","Unsupported bundle payload");let count=r.u32()? as usize;
    ensure!((2..=16).contains(&count)&&signer<count,"Invalid profile count or signer");
    let mut profiles=Vec::new();let mut keys=BTreeMap::new();let mut pure=false;let mut hybrid=false;
    for _ in 0..count {
        let p=Profile{serial:r.u32()?,slots:r.take(4)?.try_into()?,sign:r.blob()?.to_vec(),enc:r.blob()?.to_vec(),pgp:r.blob()?.to_vec(),compat:if version==b"PQMAILB2"{r.blob()?.to_vec()}else{Vec::new()}};
        if x509_bindings(&p,&mut keys)? {hybrid=true}else{pure=true};profiles.push(p);
    }r.end()?;
    ensure!(pure&&hybrid,"Missing pure or hybrid S/MIME profile");
    let serial=profiles[0].serial;ensure!(serial>0&&serial<=i32::MAX as u32&&profiles.iter().all(|p|p.serial==serial),"Conflicting bundle serials");
    verify_envelope(payload,signature,&profiles[signer])?;
    let pgps:Vec<_>=profiles.iter().filter(|p|!p.pgp.is_empty()).collect();ensure!(!pgps.is_empty(),"Bundle contains no OpenPGP identity");
    ensure!(pgps.iter().all(|p|p.pgp==pgps[0].pgp&&p.compat==pgps[0].compat),"Ambiguous OpenPGP profiles");
    ensure!(profiles.iter().all(|p|!p.pgp.is_empty()||p.compat.is_empty()),"Orphan compatibility certificate");
    let cert=Cert::from_bytes(&pgps[0].pgp)?;let compatibility=if pgps[0].compat.is_empty(){None}else{Some(Cert::from_bytes(&pgps[0].compat)?)};
    let (signing,encryption)=pgp_bindings(&cert,compatibility.as_ref(),&mut keys)?;
    Ok(Restored{serial,generation,bank,stored,profiles,cert,compatibility,keys,signing,encryption,warnings:Vec::new()})
}

/// Select the newest complete, authenticated supported bank. Transport errors
/// abort; corrupt banks generate a visible recovery warning. Live-key mismatch
/// aborts instead of silently falling back to an older identity.
pub fn restore(card:&mut impl Card,expected_serial:u32)->Result<Restored> {
    ensure!(expected_serial>0&&card.serial()?==expected_serial,"Wrong YubiKey serial");
    let mut valid=Vec::new();let mut warnings=Vec::new();
    for tag in BANKS {
        match read_bank(card,tag)? {
            Some((generation,bytes))=>match decode(bytes,generation,tag) {Ok(v)=>valid.push(v),Err(e)=>warnings.push(format!("Bank {tag:06x} rejected: {e}"))},
            None=>warnings.push(format!("Bank {tag:06x} is absent or incomplete")),
        }
    }
    valid.sort_by_key(|v|v.generation);
    if valid.len()==2&&valid[0].generation==valid[1].generation {ensure!(valid[0].stored==valid[1].stored,"Conflicting bank generations");}
    let mut result=valid.pop().with_context(||format!("No complete supported Level 3 bundle: {}",warnings.join("; ")))?;
    ensure!(result.serial==expected_serial,"Bundle belongs to another YubiKey");
    for (slot,expected) in &result.keys {
        ensure!(card.public_key(*slot)?.as_ref()==Some(expected),"Live public key mismatch in slot {slot:02x}; no import");
    }
    ensure!(card.serial()?==expected_serial,"Device changed during restore");
    if !result.stored.starts_with(b"PQMZIP01") {warnings.push("Restored legacy uncompressed storage; new backups should use PQMZIP01".into());}
    if result.compatibility.is_none() {warnings.push("This bundle has no v4 compatibility certificate; none was created or inferred".into());}
    if !result.keys.contains_key(&0x86) {warnings.push("This bundle uses the original combined certification/signing primary; newer local certificates are not present on the key".into());}
    result.warnings=warnings;Ok(result)
}
