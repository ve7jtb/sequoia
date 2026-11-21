//! PIN-free restore of the Level 3 reverse-polyfill public envelope. The
//! authenticated ciphertext and public certificates are the only persisted data.
use anyhow::{ensure, Result};
use sequoia_pqmail_piv::{
    level3_companion::{read_card, Envelope},
    restore::ObjectReader,
};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

/// Publish a complete restore only after every public check succeeds. No file
/// overwrites are allowed, and failure removes only files created by this call.
fn save(
    out: &Path,
    encoded: &[u8],
    keys: &std::collections::BTreeMap<String, Vec<u8>>,
    envelope: &Envelope,
) -> Result<()> {
    fs::create_dir(out)?;
    let mut created = Vec::new();
    let result = (|| -> Result<()> {
        let mut write = |name: &str, data: &[u8]| -> Result<()> {
            let path = out.join(name);
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
            created.push(path);
            file.write_all(data)?;
            file.sync_all()?;
            Ok(())
        };
        write("companion.pqcomp", encoded)?;
        for (slot, key) in keys {
            write(&format!("{slot}.der"), key)?;
        }
        write("public.pgp", envelope.certificate_bytes())?;
        write("signing.cer", &envelope.anchors()[0])?;
        write("encryption.cer", &envelope.anchors()[1])?;
        write(
            "restore.json",
            &serde_json::to_vec_pretty(&serde_json::json!({
                "serial":envelope.serial,"profile":"LEVEL3_POLYFILL","signatureVerified":true,
                "liveKeysMatched":true,"trusted":false,"privateMaterialSaved":false,
                "slots":{"certification":"82","signing":"9c","decryption":"9d","wrap":"83"}
            }))?,
        )?;
        Ok(())
    })();
    if result.is_err() {
        for path in created {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir(out);
    }
    result
}
fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().collect();
    ensure!(
        args.len() == 4,
        "Usage: piv-level3-companion-restore OBJECT_HELPER SERIAL NEW_DIRECTORY"
    );
    let serial = args[2]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid serial"))?
        .parse::<u32>()?;
    let out = PathBuf::from(&args[3]);
    ensure!(!out.exists(), "Choose a new restore directory");
    let mut card = ObjectReader::connect(&PathBuf::from(&args[1]), serial)?;
    let (encoded, keys, envelope) = read_card(&mut card)?;
    drop(card); // Release PC/SC before a later private PKCS#11 operation.
    save(&out, &encoded, &keys, &envelope)?;
    println!("PASS Sequoia Level 3 companion restore: authenticated envelope, certificate signatures and live 82/9c/9d/83 keys verified. Public/ciphertext only; trust unchanged.");
    Ok(())
}
