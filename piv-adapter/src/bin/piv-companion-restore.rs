//! Read-only card restore. First-host ultra reconstruction requests one local
//! PIN, verifies every generated certificate signature, and persists only public
//! certificates and the encrypted companion. No card object/key/policy is written.
use anyhow::{ensure, Result};
use sequoia_pqmail_piv::{
    companion::{read_card_for_restore, Envelope, RestoreState},
    level3_companion,
    process::{Config, Pkcs11Operation},
    restore::ObjectReader,
};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Configuration is explicit trusted host state, never taken from the card.
fn configuration(serial: u32) -> Result<Config> {
    let path = |name| -> Result<PathBuf> { Ok(PathBuf::from(env::var(name)?)) };
    let config = Config {
        python: path("PQMAIL_PYTHON")?,
        adapters: path("PQMAIL_ADAPTERS")?,
        openssl: path("OPENSSL_BIN")?,
        provider: path("PKCS11_PROVIDER")?,
        module: path("PKCS11_MODULE")?,
        serial: serial.to_string(),
    };
    config.validate()?;
    Ok(config)
}

/// All files produced by this command are public data or authenticated ciphertext.
/// Create-new and a last-written result marker prevent overwriting identities or
/// presenting a partial restore as complete. A failure removes only our new files.
fn save(
    out: &Path,
    encoded: &[u8],
    keys: &std::collections::BTreeMap<String, Vec<u8>>,
    serial: u32,
    certificate: &[u8],
    profile: &str,
    anchors: Option<&[Vec<u8>; 2]>,
    reconstructed: bool,
) -> Result<()> {
    fs::create_dir(out)?;
    let mut created = Vec::new();
    let result = (|| -> Result<()> {
        let mut write = |name: &str, bytes: &[u8]| -> Result<()> {
            let path = out.join(name);
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
            created.push(path);
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        };
        write("companion.pqcomp", encoded)?;
        for (slot, key) in keys {
            write(&format!("{slot}.der"), key)?;
        }
        write("public.pgp", certificate)?;
        if let Some(anchors) = anchors {
            write("signing.cer", &anchors[0])?;
            write("encryption.cer", &anchors[1])?;
        }
        write(
            "restore.json",
            &serde_json::to_vec_pretty(&serde_json::json!({
                "serial":serial,"profile":profile,
                "signatureVerified":true,"liveKeysMatched":true,
                "certificateReconstructed":reconstructed,"trusted":false
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
    ensure!(args.len()==4||args.len()==6,"Usage: piv-companion-restore OBJECT_HELPER SERIAL NEW_DIRECTORY [--cache PUBLIC_CERTIFICATE]");
    let serial = args[2]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid serial"))?
        .parse::<u32>()?;
    let out = PathBuf::from(&args[3]);
    ensure!(!out.exists(), "Choose a new restore directory");
    let cache = if args.len() == 6 {
        ensure!(args[4] == "--cache", "Expected --cache PUBLIC_CERTIFICATE");
        let path = PathBuf::from(&args[5]);
        ensure!(
            fs::metadata(&path)?.len() <= 65536,
            "Oversized public certificate cache"
        );
        Some(fs::read(path)?)
    } else {
        None
    };
    let mut card = ObjectReader::connect(&PathBuf::from(&args[1]), serial)?;
    // The discriminator is only a routing hint. The selected parser rereads
    // and authenticates the complete envelope, every live slot and the serial.
    // No profile probing causes a PIN prompt or substitutes a fallback key.
    if level3_companion::is_level3_card(&mut card)? {
        ensure!(
            cache.is_none(),
            "Level 3 full companion does not use a reconstruction cache"
        );
        let (encoded, keys, envelope) = level3_companion::read_card(&mut card)?;
        drop(card);
        save(
            &out,
            &encoded,
            &keys,
            envelope.serial,
            envelope.certificate_bytes(),
            "LEVEL3_POLYFILL",
            Some(envelope.anchors()),
            false,
        )?;
        println!("PASS Sequoia Level 3 companion restore: authenticated envelope, certificates and live 82/9c/9d/83 keys verified. Public/ciphertext only; trust unchanged.");
        return Ok(());
    }
    let (encoded, keys, state) = read_card_for_restore(&mut card)?;
    // PC/SC must release its card/session before the PKCS#11 child connects.
    drop(card);
    let (envelope, reconstructed) = match state {
        RestoreState::Ready(envelope) => (envelope, false),
        RestoreState::Pending(pending) => {
            if let Some(cache) = cache {
                (
                    Envelope::parse_with_cache(&encoded, serial, &keys, &cache)?,
                    false,
                )
            } else {
                let config = configuration(serial)?;
                eprintln!("First-host public certificate reconstruction on YubiKey {serial}: P-384 unwrap in 82, certification in 86, and signing cross-certification in 9c. Touch when required. No key/policy writes, no automatic retry.");
                // Match the existing integration-test convention. The synthetic
                // PIN is public fixture data and is restricted to serial 123456;
                // production restores always use the hidden local prompt.
                let pin = Zeroizing::new(
                    if env::var("PQMAIL_SYNTHETIC_COMPANION").as_deref() == Ok("1") {
                        ensure!(
                            serial == 123456,
                            "Synthetic restore requires fixture serial"
                        );
                        "123456".to_string()
                    } else {
                        rpassword::prompt_password("YubiKey PIN (not saved): ")?
                    },
                );
                let mut backend =
                    Pkcs11Operation::new(config.clone(), Zeroizing::new(pin.as_bytes().to_vec()))?;
                let (envelope, _public) = pending.reconstruct(&mut backend, &config.openssl)?;
                (envelope, true)
            }
        }
    };
    save(
        &out,
        &encoded,
        &keys,
        envelope.serial,
        envelope.certificate_bytes(),
        "LEVEL5_COMPANION",
        None,
        reconstructed,
    )?;
    println!("PASS Sequoia companion restore: authenticated envelope, certificate signatures and live 86/9c/9d/82 keys verified. Only public certificate/ciphertext saved; trust unchanged.");
    Ok(())
}
