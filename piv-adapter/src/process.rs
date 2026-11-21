//! Bridge to PQ Mail's existing, single-process PKCS#11 component helpers.
//!
//! The Python adapters retain responsibility for live public-key comparison,
//! serial/slot selection, native PIN callbacks, and touch handling. Each
//! component uses one native process/session; a composite uses two components.
//! This crate does not introduce a long-lived token session or PIN cache.

use crate::{Backend, Operation};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Paths are trusted application configuration, never taken from an incoming
/// message or a certificate. The explicit serial prevents first-device wins.
#[derive(Clone)]
pub struct Config {
    pub python: PathBuf,
    pub adapters: PathBuf,
    pub openssl: PathBuf,
    pub provider: PathBuf,
    pub module: PathBuf,
    pub serial: String,
}

impl Config {
    /// Checks public configuration only. This does not connect or log in.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.serial.is_empty() && self.serial.bytes().all(|c| c.is_ascii_digit()),
            "An explicit numeric YubiKey serial is required"
        );
        for p in [&self.python, &self.openssl, &self.provider, &self.module] {
            ensure!(
                p.is_absolute() && p.is_file(),
                "Missing absolute backend file: {}",
                p.display()
            );
        }
        ensure!(
            self.adapters.is_absolute(),
            "Adapter directory must be absolute"
        );
        // ykman-mu.py supplies protocol definitions only. No ykman command or
        // transport fallback is invoked by these PKCS#11 adapters.
        for name in ["pkcs11-mu.py", "pkcs11-kem.py", "ykman-mu.py"] {
            ensure!(
                self.adapters.join(name).is_file(),
                "Missing adapter: {name}"
            );
        }
        Ok(())
    }
}

/// One user-authorized composite signature or decryption. The PIN is passed
/// only through anonymous stdin pipes, never argv, environment, or files.
/// `finish` and `Drop` clear our owned PIN buffer; clearing cannot promise
/// removal of every copy made inside the OS or existing Python runtime.
pub struct Pkcs11Operation {
    config: Config,
    pin: Option<Zeroizing<Vec<u8>>>,
    // Explicit trusted construction selects the reverse-polyfill routing.
    // It is never inferred from untrusted environment or certificate strings.
    level3_polyfill: bool,
}

impl Pkcs11Operation {
    /// Takes ownership of the PIN immediately, including on validation errors.
    /// A caller should also wipe any original input buffer it retained.
    pub fn new(config: Config, pin: Zeroizing<Vec<u8>>) -> Result<Self> {
        config.validate()?;
        ensure!(
            (6..=8).contains(&pin.len()) && pin.iter().all(|c| (32..=126).contains(c)),
            "Use a 6–8 character ASCII PIV PIN"
        );
        Ok(Self {
            config,
            pin: Some(pin),
            level3_polyfill: false,
        })
    }

    /// A Level 3 polyfill uses Ed25519 in 9c, X25519 in 9d and the
    /// dedicated P-384 wrapping key in 83. Software PQ operations never reach
    /// these subprocesses; the closed operation set below enforces that.
    pub fn new_level3_polyfill(config: Config, pin: Zeroizing<Vec<u8>>) -> Result<Self> {
        let mut operation = Self::new(config, pin)?;
        operation.level3_polyfill = true;
        Ok(operation)
    }

    /// Useful to callers/tests without exposing any credential bytes.
    pub fn is_finished(&self) -> bool {
        self.pin.is_none()
    }
}

/// Read at most limit+1 bytes so a broken adapter cannot allocate unbounded
/// memory. The reader closes its pipe when the cap is reached; the parent
/// will reject overflow and terminate a child that fails to finish in time.
fn bounded_read(reader: impl Read, limit: usize) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    reader.take((limit + 1) as u64).read_to_end(&mut out)?;
    Ok(out)
}

/// Preserve only OS startup/temp variables required by bundled runtimes.
/// In particular, inherited PKCS#11 slot overrides, Python import overrides,
/// and OpenSSL provider settings cannot redirect this Level 3 operation.
fn command(python: &Path, script: &Path) -> Command {
    let mut c = Command::new(python);
    c.arg("-I").arg("-B").arg(script).env_clear();
    for name in ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR"] {
        if let Some(v) = std::env::var_os(name) {
            c.env(name, v);
        }
    }
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

impl Pkcs11Operation {
    /// The boolean is private and selected only by the two closed Backend
    /// entry points below. No certificate-provided slot or environment override
    /// can redirect a certification operation or an ordinary message signature.
    fn execute_at(
        &mut self,
        op: Operation,
        spki: &[u8],
        input: &[u8],
        certification: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let result = (|| {
            ensure!(
                !matches!(op, Operation::Ed448 | Operation::X448),
                "Software component requires companion backend"
            );
            let pin = self
                .pin
                .as_ref()
                .context("This operation has ended; request a new PIN")?;
            let script = self.config.adapters.join(if op.is_signature() {
                "pkcs11-mu.py"
            } else {
                "pkcs11-kem.py"
            });
            let mut cmd = command(&self.config.python, &script);
            cmd.env("OPENSSL_BIN", &self.config.openssl)
                .env("PKCS11_PROVIDER", &self.config.provider)
                .env("PKCS11_MODULE", &self.config.module)
                .env("PKCS11_SERIAL", &self.config.serial)
                .env("HYBRID_MAIL_PIN_STDIN", "1")
                .env("PKCS11_TRADITIONAL_SLOT", "84")
                .env("PKCS11_KEM_SLOT", "9d")
                .env(
                    "PKCS11_ECDH_SLOT",
                    if op == Operation::P384 { "82" } else { "85" },
                );
            if self.level3_polyfill {
                ensure!(
                    !certification
                        && matches!(op, Operation::Ed25519 | Operation::X25519 | Operation::P384),
                    "Operation outside Level 3 polyfill hardware profile"
                );
                cmd.env("PQMAIL_LEVEL3_POLYFILL", "1")
                    .env("PKCS11_TRADITIONAL_SLOT", "9c")
                    .env(
                        "PKCS11_ECDH_SLOT",
                        if op == Operation::P384 { "83" } else { "9d" },
                    );
            }
            if certification {
                ensure!(
                    op == Operation::MlDsa87 && input.len() == 64,
                    "Expected certification external μ"
                );
                cmd.env("PQMAIL_CERTIFICATION_SLOTS", "86,87");
            }
            let mut child = cmd.spawn().context("Cannot start PKCS#11 adapter")?;

            // Drain both output pipes concurrently to avoid a stderr-full
            // deadlock while waiting for a touch or a large ML-DSA signature.
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let out_thread = thread::spawn(move || bounded_read(stdout, 8192));
            let err_thread = thread::spawn(move || bounded_read(stderr, 8192));

            // Only these first three fields are public. Write the PIN directly
            // from its protected buffer instead of formatting a second copy.
            let write_result = (|| -> std::io::Result<()> {
                let mut stdin = child.stdin.take().unwrap();
                writeln!(
                    stdin,
                    "{}\n{}\n{}",
                    op.algorithm(),
                    STANDARD.encode(spki),
                    STANDARD.encode(input)
                )?;
                stdin.write_all(pin)?;
                stdin.write_all(b"\n")?;
                Ok(()) // Dropping stdin signals a complete request/EOF.
            })();

            // Existing adapters impose 100-second native timeouts. Give that
            // cleanup time to finish, then kill/reap a stuck wrapper. Never
            // retry a private operation: PIN failures must not consume retries.
            let start = Instant::now();
            let mut timeout = false;
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if write_result.is_err() || start.elapsed() > Duration::from_secs(120) {
                    timeout = true;
                    let _ = child.kill();
                    break child.wait()?;
                }
                thread::sleep(Duration::from_millis(20));
            };
            let out = out_thread
                .join()
                .map_err(|_| anyhow::anyhow!("Adapter stdout reader failed"))??;
            let err = err_thread
                .join()
                .map_err(|_| anyhow::anyhow!("Adapter stderr reader failed"))??;
            ensure!(
                !timeout,
                "PKCS#11 adapter timed out or rejected input; no retry"
            );
            write_result.context("Could not supply adapter request")?;
            ensure!(
                out.len() <= 8192 && err.len() <= 8192,
                "Adapter output exceeded protocol limit"
            );
            // Don't relay arbitrary stderr: providers sometimes include input
            // data in diagnostics. The failure identifies the component only.
            ensure!(
                status.success(),
                "PKCS#11 {} failed (exit {:?}); no retry",
                op.algorithm(),
                status.code()
            );
            let response = if op.is_signature() {
                // Signatures use one base64 line; KEM shared secrets are raw
                // bytes and MUST NOT be base64-decoded or whitespace-trimmed.
                ensure!(
                    out.ends_with(b"\n") && !out[..out.len() - 1].contains(&b'\n'),
                    "Malformed signature response"
                );
                Zeroizing::new(
                    STANDARD
                        .decode(&out[..out.len() - 1])
                        .context("Invalid signature encoding")?,
                )
            } else {
                out
            };
            ensure!(
                response.len() == op.output_size(),
                "Incorrect {} response size",
                op.algorithm()
            );
            Ok(response)
        })();
        // Failure clears authorization immediately; successful first-component
        // calls retain it only until Signer/Decryptor::finish after component 2.
        if result.is_err() {
            self.finish();
        }
        result
    }
}

impl Backend for Pkcs11Operation {
    fn execute(&mut self, op: Operation, spki: &[u8], input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.execute_at(op, spki, input, false)
    }
    fn certify(&mut self, spki: &[u8], mu: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.execute_at(Operation::MlDsa87, spki, mu, true)
    }
    fn finish(&mut self) {
        self.pin.take();
    }
}
