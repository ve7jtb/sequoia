//! Read-only facade over PQ Mail's native PC/SC object transport. PKCS#11 is
//! still used for private operations; custom PIV objects need the object API.
use super::Card;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{io::{BufRead, BufReader, Read, Write}, path::Path, process::{Child, ChildStdin, Command, Stdio}, sync::mpsc, thread, time::Duration};

/// Only serial, public-key and object-read requests are exposed. The executable
/// path is application configuration; no path or command is accepted from a bundle.
pub struct ObjectReader {
    child: Child,
    input: ChildStdin,
    lines: mpsc::Receiver<Result<String, String>>,
}
impl ObjectReader {
    pub fn connect(helper: &Path, serial: u32) -> Result<Self> {
        ensure!(serial > 0 && serial <= i32::MAX as u32, "Invalid serial");
        ensure!(helper.is_absolute() && helper.is_file(), "Supply an absolute native object-helper path");
        let mut cmd = Command::new(helper);
        cmd.args(["objects", &serial.to_string()]).env_clear();
        for name in ["PATH", "SystemRoot", "WINDIR", "TMPDIR", "TMP", "TEMP"] {
            if let Some(value) = std::env::var_os(name) { cmd.env(name, value); }
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                let r = reader.by_ref().take(16385).read_line(&mut line);
                let value = match r {
                    Ok(0) => break,
                    Ok(_) if line.len() <= 16384 && line.ends_with('\n') => Ok(line),
                    _ => Err("Invalid or oversized object-helper response".to_owned()),
                };
                let bad = value.is_err();
                if tx.send(value).is_err() || bad { break; }
            }
        });
        let mut card = Self { child, input, lines };
        ensure!(card.serial()? == serial, "Wrong YubiKey serial");
        Ok(card)
    }
    fn call(&mut self, request: Value) -> Result<Value> {
        // Requests are small fixed-schema public data; no PIN/management secret
        // is requested or passed to this subprocess, even on error recovery.
        writeln!(self.input, "{request}")?;
        self.input.flush()?;
        let line = self.lines.recv_timeout(Duration::from_secs(45)).context("PIV public read timed out or helper exited")?
            .map_err(anyhow::Error::msg)?;
        let value: Value = serde_json::from_str(&line)?;
        ensure!(value.get("error").is_none(), "PIV public read failed; no import performed");
        value.get("value").cloned().context("Missing object-helper result")
    }
    fn bytes(&mut self, request: Value) -> Result<Option<Vec<u8>>> {
        let value = self.call(request)?;
        if value.is_null() { return Ok(None); }
        let bytes = STANDARD.decode(value.as_str().context("Invalid public-data response")?)?;
        ensure!(bytes.len() <= 8192, "Oversized public-data response");
        Ok(Some(bytes))
    }
}
impl Card for ObjectReader {
    fn serial(&mut self) -> Result<u32> {
        self.call(json!({"op":"serial"}))?.as_u64().context("Invalid device serial")?.try_into().map_err(Into::into)
    }
    fn public_key(&mut self, slot: u8) -> Result<Option<Vec<u8>>> {
        self.bytes(json!({"op":"key","slot":format!("{slot:02x}")}))
    }
    fn object(&mut self, tag: u32) -> Result<Option<Vec<u8>>> {
        ensure!((0x5f5000..=0x5f5020).contains(&tag) || (0x5f5100..=0x5f5120).contains(&tag) || (0x5f5200..=0x5f5220).contains(&tag), "Object outside bundle namespace");
        self.bytes(json!({"op":"get","tag":tag}))
    }
}
impl Drop for ObjectReader {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}
