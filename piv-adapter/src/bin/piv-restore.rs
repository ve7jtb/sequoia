//! PIN-free, read-only restore. Explicit serial and executable paths prevent
//! choosing an arbitrary attached key or trusting commands from bundle data.
use anyhow::{ensure, Context, Result};
use sequoia_pqmail_piv::restore::{restore, ObjectReader};
use std::{env, path::PathBuf};
fn main() -> Result<()> {
    let args:Vec<_>=env::args_os().collect();
    ensure!(args.len()==4,"Usage: piv-restore ABSOLUTE_OBJECT_HELPER SERIAL NEW_OUTPUT_DIRECTORY");
    let serial=args[2].to_str().context("Invalid serial")?.parse()?;
    let out=PathBuf::from(&args[3]);
    ensure!(!out.exists(),"Restore destination already exists; choose a new directory");
    let mut card=ObjectReader::connect(&PathBuf::from(&args[1]),serial)?;
    let restored=restore(&mut card,serial)?;
    // Release PC/SC before another application starts using PKCS#11.
    drop(card);
    restored.save(&out)?;
    println!("{}",serde_json::to_string_pretty(&restored.review())?);
    println!("Restored public certificates to {}. No trust granted; no token writes or PIN operations.",out.display());
    Ok(())
}
