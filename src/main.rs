mod cli;
mod minidump;

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;

use cli::{Cli, Command};
use minidump::RawDump;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let dump = RawDump::open(&cli.rawdump)?;

    match cli.command {
        Command::Dmesg => dump.print_section("dmesg")?,
        Command::Console => dump.print_section("console")?,
        Command::Pmsg => dump.print_section("pmsg")?,
        Command::Logbuf => dump.print_section("logbuf")?,
        Command::Bootlog => dump.print_section("bootlog")?,
        Command::Print { ref name } => dump.print_section(name)?,
        Command::List => dump.list_sections(),
        Command::Split { ref out_dir } => {
            ensure_dir(out_dir)?;
            dump.split(out_dir)?;
        }
        Command::GenInfo { ref out_file } => {
            if let Some(parent) = out_file.parent() {
                ensure_dir(parent)?;
            }
            dump.gen_dumpinfo(out_file)?;
        }
    }

    Ok(())
}

fn ensure_dir(path: &Path) -> Result<()> {
    if !path.is_dir() {
        fs::create_dir_all(path)
            .with_context(|| format!("cannot create directory: {}", path.display()))?;
    }
    Ok(())
}
