// Copyright (c) 2021 The Linux Foundation. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 and
// only version 2 as published by the Free Software Foundation.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use memmap2::Mmap;

const SIGNATURE: &[u8; 8] = b"Raw_Dmp!";

// Header layout: <8sIIQ8sIQQI> = 56 bytes
// offset  0: sig            [u8; 8]
// offset  8: version        u32
// offset 12: valid          u32
// offset 16: data           u64
// offset 24: context        [u8; 8]
// offset 32: reset_trigger  u32
// offset 36: dump_size      u64
// offset 44: total_size     u64
// offset 52: sections_count u32
const HEADER_SIZE: usize = 56;

// Section header layout: <IIIQQQQ20s> = 64 bytes
// offset  0: s_valid        u32
// offset  4: s_version      u32
// offset  8: section_type   u32
// offset 12: section_offset u64
// offset 20: section_size   u64
// offset 28: paddr          u64
// offset 36: info           u64
// offset 44: name           [u8; 20]
const SECTION_HEADER_SIZE: usize = 64;

#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub paddr: u64,
    pub section_type: u32,
    pub valid: u32,
    pub version: u32,
}

/// Parsed rawdump backed by a memory-mapped file.
pub struct RawDump {
    mmap: Mmap,
    pub sections: Vec<Section>,
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    let bytes: [u8; 4] = buf[off..off + 4]
        .try_into()
        .expect("read_u32: slice length verified by caller");
    u32::from_le_bytes(bytes)
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    let bytes: [u8; 8] = buf[off..off + 8]
        .try_into()
        .expect("read_u64: slice length verified by caller");
    u64::from_le_bytes(bytes)
}

impl RawDump {
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("cannot open file: {}", path.display()))?;

        // SAFETY: the file is opened read-only and we don't modify it
        let mmap = unsafe { Mmap::map(&file) }.context("cannot mmap file")?;

        if mmap.len() < HEADER_SIZE {
            bail!("file too small for rawdump header");
        }

        if &mmap[0..8] != SIGNATURE {
            bail!("rawdump signature is not Raw_Dmp!");
        }

        let valid = read_u32(&mmap, 12);
        if valid != 1 {
            if valid == 2 {
                eprintln!("Ramdump not complete: no space was left on device during the dump operation.");
                eprintln!("This usually happens when a full dump is set to be written to a rawdump partition.");
                eprintln!("Please check if the value of /sys/kernel/dload/dload_mode is set to 'mini'.");
            } else {
                eprintln!("Valid tag not set!");
            }
            bail!("invalid rawdump (valid={})", valid);
        }

        let sections_count = read_u32(&mmap, 52) as usize;
        let expected_len = HEADER_SIZE + sections_count * SECTION_HEADER_SIZE;
        if mmap.len() < expected_len {
            bail!(
                "file truncated: need {} bytes for {} section headers, got {}",
                expected_len,
                sections_count,
                mmap.len()
            );
        }

        let mut sections = Vec::with_capacity(sections_count);
        for i in 0..sections_count {
            let base = HEADER_SIZE + i * SECTION_HEADER_SIZE;
            let sec_buf = &mmap[base..base + SECTION_HEADER_SIZE];

            let name = String::from_utf8_lossy(&sec_buf[44..64])
                .trim_end_matches('\0')
                .to_string();

            sections.push(Section {
                name,
                offset: read_u64(sec_buf, 12),
                size: read_u64(sec_buf, 20),
                paddr: read_u64(sec_buf, 28),
                section_type: read_u32(sec_buf, 8),
                valid: read_u32(sec_buf, 0),
                version: read_u32(sec_buf, 4),
            });
        }

        Ok(Self { mmap, sections })
    }

    /// Find a section by exact name, or by fuzzy match if exactly one section matches.
    ///
    /// Fuzzy matching: case-insensitive, ignores separators (`_`, `.`, `-`).
    /// Examples: "FSM_STS" or "FSMSTS" both match "md_FSM_STS.BIN"
    pub fn find_section(&self, name: &str) -> Option<&Section> {
        // Exact match first
        if let Some(sec) = self.sections.iter().find(|s| s.name == name) {
            return Some(sec);
        }
        // Fuzzy: strip separators, uppercase, then substring match
        let needle = normalize(name);
        let mut matches = self
            .sections
            .iter()
            .filter(|s| normalize(&s.name).contains(&needle));
        let first = matches.next()?;
        if matches.next().is_some() {
            return None; // ambiguous
        }
        Some(first)
    }

    /// Get a byte slice for the given section from the mmap.
    fn section_data(&self, sec: &Section) -> Result<&[u8]> {
        let start = sec.offset as usize;
        let end = start + sec.size as usize;
        if end > self.mmap.len() {
            bail!(
                "section {} extends beyond file (offset=0x{:x}, size=0x{:x}, file_len=0x{:x})",
                sec.name,
                sec.offset,
                sec.size,
                self.mmap.len()
            );
        }
        Ok(&self.mmap[start..end])
    }

    /// Print a section's text content to stdout (null bytes stripped).
    pub fn print_section(&self, alias: &str) -> Result<()> {
        let target = resolve_section_name(alias);
        let sec = self
            .find_section(target)
            .with_context(|| format!("section {} not found in rawdump", target))?;

        let data = self.section_data(sec)?;

        // Write non-null byte chunks to avoid per-byte write calls
        let stdout = io::stdout();
        let mut out = stdout.lock();
        let mut start = 0;
        while start < data.len() {
            // Skip null bytes
            if data[start] == 0 {
                start += 1;
                continue;
            }
            // Find the end of non-null run
            let end = data[start..]
                .iter()
                .position(|&b| b == 0)
                .map_or(data.len(), |pos| start + pos);
            out.write_all(&data[start..end])?;
            start = end;
        }
        // Ensure trailing newline
        if data.last().is_some_and(|&b| b != b'\n') {
            out.write_all(b"\n")?;
        }
        Ok(())
    }

    /// List all sections in a formatted table.
    pub fn list_sections(&self) {
        println!(
            "{:<20} {:>12} {:>18} {:>10} {:>5} {:>5} {:>7}",
            "NAME", "OFFSET", "PADDR", "SIZE", "TYPE", "VALID", "VERSION"
        );
        println!("{}", "-".repeat(85));
        for sec in &self.sections {
            println!(
                "{:<20} 0x{:010x} 0x{:016x} {:>10} {:>5} {:>5} {:>7}",
                sec.name,
                sec.offset,
                sec.paddr,
                fmt_size(sec.size),
                sec.section_type,
                sec.valid,
                sec.version
            );
        }
        println!("{}", "-".repeat(85));
        println!("Total: {} sections", self.sections.len());
    }

    /// Split rawdump into separate files under `out_folder`.
    pub fn split(&self, out_folder: &Path) -> Result<()> {
        println!("Split rawdump to {} ...", out_folder.display());

        for sec in &self.sections {
            println!(
                "Writing {:<20} @0x{:x} len:0x{:x} ...",
                sec.name, sec.offset, sec.size
            );
            let data = self.section_data(sec)?;
            let out_path = out_folder.join(&sec.name);
            std::fs::write(&out_path, data)
                .with_context(|| format!("cannot create file: {}", out_path.display()))?;
        }

        println!("Done, {} files extracted.", self.sections.len());
        Ok(())
    }

    /// Generate dump_info file at the given path.
    pub fn gen_dumpinfo(&self, out_file: &Path) -> Result<()> {
        // Try to parse base addresses from load.cmm section
        let mut base_overrides: BTreeMap<String, u64> = BTreeMap::new();
        if let Some(cmm_sec) = self.find_section("load.cmm") {
            let data = self.section_data(cmm_sec)?;
            let cmm_text = String::from_utf8_lossy(data);

            for line in cmm_text.lines() {
                let trimmed = line.trim();
                let rest = trimmed
                    .strip_prefix("d.load.binary")
                    .or_else(|| trimmed.strip_prefix("D.LOAD.BINARY"));
                if let Some(rest) = rest {
                    let mut parts = rest.split_whitespace();
                    if let (Some(fname), Some(addr)) = (parts.next(), parts.next()) {
                        let hex = addr
                            .trim_start_matches("0x")
                            .trim_start_matches("0X");
                        if let Ok(base) = u64::from_str_radix(hex, 16) {
                            if self.find_section(fname).is_some() {
                                base_overrides.insert(fname.to_string(), base);
                            }
                        }
                    }
                }
            }
        }

        let mut out = File::create(out_file)
            .with_context(|| format!("cannot create file: {}", out_file.display()))?;

        for sec in &self.sections {
            let base = base_overrides.get(&sec.name).copied().unwrap_or(sec.paddr);
            write!(
                out,
                "1 0x{:016x}\t{:016}\t{:<20}\t{}\r\n",
                base, sec.size, sec.name, sec.name
            )?;
        }

        println!("dump_info generated: {}", out_file.display());
        Ok(())
    }
}

fn resolve_section_name(alias: &str) -> &str {
    match alias {
        "dmesg" => "md_KDMESG.BIN",
        "console" => "md_KCONSOLE.BIN",
        "pmsg" => "md_KPMSG.BIN",
        "logbuf" => "md_KLOGBUF.BIN",
        "bootlog" => "md_KBOOT_LOG.BIN",
        other => other,
    }
}

/// Strip separators and uppercase for fuzzy comparison.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '_' && *c != '.' && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

fn fmt_size(size: u64) -> String {
    if size >= 0x100000 {
        format!("{:.1}M", size as f64 / 1_048_576.0)
    } else if size >= 0x400 {
        format!("{:.1}K", size as f64 / 1024.0)
    } else {
        format!("{}B", size)
    }
}
