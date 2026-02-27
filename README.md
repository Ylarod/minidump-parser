# minidump-parser

A CLI tool for parsing Qualcomm minidump/rawdump (`Raw_Dmp!`) files.

## Features

- List all sections in a rawdump file
- Print section content (dmesg, console, pmsg, logbuf, bootlog, etc.)
- Fuzzy section name matching (e.g. `FSMSTS` matches `md_FSM_STS.BIN`)
- Split rawdump into separate section files
- Generate `dump_info.txt` for trace32
- Memory-mapped I/O for fast parsing

## Install

```sh
cargo install minidump-parser
```

## Usage

```sh
# List all sections
minidump-parser <rawdump> list

# Print kernel dmesg
minidump-parser <rawdump> dmesg

# Print a specific section (supports fuzzy matching)
minidump-parser <rawdump> print <section_name>

# Split rawdump into separate files
minidump-parser <rawdump> split [out_dir]

# Generate dump_info.txt
minidump-parser <rawdump> gen-info [out_file]
```

## License

Apache License 2.0
