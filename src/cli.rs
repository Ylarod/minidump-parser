use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "minidump-parser", version = "2.0", about = "Qualcomm minidump parser tool")]
pub struct Cli {
    /// Path to rawdump file
    pub rawdump: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Print KDMESG (md_KDMESG.BIN)
    Dmesg,

    /// Print KCONSOLE (md_KCONSOLE.BIN)
    Console,

    /// Print KPMSG (md_KPMSG.BIN)
    Pmsg,

    /// Print KLOGBUF (md_KLOGBUF.BIN)
    Logbuf,

    /// Print KBOOT_LOG (md_KBOOT_LOG.BIN)
    Bootlog,

    /// Print specified section by name (use `list` to see all)
    Print {
        /// Section name
        name: String,
    },

    /// List all sections in rawdump
    List,

    /// Split rawdump to separate files
    Split {
        /// Output directory for extracted files
        #[arg(default_value = ".")]
        out_dir: PathBuf,
    },

    /// Generate dump_info.txt
    GenInfo {
        /// Output file path
        #[arg(default_value = "dump_info.txt")]
        out_file: PathBuf,
    },
}
