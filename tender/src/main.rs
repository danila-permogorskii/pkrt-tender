mod elf;

use std::fs;
use clap::{Arg, Command};
use anyhow::{Context, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    let matches = Command::new("pkrt-tender")
        .version("0.1.0")
        .about("Polykernel runtime tender")
        .arg(
            Arg::new("kernel")
                .help("Path to the unikernel library")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf))
        )
        .get_matches();

    let kernel_path = matches.get_one::<PathBuf>("kernel").unwrap();

    println!("Poly kernel tender v0.1.0");
    println!("Loading kernel: {}", kernel_path.display());

    let metadata = fs::metadata(kernel_path)
        .with_context(|| format!("Cannot access file: {}", kernel_path.display()))?;

    println!("File size: {} bytes", metadata.len());
    
    // Parse ELF binary
    match elf::parse_elf(kernel_path) { 
        Ok(elf_info) => {
            println!("Valid ELF binary");
            println!("  Architecture: {}", elf_info.architecture);
            println!("  Entry point: 0x{:x}", elf_info.entry_point);
            println!("  64-bit: {}", elf_info.is_64bit);
            println!("  Loadable segments: {}", elf_info.segments.len());

            for (i, segment) in elf_info.segments.iter().enumerate()  {
                println!("  Segment {}: vaddr=0x{:x}, size=0x{:x}, flags=0x{:x}",
                i, segment.virtual_addr, segment.size, segment.flags);
            }
        }
        Err(e) => {
            println!("Elf parsing filed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}