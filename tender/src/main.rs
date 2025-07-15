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
            println!("  Detected language: {}", elf_info.detected_language);
            println!("  Architecture: {}", elf_info.architecture);
            println!("  Entry point: 0x{:x}", elf_info.entry_point);
            println!("  64-bit: {}", elf_info.is_64bit);
            println!("  Total segments: {}", elf_info.segments.len());

            for (i, segment) in elf_info.segments.iter().enumerate()  {
                println!("  Segment {}: types={} vaddr=0x{:x}, size=0x{:x}, flags=0x{:x}, permissions={}",
                i, segment.segment_type, segment.virtual_addr, segment.size, segment.flags, segment.permissions);
            }

            let loadable_segments: Vec<_> = elf_info.segments.iter().filter(|s| s.is_loadable()).collect();
            let dynamic_segments: Vec<_> = elf_info.segments.iter().filter(|s| s.requires_dynamic_linking() ).collect();
            let security_segments: Vec<_> = elf_info.segments.iter().filter(|s| s.is_security_related()).collect();

            println!("  Loadable: {} | Dynamic linking: {} | Security: {}",
                loadable_segments.len(), dynamic_segments.len(), security_segments.len());

            println!("\n  Loadable segments (tender must handle):");
            for (i, segment) in loadable_segments.iter().enumerate() {
                println!("    [{}] vaddr=0x{:x}, size=0x{:x}, perms={}",
                    i, segment.virtual_addr, segment.size, segment.permissions);
            }

            if !dynamic_segments.is_empty() {
                println!("\n Dynamic linking segments (unikernels shouldn't have these):");
                for segment in &dynamic_segments {
                    println!("    {} at vaddr=0x{:x}", segment.segment_type, segment.virtual_addr);
                }
            }

            let (base_addr, memory_span, loadable_count) = elf::analyze_memory_layout(&elf_info.segments);

            println!("\n Memory layout analysis:");
            println!("  Base address: 0x{:x}", base_addr);
            println!("  Memory span: 0x{:x} bytes ({:.1} KB)", memory_span, memory_span as f64 / 1024.0);
            println!("  Segments to map: {}", loadable_count);
            println!("  Layout strategy: {}",
                if base_addr == 0 { "Starts at zero (needs special handling)" }
                else { "Normal base address" });
        }
        Err(e) => {
            println!("Elf parsing filed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}