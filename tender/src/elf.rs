use std::fmt::format;
use anyhow::{Result, Context, bail};
use goblin::elf::Elf;
use std::fs;
use std::path::Path;

pub struct ElfSegment {
    pub segment_type: String,
    pub virtual_addr: u64,
    pub size: u64,
    pub flags: u32,
    pub permissions: String
}

impl ElfSegment {
    // Helper function to determine if this segment is relevant for unikernel loading
    pub fn is_loadable(&self) -> bool {
        self.segment_type == "LOAD"
    }

    pub fn is_metadata(&self) -> bool {
        matches!(self.segment_type.as_str(), "NOTE" | "PHDR")
    }

    pub fn is_security_related(&self) -> bool {
        matches!(self.segment_type.as_str(), "GNU_STACK" | "GNU_RELO" | "GNU_EH_FRAME")
    }

    pub fn requires_dynamic_linking(&self) -> bool {
        matches!(self.segment_type.as_str(), "INTERP" | "DYNAMIC")
    }
}

pub struct ElfInfo {
    pub entry_point: u64,
    pub architecture: String,
    pub is_64bit: bool,
    pub segments: Vec<ElfSegment>,
    pub detected_language: String
}

pub fn parse_elf<P: AsRef<Path>>(path: P) -> Result<ElfInfo> {
    let path = path.as_ref();

    // Read the entire file
    let file_data = fs::read(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    // Parse with goblin
    let elf = Elf::parse(&file_data)
        .with_context(|| "Failed to parse as ELF binary")?;

    // Validate it's what we expect
    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        bail!("Only x86_64 binaries are supported (found: {})", elf.header.e_machine);
    }

    // Extract loadable segments
    let segments: Vec<ElfSegment> = elf.program_headers.iter()
        .map(|ph| {

            let segment_type = match ph.p_type{
                goblin::elf::program_header::PT_NULL => "NULL",
                goblin::elf::program_header::PT_LOAD => "LOAD",
                goblin::elf::program_header::PT_DYNAMIC => "DYNAMIC",
                goblin::elf::program_header::PT_INTERP => "INTERP",
                goblin::elf::program_header::PT_NOTE => "NOTE",
                goblin::elf::program_header::PT_SHLIB => "SHLIB",
                goblin::elf::program_header::PT_PHDR => "PHDR",
                goblin::elf::program_header::PT_TLS => "TLS",
                goblin::elf::program_header::PT_GNU_EH_FRAME => "GNU_EH_FRAME",
                goblin::elf::program_header::PT_GNU_STACK => "GNU_STACK",
                goblin::elf::program_header::PT_GNU_RELRO => "GNU_RELRO",
                _ => "UNKNOWN"
            }.to_string();

            // Calculate human-readable permissions
            let permissions = format!("{}{}{}",
                if ph.p_flags & goblin::elf::program_header::PF_R != 0 { "R" } else {"-"},
                if ph.p_flags & goblin::elf::program_header::PF_W != 0 { "W" } else {"-"},
                if ph.p_flags & goblin::elf::program_header::PF_X != 0 { "X" } else { "-" }
            );

            ElfSegment {
                segment_type,
                virtual_addr: ph.p_vaddr,
                size: ph.p_memsz,
                flags: ph.p_flags,
                permissions
            }
        })
        .collect();

    let detected_language = detect_language(&elf);

    Ok(ElfInfo {
        entry_point: elf.entry,
        architecture: "x86_64".to_string(),
        is_64bit: elf.is_64,
        segments,
        detected_language
    })
}

// Simple language detection based on symbol patterns
pub fn detect_language(elf: &Elf) -> String {
    let mut rust_indicators = 0;
    let mut c_indicators = 0;

    // Look at symbol table if it exists
    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            // Rust symbols often contain these patterns
            if name.contains("rust_") || (name.contains("_ZN") && name.contains("core")) {
                rust_indicators += 1;
            }

            // C symbols often have these patterns
            if name == "main" || name.contains("libc") || name.contains("__libc") {
                c_indicators += 1;
            }
        }
    }


    // Simple decision logic
    if rust_indicators > c_indicators && rust_indicators > 0 {
        format!("Rust (confidence: {} indicators)", rust_indicators)
    } else if c_indicators > 0 {
        format!("C (confidence: {} indicators)", c_indicators)
    } else {
        "Unknown (no clear indicators)".to_string()
    }
}

// Analyze memory layout requirements for planning
pub fn analyze_memory_layout(segments: &[ElfSegment]) -> (u64, u64, usize) {
    let loadable_segments: Vec<_> = segments.iter()
        .filter(|s| s.is_loadable())
        .collect();
    
    if loadable_segments.is_empty() { 
        return (0,0,0);
    }
    
    // Find the lows and highest addresses
    let min_addr = loadable_segments.iter()
        .map(|s| s.virtual_addr)
        .min()
        .unwrap_or(0);
    
    let max_addr = loadable_segments.iter()
        .map(|s| s.virtual_addr + s.size)
        .max()
        .unwrap_or(0);
    
    let total_span = max_addr - min_addr;
    let segment_count = loadable_segments.len();

    (min_addr, total_span, segment_count)
}