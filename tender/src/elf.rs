use std::fmt::format;
use anyhow::{Result, Context, bail};
use goblin::elf::Elf;
use std::fs;
use std::path::Path;

pub struct ElfSegment {
    pub virtual_addr: u64,
    pub size: u64,
    pub flags: u32
}

pub struct ElfInfo {
    pub entry_point: u64,
    pub architecture: String,
    pub is_64bit: bool,
    pub segments: Vec<ElfSegment>
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
        .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|ph| ElfSegment {
            virtual_addr: ph.p_vaddr,
            size: ph.p_memsz,
            flags: ph.p_flags
        })
        .collect();

    Ok(ElfInfo {
        entry_point: elf.entry,
        architecture: "x86_64".to_string(),
        is_64bit: elf.is_64,
        segments
    })
}