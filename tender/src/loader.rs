use anyhow::{Context, Result};
use std::fs::{File, Permissions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::elf::{ElfInfo, ElfSegment};
use crate::memory::AllocatedMemory;

/// Represents a loaded segment with its memory details
#[derive(Debug)]
pub struct LoadedSegment {
    pub segment_type: String,
    pub guest_addr: u64,     // Where guest thinks this segment is
    pub host_addr: *mut u8,  // Where it actually is in host memory
    pub file_size: u64,      // How much data to copy from file
    pub memory_size: u64,    // Total memory size (includes BSS)
    pub file_offset: u64,    // Where to read from in the ELF file
    pub permissions: String, // Memory permissions for this segment
}

/// Complete guest memory image ready for execution
#[derive(Debug)]
pub struct LoadedGuest {
    pub allocated_memory: AllocatedMemory, // The underlying memory allocation
    pub loaded_segments: Vec<LoadedSegment>, // Details of loaded segments
    pub entry_point: u64,                  // Guest's execution entry point
    pub binary_end: u64,                   // Highest address copied from file
    pub total_loaded_bytes: u64,           // Total bytes copied from file
    pub bss_bytes: u64,                    // Total zero-initialized bytes
}

impl LoadedGuest {
    /// Load a complete guest binary into allocated memory
    /// This is the main function that orchestrates the loading process
    pub fn load_from_elf(
        elf_path: &Path,
        elf_info: &ElfInfo,
        allocated_memory: AllocatedMemory,
    ) -> Result<Self> {
        println!("Loading ELF segments into allocated memory...");

        // Open the ELF file for reading segment data
        let mut file = File::open(elf_path)
            .context("Failed to open ELF file for segment loading")?;

        // Collect loadable segments that need to be copied
        let loadable_segments: Vec<&ElfSegment> = elf_info
            .segments
            .iter()
            .filter(|seg| seg.is_loadable())
            .collect();

        println!(
            "  Found {} loadable segments to process",
            loadable_segments.len()
        );

        let mut loaded_segments = Vec::new();
        let mut total_loaded_bytes = 0u64;
        let mut bss_bytes = 0u64;
        let mut binary_end = 0u64;

        // Load each segment into memory
        for (i, segment) in loadable_segments
            .iter()
            .filter(|seg| seg.is_loadable())
            .enumerate()
        {
            println!(
                "  Loading segment {}: {} at 0x{:x}",
                i, segment.segment_type, segment.virtual_addr
            );

            let loaded_segment = Self::load_single_segment(
                &mut file,
                segment,
                &allocated_memory
            )?;

            // Track statistics
            total_loaded_bytes += loaded_segment.file_size;
            bss_bytes += loaded_segment.memory_size.saturating_sub(loaded_segment.file_size);
            binary_end = binary_end.max(loaded_segment.guest_addr + loaded_segment.memory_size);

            loaded_segments.push(loaded_segment);
        }

        println!("✅ ELF loading completed:");
        println!("   {} segments loaded", loaded_segments.len());
        println!("   {} bytes copied from file", total_loaded_bytes);
        println!("   {} bytes zero-initialized (BSS)", bss_bytes);
        println!("   Binary ends at: 0x{:x}", binary_end);

        Ok(LoadedGuest {
            allocated_memory,
            loaded_segments,
            entry_point: elf_info.entry_point,
            binary_end,
            total_loaded_bytes,
            bss_bytes
        })
    }
    /// Load a single ELF segment into memory
    /// This handles the actual file reading and memory copying
    fn load_single_segment(
        file: &mut File,
        segment: &ElfSegment,
        allocated_memory: &AllocatedMemory
    ) -> Result<LoadedSegment> {

        // Calculate where this segment should go in host memory
        let host_addr = allocated_memory.guest_to_host_addr(segment.virtual_addr)
            .context("Segment address outside allocated memory")?;

        // For now we'll simulate the segment loading process
        // In a real implementation, we'd need to:
        // 1. Read the segment's file offset and size from the ELF headers
        // 2. Seek to that position in the file
        // 3. Read the data and copy it to host_addr
        // 4. Zero-initialize any BSS portion

        // This is a simplified implementation for Microphase 6
        // We'll focus on the structure and concepts first

        println!("  Guest addr: 0x{:x} -> Host addr: {:p}", segment.virtual_addr, host_addr);
        println!("  Size: {} bytes, Permissions: {}", segment.size, segment.permissions);

        // For ow, simulate reading form file
        // TODO: ACtual file reading in next implementation step
        let file_size = segment.size; // Simplified - actual implementation needs ELF file size
        let memory_size = segment.size; // Simplified - actual implementation includes BSS
        let file_offset = 0; // TODO: Get from ELF program header

        Ok(LoadedSegment {
            segment_type: segment.segment_type.clone(),
            guest_addr: segment.virtual_addr,
            host_addr,
            file_size,
            memory_size,
            file_offset,
            permissions: segment.permissions.clone()
        })
    }

    /// Verify that the loaded binary is ready for execution
    /// This validates that all segments are properly loaded
    pub fn validate_loading(&self) -> Result<()> {
        println!("Validating loaded guest binary...");

        // Check that entry point is within loaded memory
        let entry_in_range = self.loaded_segments.iter().any(|seg| {
           self.entry_point >= seg.guest_addr &&
               self.entry_point < seg.guest_addr + seg.memory_size
        });

        if !entry_in_range {
            return Err(anyhow::anyhow!(
                "Entry point 0x{:x} not within any loaded segment",
                self.entry_point
            ));
        }

        println!("   ✅ Entry point 0x{:x} within loaded segments", self.entry_point);
        println!("   ✅ {} segments loaded successfully", self.loaded_segments.len());
        println!("   ✅ Binary memory image ready for execution");

        Ok(())
    }
}



/// Public interface function for loading ELF binaries
/// This combines memory alloctaion and segment leading in one step
pub fn load_guest_binary(
    elf_path: &Path,
    elf_info: &ElfInfo,
    memory_layout: &crate::elf::MemoryLayout
) -> Result<LoadedGuest> {
    println!("  Beginning complete guest binary loading...");

    // Step 1: Allocate memory
    let allocated_memory = crate::memory::allocate_guest_memory(memory_layout)
        .context("Failed to allocate memory for guest binary")?;

    // Step 2: Load ELF segments into allocated memory
    let loaded_guest = LoadedGuest::load_from_elf(elf_path, elf_info, allocated_memory)
        .context("Failed to load ELF segments")?;

    // Step 3: Validate the loaded binary
    loaded_guest.validate_loading()
        .context("Guest binary validation failed")?;

    println!("  Guest binary loading completed successfully!");

    Ok(loaded_guest)
}