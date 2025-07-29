use anyhow::{Result, Context};
use std::ptr;

use crate::elf::MemoryLayout;

// Constants based on Solo5-spt approach
const HOST_MEM_BASE: u64 = 0x10000; // 64KB - safe base address for mapping
const PAGE_SIZE: u64 = 4096; // Standard page size for alignment

/// Represents different memory protection levels
#[derive(Debug, Clone)]
pub enum Protection{
    Read, // PROT_READ
    ReadWrite, // PROT_READ | PROT_WRITE
    ReadExecute // PROT_READ | PROT_EXEC
}

impl Protection {
    /// Convert to libc protection flags for mmap/mprotect
    fn to_libc_prot(&self) -> i32 {
        match self {
            Protection::Read => libc::PROT_READ,
            Protection::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
            Protection::ReadExecute => libc::PROT_READ | libc::PROT_EXEC
        }
    }
}

/// Represents a single allocated memory region with specific permissions
#[derive(Debug)]
pub struct MemoryRegion {
    pub guest_addr: u64,
    pub host_addr: *mut u8,
    pub size: u64,
    pub permissions: Protection
}

/// Complete memory allocation for a guest binary
#[derive(Debug)]
pub struct AllocatedMemory {
    pub host_mapping: *mut u8,
    pub guest_base: u64,
    pub host_base: u64,
    pub total_size: u64,
    pub address_offset: i64,
    pub regions: Vec<MemoryRegion>
}

impl AllocatedMemory {
    /// Allocate memory according to a MemoryLayout plan
    /// This is our first implementation - handles the basic allocation without loading guest code
    pub fn allocate_from_layout(layout: &MemoryLayout) -> Result<Self> {
        // First, validate that we can actually allocate this layout
        if !layout.is_unikernel_compatible {
            return Err(anyhow::anyhow!(
                "Cannot allocate memory for incompatible binary: {:?}",
                layout.compatibility_issues
            ));
        }

        println!("  Planning memory allocation");
        println!("  Guest expects: 0x{:x} - 0x{:x} ({} bytes)",
                 layout.guest_base_addr,
                 layout.guest_end_addr,
                 layout.guest_memory_span);
        println!("  Strategy: {}", layout.mapping_strategy);

        // Determine where we'll actually allocate in host memory
        let (host_base, address_offset) = if layout.needs_address_translation {
            // Guest wants zero-page, map at safe address with translation
            let host_base = HOST_MEM_BASE;
            let offset = host_base as i64 - layout.guest_base_addr as i64;
            (host_base, offset)
        } else {
            // Guest address is safe, use direct mapping
            (layout.suggested_host_base, 0i64)
        };

        println!("  Host allocation: 0x{:x} ({} bytes)", host_base, layout.total_allocation_size);
        if address_offset != 0 {
            println!("  Address translation: guest+0x{:x} = host", address_offset);
        }

        // Perform the actual memory allocation using mmap
        let allocated_memory = Self::allocate_host_memory(host_base, layout.total_allocation_size)
            .context("Failed to allocate host memory")?;

        println!("  Memory allocated successfully at: {:p}", allocated_memory);

        // For now, create a single region covering the entire allocation
        // Later microphases will subdivide this into per-segment regions
        let regions = vec![MemoryRegion {
           guest_addr: layout.guest_base_addr,
            host_addr: allocated_memory,
            size: layout.total_allocation_size,
            permissions: Protection::ReadWrite // Start with RW, will refine later
        }];

        Ok(AllocatedMemory {
            host_mapping: allocated_memory,
            guest_base: layout.guest_base_addr,
            host_base,
            total_size: layout.total_allocation_size,
            address_offset,
            regions
        })
    }

    fn allocate_host_memory(base_addr: u64, size: u64) -> Result<*mut u8> {
        // Round size up to page boundary for efficient allocation
        let aligned_size = ((size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;


        println!("  Calling mmap:");
        println!("  Addresses: 0x{:x}", base_addr);
        println!("  Size: {} bytes ({} pages)", aligned_size, aligned_size / PAGE_SIZE);

        // Use mmap to allocate memory
        // MAP_PRIVATE: Not shared with other processes
        // MAP_ANONYMOUS:  Not backed by a file
        // MAP_FIXED:  Allocate at exact address (or fail)
        let mapping = unsafe {
            libc::mmap(
                base_addr as *mut libc::c_void, // Desired address
                aligned_size as libc::size_t, // Size to allocate
                libc::PROT_READ | libc::PROT_WRITE, // Initial permissions (RW)
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, // Flags
                -1, // No file descriptor (anonymous mapping)
                0 // No file offset
            )
        };

        // Check if allocation succeeded
        if mapping == libc::MAP_FAILED {
            return Err(anyhow::anyhow!(
                "mmap failed to allocate {} bytes at 0x{:x}",
                aligned_size, base_addr
            ));
        }

        // Verify we got the address we requested
        if mapping as u64 != base_addr {
            // Clean up the mapping we got
            unsafe {
                libc::munmap(mapping, aligned_size as libc::size_t);
            }
            return Err(anyhow::anyhow!(
                "mmap returned 0x{:x} instead of requested 0x{:x}",
                mapping as u64, base_addr
            ));
        }

        Ok(mapping as *mut u8)
    }


    /// Convert guest virtual address to host pointer
    /// This is the crucial trannslation function for future guest loading
    pub fn guest_to_host_addr(&self, guest_addr: u64) -> Result<*mut u8> {
        // Check if address is within allocated range
        if guest_addr < self.guest_base ||
            guest_addr >= self.guest_base + self.total_size {
            return Err(anyhow::anyhow!(
                "Guest address 0x{:x} outside allocated range 0x{:x}-0x{:x}",
                guest_addr, self.guest_base, self.guest_base + self.total_size
            ));
        }

        // Apply address translation offset
        let host_addr = (guest_addr as i64 + self.address_offset) as u64;
        Ok(host_addr as *mut u8)
    }
    
    pub fn translate_guest_to_host(&self, guest_addr: u64) -> Result<u64> {
        if guest_addr < self.guest_base {
            anyhow::bail!("Guest address 0x{:x} below guest base 0x{:x}",
            guest_addr, self.guest_base);
        }
        
        let guest_offset = guest_addr - self.guest_base;
        let host_addr = self.host_base + guest_offset;
        
        if host_addr >= self.host_base + self.total_size {
            anyhow::bail!("Translated address 0x{:x} outside allocated memory",
            host_addr);
        }
        
        Ok(host_addr)
    }
}

impl Drop for AllocatedMemory {
    /// Cleanup allocated memory when AllocatedMemory is dropped
    fn drop(&mut self) {
        if !self.host_mapping.is_null() {
            println!("  Cleaning up {} bytes at {:p}", self.total_size, self.host_mapping);
            unsafe {
                libc::munmap(
                    self.host_mapping as *mut libc::c_void,
                    self.total_size as libc::size_t
                );
            }
        }
    }
}

/// Public interface function - allocates memory for a guest binary
/// This is what main.rs will call to test our memory allocation
pub fn allocate_guest_memory(layout: &MemoryLayout) -> Result<AllocatedMemory> {
    AllocatedMemory::allocate_from_layout(layout)
}