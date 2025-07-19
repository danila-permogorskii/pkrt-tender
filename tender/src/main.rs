mod elf;
mod memory;
mod loader;

use std::fs;
use clap::Parser;
use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pkrt-tender")]
#[command(about = "PolyKernel Runtime Tender - Multi-language unikernel runtime")]
struct Args {
    /// Path to the kernel binary to analyze and potentially execute
    kernel_binary: PathBuf,

    /// Test memory allocation without loading guest code
    #[arg(long, help = "Test memory allocation for the binary")]
    test_memory: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let kernel_path = &args.kernel_binary;

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

            // Add this to main.rs after your existing ELF analysis printout
            println!("\n--- Memory Layout Analysis ---");
            let memory_layout = elf::plan_memory_layout(&elf_info);

            println!("Guest memory requirements:");
            println!("  Base address: 0x{:x}", memory_layout.guest_base_addr);
            println!("  Memory span: 0x{:x} bytes ({:.1} KB)",
                     memory_layout.guest_memory_span,
                     memory_layout.guest_memory_span as f64 / 1024.0);
            println!("  End address: 0x{:x}", memory_layout.guest_end_addr);
            println!("  Loadable segments: {}", memory_layout.loadable_segments_count);

            println!("\nMemory mapping strategy:");
            println!("  Strategy: {}", memory_layout.mapping_strategy);
            println!("  Suggested host base: 0x{:x}", memory_layout.suggested_host_base);
            println!("  Needs address translation: {}", memory_layout.needs_address_translation);
            println!("  Total allocation needed: 0x{:x} bytes ({:.1} KB)",
                     memory_layout.total_allocation_size,
                     memory_layout.total_allocation_size as f64 / 1024.0);

            println!("\nUnikernel compatibility:");
            println!("  Compatible: {}", memory_layout.is_unikernel_compatible);
            if !memory_layout.compatibility_issues.is_empty() {
                println!("  Issues:");
                for issue in &memory_layout.compatibility_issues {
                    println!("    - {}", issue);
                }
            }

            // Test memory allocation if requested
            if args.test_memory {
                println!("\n🧪 Testing Memory Allocation");
                println!("==========================================");
                test_memory_allocation(&memory_layout)?;
            }
        }
        Err(e) => {
            println!("Elf parsing filed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Test the new memory allocation capability
/// This demonstrates memory allocation without loading guest code yet
fn test_memory_allocation(layout: &elf::MemoryLayout) -> Result<()> {
    println!("🔬 Beginning memory allocation test...");

    // Attempt to allocate memory according to our layout plan
    match memory::allocate_guest_memory(layout) {
        Ok(allocated) => {
            println!("✅ Memory allocation successful!");

            // Display detailed allocation information
            display_allocation_details(&allocated);

            // Test address translation functionality
            test_address_translation(&allocated)?;

            println!("🎉 Memory allocation test completed successfully!");
            println!("💡 Ready to proceed to next phase: Guest Memory Loading");

            // The AllocatedMemory will be cleaned up when dropped
        }
        Err(e) => {
            println!("❌ Memory allocation failed: {}", e);
            println!("💭 This is expected for incompatible binaries");

            // For incompatible binaries, explain why allocation failed
            if !layout.is_unikernel_compatible {
                println!("\n📋 Analysis:");
                println!("   This binary cannot be loaded as a unikernel because:");
                for issue in &layout.compatibility_issues {
                    println!("   • {}", issue);
                }
                println!("   Memory allocation is intentionally skipped for safety.");
            }
        }
    }

    Ok(())
}

/// Display detailed information about successful memory allocation
fn display_allocation_details(allocated: &memory::AllocatedMemory) {
    println!("\n📊 Memory Allocation Details:");
    println!("   Host mapping address: {:p}", allocated.host_mapping);
    println!("   Guest base address: 0x{:x}", allocated.guest_base);
    println!("   Host base address: 0x{:x}", allocated.host_base);
    println!("   Total allocated size: {} bytes", allocated.total_size);

    if allocated.address_offset != 0 {
        println!("   Address translation: guest + 0x{:x} = host", allocated.address_offset);
    } else {
        println!("   Address translation: direct mapping (no offset)");
    }

    println!("   Memory regions: {} regions allocated", allocated.regions.len());
    for (i, region) in allocated.regions.iter().enumerate() {
        println!("     Region {}: guest 0x{:x}, host {:p}, {} bytes, {:?}",
                 i, region.guest_addr, region.host_addr, region.size, region.permissions);
    }
}

/// Test the address translation functionality
/// This validates that our guest-to-host address mapping works correctly
fn test_address_translation(allocated: &memory::AllocatedMemory) -> Result<()> {
    println!("\n🧮 Testing address translation:");

    // Test translation for the guest base address
    let guest_start = allocated.guest_base;
    match allocated.guest_to_host_addr(guest_start) {
        Ok(host_ptr) => {
            println!("   ✅ Guest 0x{:x} → Host {:p}", guest_start, host_ptr);
        }
        Err(e) => {
            println!("   ❌ Translation failed: {}", e);
            return Err(e);
        }
    }

    // Test translation for an address in the middle of the allocation
    let guest_middle = allocated.guest_base + (allocated.total_size / 2);
    match allocated.guest_to_host_addr(guest_middle) {
        Ok(host_ptr) => {
            println!("   ✅ Guest 0x{:x} → Host {:p}", guest_middle, host_ptr);
        }
        Err(e) => {
            println!("   ❌ Mid-range translation failed: {}", e);
            return Err(e);
        }
    }

    // Test translation for an invalid address (should fail safely)
    let invalid_addr = allocated.guest_base + allocated.total_size + 0x1000;
    match allocated.guest_to_host_addr(invalid_addr) {
        Ok(_) => {
            println!("   ❌ Invalid address 0x{:x} should have failed translation", invalid_addr);
            return Err(anyhow::anyhow!("Address validation failed"));
        }
        Err(_) => {
            println!("   ✅ Invalid address 0x{:x} correctly rejected", invalid_addr);
        }
    }

    Ok(())
}

