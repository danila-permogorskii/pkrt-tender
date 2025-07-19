// src/main.rs
// pkrt-tender: PolyKernel Runtime Tender
// Custom Solo5-SPT inspired unikernel runtime for multi-language support

mod elf;
mod memory;
mod loader;

use anyhow::Result;
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pkrt-tender")]
#[command(about = "PolyKernel Runtime Tender - Multi-language unikernel runtime")]
#[command(version = "0.1.0")]
struct Args {
    /// Path to the kernel binary to analyze and potentially execute
    kernel_binary: PathBuf,

    /// Test memory allocation without loading guest code (Microphase 5)
    #[arg(long, help = "Test memory allocation for the binary")]
    test_memory: bool,

    /// Test complete ELF loading (allocation + segments) (Microphase 6)
    #[arg(long, help = "Test complete ELF loading (allocation + segments)")]
    test_loading: bool,

    /// Show detailed segment analysis
    #[arg(long, help = "Show detailed ELF segment analysis")]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Validate that the kernel binary exists and is readable
    if !args.kernel_binary.exists() {
        return Err(anyhow::anyhow!(
            "Kernel binary does not exist: {}",
            args.kernel_binary.display()
        ));
    }

    println!("🚀 PolyKernel Runtime Tender (pkrt-tender) v0.1.0");
    println!("📂 Analyzing kernel binary: {}", args.kernel_binary.display());

    // Display file size
    let metadata = fs::metadata(&args.kernel_binary)?;
    println!("File size: {} bytes ({:.1} KB)", metadata.len(), metadata.len() as f64 / 1024.0);

    // Phase 1: Analyze the ELF binary (Microphases 2-3) - Using your actual function name
    let elf_info = elf::parse_elf(&args.kernel_binary)?;

    // Phase 2: Plan memory layout (Microphase 4)
    let memory_layout = elf::plan_memory_layout(&elf_info);

    // Display comprehensive analysis
    display_analysis(&elf_info, &memory_layout, args.verbose);

    // Phase 3: Test memory allocation if requested (Microphase 5)
    if args.test_memory {
        println!("\n🧪 Testing Memory Allocation (Microphase 5)");
        println!("==========================================");

        test_memory_allocation(&memory_layout)?;
    }

    // Phase 4: Test complete ELF loading if requested (Microphase 6)
    if args.test_loading {
        println!("\n📚 Testing Complete ELF Loading (Microphase 6)");
        println!("=============================================");

        test_elf_loading(&args.kernel_binary, &elf_info, &memory_layout)?;
    }

    // If no specific tests requested, show available options
    if !args.test_memory && !args.test_loading {
        println!("\n💡 Available Tests:");
        println!("   --test-memory    Test memory allocation (Microphase 5)");
        println!("   --test-loading   Test complete ELF loading (Microphase 6)");
        println!("   --verbose        Show detailed segment analysis");
        println!("\nExample: {} {} --test-loading",
                 env!("CARGO_PKG_NAME"), args.kernel_binary.display());
    }

    Ok(())
}

/// Display comprehensive ELF and memory analysis
fn display_analysis(elf_info: &elf::ElfInfo, layout: &elf::MemoryLayout, verbose: bool) {
    println!("\n📋 ELF Binary Analysis:");
    println!("==========================================");
    println!("Entry Point: 0x{:x}", elf_info.entry_point);
    println!("Architecture: {}", elf_info.architecture);
    println!("64-bit: {}", elf_info.is_64bit);

    // Fixed: detected_language is String, not Option<String> in your implementation
    println!("Detected Language: {}", elf_info.detected_language);

    println!("\n📊 ELF Segments ({} total):", elf_info.segments.len());

    // Categorize segments for summary
    let loadable_segments: Vec<_> = elf_info.segments.iter().filter(|s| s.is_loadable()).collect();
    let dynamic_segments: Vec<_> = elf_info.segments.iter().filter(|s| s.requires_dynamic_linking()).collect();
    let security_segments: Vec<_> = elf_info.segments.iter().filter(|s| s.is_security_related()).collect();

    println!("  📦 Loadable: {} | 🔗 Dynamic: {} | 🛡️  Security: {}",
             loadable_segments.len(), dynamic_segments.len(), security_segments.len());

    if verbose {
        println!("\n  Detailed Segment Analysis:");
        for (i, segment) in elf_info.segments.iter().enumerate() {
            println!("  [{}] {} - 0x{:08x} ({:>8} bytes) [{}] flags=0x{:x}",
                     i,
                     segment.segment_type,
                     segment.virtual_addr,
                     segment.size,
                     segment.permissions,
                     segment.flags);
        }
    } else {
        println!("\n  Key Loadable Segments:");
        for (i, segment) in loadable_segments.iter().enumerate() {
            println!("    [{}] 0x{:08x} ({:>8} bytes) [{}]",
                     i, segment.virtual_addr, segment.size, segment.permissions);
        }
    }

    if !dynamic_segments.is_empty() {
        println!("\n  ⚠️  Dynamic Linking Segments (problematic for unikernels):");
        for segment in &dynamic_segments {
            println!("    {} at 0x{:x}", segment.segment_type, segment.virtual_addr);
        }
    }

    println!("\n🧠 Memory Layout Analysis:");
    println!("==========================================");
    println!("Guest Address Space: 0x{:x} - 0x{:x} ({} bytes)",
             layout.guest_base_addr,
             layout.guest_end_addr,
             layout.guest_memory_span);
    println!("Suggested Host Base: 0x{:x}", layout.suggested_host_base);
    println!("Mapping Strategy: {}", layout.mapping_strategy);
    println!("Needs Address Translation: {}", layout.needs_address_translation);
    println!("Unikernel Compatible: {}", layout.is_unikernel_compatible);
    println!("Total Allocation Needed: {} bytes ({:.1} KB)",
             layout.total_allocation_size,
             layout.total_allocation_size as f64 / 1024.0);
    println!("Loadable Segments: {}", layout.loadable_segments_count);

    if !layout.compatibility_issues.is_empty() {
        println!("\n⚠️  Compatibility Issues:");
        for issue in &layout.compatibility_issues {
            println!("  • {}", issue);
        }
    }
}

/// Test memory allocation capability (Microphase 5)
fn test_memory_allocation(layout: &elf::MemoryLayout) -> Result<()> {
    println!("🔬 Beginning memory allocation test...");

    match memory::allocate_guest_memory(layout) {
        Ok(allocated) => {
            println!("✅ Memory allocation successful!");

            // Display detailed allocation information
            display_allocation_details(&allocated);

            // Test address translation functionality
            test_address_translation(&allocated)?;

            println!("🎉 Memory allocation test completed successfully!");
            println!("💡 Ready to proceed to Microphase 6: ELF Segment Loading");
        }
        Err(e) => {
            println!("❌ Memory allocation failed: {}", e);
            println!("💭 This is expected for incompatible binaries");

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

/// Test complete ELF segment loading (Microphase 6)
fn test_elf_loading(
    elf_path: &PathBuf,
    elf_info: &elf::ElfInfo,
    layout: &elf::MemoryLayout,
) -> Result<()> {
    println!("🚀 Beginning complete ELF loading test...");

    match loader::load_guest_binary(elf_path, elf_info, layout) {
        Ok(loaded_guest) => {
            println!("✅ Complete ELF loading successful!");

            // Display detailed loading information
            display_loading_details(&loaded_guest);

            // Validate the loaded binary
            loaded_guest.validate_loading()?;

            println!("🎉 Guest binary loading completed successfully!");
            println!("💡 Ready to proceed to Microphase 7: Basic Seccomp Structure");
        }
        Err(e) => {
            println!("❌ ELF loading failed: {}", e);
            println!("💭 This is expected for incompatible binaries");

            if !layout.is_unikernel_compatible {
                println!("\n📋 Analysis:");
                println!("   This binary cannot be loaded because:");
                for issue in &layout.compatibility_issues {
                    println!("   • {}", issue);
                }
            }
        }
    }

    Ok(())
}

/// Display detailed memory allocation information
fn display_allocation_details(allocated: &memory::AllocatedMemory) {
    println!("\n📊 Memory Allocation Details:");
    println!("   Host mapping address: {:p}", allocated.host_mapping);
    println!("   Guest base address: 0x{:x}", allocated.guest_base);
    println!("   Host base address: 0x{:x}", allocated.host_base);
    println!("   Total allocated size: {} bytes ({:.1} KB)",
             allocated.total_size, allocated.total_size as f64 / 1024.0);

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

/// Display detailed ELF loading information
fn display_loading_details(loaded_guest: &loader::LoadedGuest) {
    println!("\n📊 ELF Loading Details:");
    println!("   Entry point: 0x{:x}", loaded_guest.entry_point);
    println!("   Binary end: 0x{:x}", loaded_guest.binary_end);
    println!("   Segments loaded: {}", loaded_guest.loaded_segments.len());
    println!("   Data loaded: {} bytes ({:.1} KB)",
             loaded_guest.total_loaded_bytes,
             loaded_guest.total_loaded_bytes as f64 / 1024.0);
    println!("   BSS cleared: {} bytes ({:.1} KB)",
             loaded_guest.bss_bytes,
             loaded_guest.bss_bytes as f64 / 1024.0);

    println!("\n   Loaded Segments:");
    for (i, segment) in loaded_guest.loaded_segments.iter().enumerate() {
        println!("     [{}] {} at guest 0x{:x} → host {:p}",
                 i, segment.segment_type, segment.guest_addr, segment.host_addr);
        println!("         File: {} bytes, Memory: {} bytes, Perms: {}",
                 segment.file_size, segment.memory_size, segment.permissions);
    }
}

/// Test address translation functionality
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