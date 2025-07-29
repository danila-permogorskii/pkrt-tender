use crate::elf::ElfInfo;
use crate::memory::AllocatedMemory;
use libc::printf;

/// Guest CPU state configuration for execution
#[derive(Debug)]
pub struct GuestExecutionState {
    /// Guest entry point (from ELF)
    pub entry_point: u64,

    /// Stack pointer for guest execution
    pub stack_pointer: u64,

    /// Guest memory context
    pub memory: AllocatedMemory,

    /// Execution ready flag
    pub ready_for_execution: bool,
}

impl GuestExecutionState {
    /// Create guest execution state from loaded binary
    pub fn new(elf_info: &ElfInfo, memory: AllocatedMemory) -> anyhow::Result<Self> {
        // Calculate entry point in host memory space
        let entry_point = Self::calculate_entry_point(elf_info, &memory)?;

        // Setup stack at top of guest memory
        let stack_pointer = Self::setup_guest_stack(&memory)?;

        Ok(GuestExecutionState {
            entry_point,
            stack_pointer,
            memory,
            ready_for_execution: false,
        })
    }

    /// Calculate entry point in host memory space
    fn calculate_entry_point(
        elf_info: &ElfInfo,
        allocated_memory: &AllocatedMemory,
    ) -> anyhow::Result<u64> {
        // Convert guest virtual address to host address
        let host_entry = allocated_memory.translate_guest_to_host(elf_info.entry_point)?;

        println!("  Entry point translation:");
        println!("  Guest entry point: 0x{:x}", elf_info.entry_point);
        println!("  Host entry point: 0x{:x}", host_entry);

        Ok(host_entry)
    }

    /// Setup guest stack at top of memory
    fn setup_guest_stack(memory: &AllocatedMemory) -> anyhow::Result<u64> {
        // Stack grows downward from top of memory
        // Leave 8-byte alignment for x86_64
        let stack_top = memory.host_base + memory.total_size;
        let aligned_stack = stack_top - 0x8;

        println!("  Stack setup");
        println!("  Memory top: 0x{:x}", stack_top);
        println!("  Aligned Stack: 0x{:x}", aligned_stack);

        Ok(aligned_stack)
    }

    /// Validate execution state is ready
    pub fn validate_state(&mut self) -> anyhow::Result<()> {
        // Verify entry point is within loaded memory
        if self.entry_point < self.memory.host_base
            || self.entry_point >= self.memory.host_base + self.memory.total_size
        {
            anyhow::bail!(
                "Entry point 0x{:x} outside allocated memory",
                self.entry_point
            );
        }

        if self.stack_pointer <= self.memory.host_base
            || self.stack_pointer > self.memory.host_base + self.memory.total_size
        {
            anyhow::bail!(
                "Stack pointer 0x{:x} outside allocated memory",
                self.stack_pointer
            );
        }

        println!("  Guest execution state validated");
        self.ready_for_execution = true;

        Ok(())
    }

    /// Display execution state for debugging
    pub fn display_state(&self) {
        println!("\n🎮 Guest Execution State:");
        println!("==========================================");
        println!("Entry Point: 0x{:x}", self.entry_point);
        println!("Stack Pointer: 0x{:x}", self.stack_pointer);
        println!("Memory Base: 0x{:x}", self.memory.host_base);
        println!("Memory Size: {} bytes", self.memory.total_size);
        println!("Ready for Execution: {}", self.ready_for_execution);
    }
}
