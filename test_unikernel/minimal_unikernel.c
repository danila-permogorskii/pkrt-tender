/*
 * Minimal Test Unikernel
 *
 * This program demonstrates unikernel-compatible binary structure:
 * - No external library dependencies (no libc)
 * - Static linking only (no dynamic libraries)
 * - Self-contained execution (custom _start entry point)
 * - Simple, predictable memory layout
 * - Direct system calls using inline assembly
 * - Basic error handling for syscall failures
 *
 * Purpose: Serves as a test binary for PolyKernel tender system
 * to validate unikernel loading and execution capabilities.
 */

// Direct system call interface - no libc dependencies
static inline long syscall_write(int fd, const void *buf, unsigned long count) {
    long result;
    // Direct system call using inline assembly - this is how unikernels
    // typically interact with the host without library dependencies
    __asm__ volatile (
        "syscall"
        : "=a" (result)
        : "a" (1), "D" (fd), "S" (buf), "d" (count)  // SYS_write = 1
        : "rcx", "r11", "memory"
    );
    return result;
}

// Simple string length calculation - no library dependencies
static unsigned long string_length(const char *str) {
    unsigned long len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// Helper function to write error messages
static inline void write_error(const char *msg) {
    unsigned long len = string_length(msg);
    syscall_write(2, msg, len);  // 2 = stderr
}

static inline void syscall_exit(int status) {
    // Direct exit system call - clean termination without libc
    __asm__ volatile (
        "syscall"
        :
        : "a" (60), "D" (status)  // SYS_exit = 60
        : "memory"
    );
    __builtin_unreachable();  // Tell compiler this never returns
}

// Entry point - this is where execution begins
// Note: We use a custom entry point rather than main() to avoid
// libc initialization overhead
void _start(void) {
    // Simple message that identifies this as our test unikernel
    const char *message = "Hello from PolyKernel test unikernel!\n";
    unsigned long message_len = string_length(message);

    // Output our message using direct system call
    long write_result = syscall_write(1, message, message_len);  // 1 = stdout
    
    // Check if write operation succeeded
    if (write_result < 0) {
        write_error("Error: Failed to write message\n");
        syscall_exit(1);
    }

    // Clean exit with success status
    syscall_exit(0);
}