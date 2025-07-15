/*
 * Minimal Test Unikernel
 *
 * This program demonstrates unikernel-compatible binary structure:
 * - No external library dependencies
 * - Static linking only
 * - Self-contained execution
 * - Simple, predictable memory layout
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

// Simple string length calculation - no library dependencies
static unsigned long string_length(const char *str) {
    unsigned long len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// Entry point - this is where execution begins
// Note: We use a custom entry point rather than main() to avoid
// libc initialization overhead
void _start(void) {
    // Simple message that identifies this as our test unikernel
    const char *message = "Hello from PolyKernel test unikernel!\n";
    unsigned long message_len = string_length(message);

    // Output our message using direct system call
    syscall_write(1, message, message_len);  // 1 = stdout

    // Clean exit with success status
    syscall_exit(0);
}