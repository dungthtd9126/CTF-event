void _start() {
    long ret;
    // Call Astral's sys_exit(42)
    asm volatile (
        "syscall"
        : "=a" (ret)
        : "a" (13), "D" (42) // rax = 13 (exit), rdi = 42
        : "rcx", "r11", "memory"
    );
}