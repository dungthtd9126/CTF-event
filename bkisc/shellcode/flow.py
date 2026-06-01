main flow
1. open(filename, O_RDONLY)  → fd=3 (inherited by child after fork!)
2. fork()
3. parent: wait()
4. child: child_process()

child_process flow
mmap(0x1337000, 0x2000, RWX, MAP_ANON|MAP_PRIVATE)
mprotect(0x1338000, 0x1000, RW)      ← second page: data
read(0, 0x1337037, 0xFC9)            ← reads YOUR shellcode
close(0)                              ← closes stdin
mprotect(0x1337000, 0x1000, RX)      ← first page: code
init_seccomp()                        ← installs filter
jmp shellcode (0x1337037)