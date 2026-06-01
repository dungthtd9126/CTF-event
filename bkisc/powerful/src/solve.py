#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('powerful-dfs_patched', checksec=False)
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
        set max-visualize-chunk-size 0x500
        b*0x5555555555af
        b*0x5555555561e5
        b*0x5555555557a3
        b*0x0000555555555645
        # show
        b*0x55555555591a
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
# set max-visualize-chunk-size 0x500
# patchelf --force-rpath --set-rpath . powerful-dfs_patched

def create(nodes, num):
    slna(b'> ', 1)
    slna(b'Number of nodes: ', nodes)
    slna(b'Number of edges: ', num)
    for i in range(num):
        info(f'{num-i} left')
        a = input("a: ")
        b = input("b: ")
        print(ru(b'(u v): '))

        sl(f'{a} {b}'.encode())
GDB()

create(100, 2)

def start_dfs(idx, src):
    slna(b'> ', 2)
    slna(b'Problem index: ', idx)
    slna(b'Source node: ', src)

start_dfs(0, 123)

p.interactive()
