#!/usr/bin/env python3
from pwn import *
import sys

def usage():
    print(f"Usage: {sys.argv[0]} <host> <port> <file>")
    print(f"Example: {sys.argv[0]} localhost 1338 _init.poc")
    sys.exit(1)

def main():
    if len(sys.argv) != 4:
        usage()

    host = sys.argv[1]
    port = int(sys.argv[2])
    path = sys.argv[3]

    with open(path, "rb") as f:
        payload = f.read()

    io = remote(host, port)

    # Protocol: first line = decimal byte length, then exactly that many raw bytes.
    # The server reads precisely `len` bytes, so no shutdown/EOF is needed.
    io.sendline(str(len(payload)).encode())
    io.send(payload)

    io.interactive()

if __name__ == "__main__":
    main()
