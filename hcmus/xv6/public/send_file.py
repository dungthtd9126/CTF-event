#!/usr/bin/env python3
from pwn import *
import base64
import sys

CHUNK_SIZE = 256

def usage():
    print(f"Usage: {sys.argv[0]} <host> <port> <file>")
    print(f"Example: {sys.argv[0]} localhost 1337 _init.poc")
    sys.exit(1)

def main():
    if len(sys.argv) != 4:
        usage()

    host = sys.argv[1]
    port = int(sys.argv[2])
    path = sys.argv[3]

    with open(path, "rb") as f:
        encoded = base64.b64encode(f.read())

    io = remote(host, port)

    # Send base64 in lines of max 256 chars.
    for i in range(0, len(encoded), CHUNK_SIZE):
        io.sendline(encoded[i:i + CHUNK_SIZE])

    io.sendline(b"EOF")

    io.interactive()

if __name__ == "__main__":
    main()
