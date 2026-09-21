#!/usr/bin/env python3
import argparse, base64, os, socket, struct, time
from typing import Iterable, Iterator, Optional, Tuple

Pos = Tuple[float, float, float]


def parse_target(s: str) -> tuple[str, int]:
    if ':' not in s:
        raise argparse.ArgumentTypeError('target must be host:port')
    host, port_s = s.rsplit(':', 1)
    return host, int(port_s)


class WS:
    def __init__(self, host: str, port: int, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = bytearray()
        self.handshake()

    def handshake(self) -> None:
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        self.s.sendall(req)
        data = bytearray()
        while b'\r\n\r\n' not in data:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError('closed during websocket handshake')
            data.extend(chunk)
        head, rest = bytes(data).split(b'\r\n\r\n', 1)
        self.buf.extend(rest)
        status = head.split(b'\r\n', 1)[0]
        if b' 101 ' not in status:
            raise RuntimeError(f'websocket upgrade failed: {status.decode(errors="replace")}')

    def _recvn(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError('socket closed')
            self.buf.extend(chunk)
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def send_text(self, text: str) -> None:
        payload = text.encode()
        hdr = bytearray([0x81])
        if len(payload) < 126:
            hdr.append(0x80 | len(payload))
        elif len(payload) < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack('!H', len(payload))
        else:
            hdr += bytes([0x80 | 127]) + struct.pack('!Q', len(payload))
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        self.s.sendall(bytes(hdr) + mask + masked)

    def _send_control(self, opcode: int, payload: bytes = b'') -> None:
        hdr = bytearray([0x80 | opcode])
        hdr.append(0x80 | len(payload))
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        self.s.sendall(bytes(hdr) + mask + masked)

    def recv_event(self, timeout: float = 1.0) -> Optional[tuple[str, str]]:
        old = self.s.gettimeout()
        self.s.settimeout(timeout)
        frag_opcode = None
        frag_payload = bytearray()
        try:
            while True:
                try:
                    h = self._recvn(2)
                except socket.timeout:
                    return None
                b0, b1 = h
                fin = (b0 >> 7) & 1
                opcode = b0 & 0x0f
                masked = (b1 >> 7) & 1
                n = b1 & 0x7f
                if n == 126:
                    n = struct.unpack('!H', self._recvn(2))[0]
                elif n == 127:
                    n = struct.unpack('!Q', self._recvn(8))[0]
                mask = self._recvn(4) if masked else b''
                payload = bytearray(self._recvn(n))
                if masked:
                    for i in range(n):
                        payload[i] ^= mask[i & 3]
                payload_b = bytes(payload)

                if opcode == 0x8:  # close
                    code = None
                    reason = ''
                    if len(payload_b) >= 2:
                        code = struct.unpack('!H', payload_b[:2])[0]
                        reason = payload_b[2:].decode(errors='replace')
                    if code is None:
                        return ('close', 'close frame')
                    return ('close', f'code={code} reason={reason}')
                if opcode == 0x9:
                    self._send_control(0xA, payload_b)
                    continue
                if opcode == 0xA:
                    return ('pong', payload_b.decode(errors='replace'))
                if opcode == 0x2:
                    return ('binary', payload_b.hex())
                if opcode == 0x1:
                    if fin:
                        return ('text', payload_b.decode(errors='replace'))
                    frag_opcode = 0x1
                    frag_payload.extend(payload_b)
                    continue
                if opcode == 0x0:
                    if frag_opcode is None:
                        return ('continuation', payload_b.hex())
                    frag_payload.extend(payload_b)
                    if fin:
                        if frag_opcode == 0x1:
                            return ('text', frag_payload.decode(errors='replace'))
                        return ('binary', bytes(frag_payload).hex())
                    continue
                return ('opcode', f'opcode=0x{opcode:x} payload={payload_b.hex()}')
        finally:
            self.s.settimeout(old)

    def close(self) -> None:
        try:
            self._send_control(0x8, struct.pack('!H', 1000))
        except Exception:
            pass
        try:
            self.s.close()
        except OSError:
            pass


def fmt_pos(p: Pos) -> str:
    x, y, z = p
    return f"pos[{x:.6f},{y:.6f},{z:.6f}]"


def step_path(final: Pos, stride: float = 6.0) -> list[Pos]:
    start = (0.0, 3.5, 0.0)
    pts = [start]
    cur = list(start)
    # Move one axis at a time with plausible deltas.
    for axis in range(3):
        target = final[axis]
        while abs(target - cur[axis]) > stride:
            cur[axis] += stride if target > cur[axis] else -stride
            pts.append(tuple(cur))
        if cur[axis] != target:
            cur[axis] = target
            pts.append(tuple(cur))
    # repeat final to trigger servers that sample/compare the latest state more than once
    pts.extend([final, final])
    return pts


def boundary_paths() -> Iterator[list[Pos]]:
    yvals = [3.5, 25.0, 49.5]
    finals = []
    for y in yvals:
        finals += [
            (24.6, y, 0.0), (25.0, y, 0.0), (25.05, y, 0.0), (25.1, y, 0.0), (25.5, y, 0.0), (26.0, y, 0.0),
            (-24.6, y, 0.0), (-25.0, y, 0.0), (-25.05, y, 0.0), (-25.1, y, 0.0), (-25.5, y, 0.0), (-26.0, y, 0.0),
            (0.0, y, 24.6), (0.0, y, 25.0), (0.0, y, 25.05), (0.0, y, 25.1), (0.0, y, 25.5), (0.0, y, 26.0),
            (0.0, y, -24.6), (0.0, y, -25.0), (0.0, y, -25.05), (0.0, y, -25.1), (0.0, y, -25.5), (0.0, y, -26.0),
        ]
    # vertical probe kept because the server might only compare against the client clamp, not normal movement constraints
    finals += [(0.0, 49.6, 0.0), (0.0, 50.0, 0.0), (0.0, 50.05, 0.0), (0.0, 50.1, 0.0), (0.0, 51.0, 0.0)]
    seen = set()
    for f in finals:
        if f in seen:
            continue
        seen.add(f)
        yield step_path(f)


def interesting(kind: str, msg: str) -> bool:
    low = msg.lower()
    if kind == 'close' and msg:
        return True
    return any(tok in low for tok in ('flag', 'ctf', 'hcmus', '{', '}')) or (kind not in {'pong'} and 'incorrect position' not in low)


def run_sequence(host: str, port: int, seq: Iterable[Pos], delay: float, linger: float) -> bool:
    ws = WS(host, port)
    hit = False
    try:
        t0 = time.time()
        while time.time() - t0 < 1.0:
            ev = ws.recv_event(0.05)
            if ev is None:
                continue
            kind, msg = ev
            print(f"[<] {kind}: {msg}")
            if interesting(kind, msg):
                hit = True
        for i, p in enumerate(seq, 1):
            pkt = fmt_pos(p)
            print(f"[>] {i:04d} {pkt}")
            ws.send_text(pkt)
            end = time.time() + delay
            while time.time() < end:
                ev = ws.recv_event(0.10)
                if ev is None:
                    continue
                kind, msg = ev
                print(f"[<] {kind}: {msg}")
                if interesting(kind, msg):
                    return True
        end = time.time() + linger
        while time.time() < end:
            ev = ws.recv_event(0.10)
            if ev is None:
                continue
            kind, msg = ev
            print(f"[<] {kind}: {msg}")
            if interesting(kind, msg):
                return True
        return hit
    finally:
        ws.close()


def main() -> None:
    ap = argparse.ArgumentParser(description='de-matrix websocket probe')
    ap.add_argument('target', type=parse_target)
    ap.add_argument('--pos', nargs=3, type=float, metavar=('X','Y','Z'), help='send one final position using a stepped path')
    ap.add_argument('--stride', type=float, default=6.0, help='max step size when building stepped paths')
    ap.add_argument('--delay', type=float, default=0.35, help='wait after each sent packet')
    ap.add_argument('--linger', type=float, default=2.0, help='final wait after the sequence')
    ap.add_argument('--sleep-between', type=float, default=0.0, help='sleep between path attempts in boundary mode')
    args = ap.parse_args()
    host, port = args.target

    if args.pos:
        seq = step_path(tuple(args.pos), stride=args.stride)
        run_sequence(host, port, seq, args.delay, args.linger)
        return

    for idx, seq in enumerate(boundary_paths(), 1):
        print(f"=== path {idx:03d} final={seq[-1]} ===")
        try:
            if run_sequence(host, port, seq, args.delay, args.linger):
                return
        except Exception as e:
            print(f"[!] {type(e).__name__}: {e}")
        if args.sleep_between:
            time.sleep(args.sleep_between)


if __name__ == '__main__':
    main()
