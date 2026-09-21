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

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long

def ptrace(req: int, pid: int, addr: int = 0, data: int = 0) -> int:
    ctypes.set_errno(0)
    r = libc.ptrace(req, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    err = ctypes.get_errno()
    if r == -1 and err != 0:
        raise OSError(err, f"ptrace req={req} addr=0x{addr:x} failed")
    return r & ((1 << 64) - 1)

def peekq(pid: int, addr: int) -> int:
    return ptrace(PTRACE_PEEKDATA, pid, addr, 0)

def resolve_symbol(libc_path: str, name: str) -> int:
    out = subprocess.check_output(["nm", "-D", libc_path], text=True, errors="ignore")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            sym = parts[2].split("@@")[0]
            if sym == name:
                return int(parts[0], 16)
    raise RuntimeError(f"symbol not found: {name}")

def main() -> None:
    chall = sys.argv[1] if len(sys.argv) > 1 else "./chall_patched"
    libc_path = sys.argv[2] if len(sys.argv) > 2 else "./libc.so.6"
    cwd = os.path.dirname(os.path.abspath(chall)) or os.getcwd()

    p = subprocess.Popen([chall], cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.05)
    pid = p.pid

    ptrace(PTRACE_ATTACH, pid)
    os.waitpid(pid, 0)

    libc_base = None
    libc_map_path = None
    heap_lo = None
    stack_lo = None
    for line in open(f"/proc/{pid}/maps"):
        parts = line.split(None, 5)
        lo = int(parts[0].split("-")[0], 16)
        perms = parts[1]
        offset = int(parts[2], 16)
        path = parts[5].strip() if len(parts) > 5 else ""
        if path.endswith("libc.so.6") and perms.startswith("r-xp"):
            libc_base = lo - offset
            libc_map_path = path
        if path == "[heap]":
            heap_lo = lo
        if path == "[stack]":
            stack_lo = lo

    if libc_base is None:
        raise RuntimeError("failed to locate libc base")

    off_stdout = resolve_symbol(libc_path, "_IO_2_1_stdout_")
    off_wfile = resolve_symbol(libc_path, "_IO_wfile_jumps")
    off_system = resolve_symbol(libc_path, "system")
    try:
        off_file = resolve_symbol(libc_path, "_IO_file_jumps")
    except Exception:
        off_file = None

    stdout_addr = libc_base + off_stdout
    wide_data = peekq(pid, stdout_addr + 0xA0)
    vtable = peekq(pid, stdout_addr + 0xD8)
    chain = peekq(pid, stdout_addr + 0x68)
    lock = peekq(pid, stdout_addr + 0x88)
    wide_vtable = peekq(pid, wide_data + 0xE0) if wide_data else 0

    print(f"libc_base        = {libc_base:#x}")
    print(f"heap_lo          = {heap_lo:#x}" if heap_lo is not None else "heap_lo          = <none>")
    print(f"stack_lo         = {stack_lo:#x}" if stack_lo is not None else "stack_lo         = <none>")
    print(f"stdout           = {stdout_addr:#x}")
    print(f"wide_data        = {wide_data:#x}")
    print(f"stdout->_chain   = {chain:#x}")
    print(f"stdout->_lock    = {lock:#x}")
    print(f"stdout->vtable   = {vtable:#x}")
    print(f"wide->_vtable    = {wide_vtable:#x}")
    print("")
    print(f"off_stdout       = {off_stdout:#x}")
    print(f"off_wfile_jumps  = {off_wfile:#x}")
    print(f"off_system       = {off_system:#x}")
    if off_file is not None:
        print(f"off_file_jumps   = {off_file:#x}")
        print(f"delta(file->wfile) = {(off_wfile - off_file):#x}")
    print("")
    print("[+] low-byte views")
    print(f"stdout->vtable low3   = {vtable & 0xffffff:#x}")
    print(f"wide->_vtable low3    = {wide_vtable & 0xffffff:#x}")
    print(f"system low3           = {(libc_base + off_system) & 0xffffff:#x}")
    print(f"stdout low3           = {stdout_addr & 0xffffff:#x}")
    print(f"_IO_wfile_jumps low3  = {(libc_base + off_wfile) & 0xffffff:#x}")

    ptrace(PTRACE_DETACH, pid)
    if p.stdin:
        p.stdin.close()
    try:
        p.kill()
    except Exception:
        pass

if __name__ == "__main__":
    main()
