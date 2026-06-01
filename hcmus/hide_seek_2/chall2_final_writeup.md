# HIDE AND SEEK — HCMUS CTF 2026

**Category:** Reverse Engineering  
**Tags:** `ELF overlap` · `anti-static-analysis` · `SUBLEQ VM` · `constraint solving` · `bit-plane checks`

---

## 1. Mô tả bài

File được đưa là một ELF 64-bit, static linked và not stripped. Nhìn bằng `file`/`readelf` thì tưởng khá bình thường:

```text
ELF 64-bit LSB executable, x86-64, statically linked, not stripped
Entry point: 0x402060
```

Bài đọc một dòng input, chạy một VM nhỏ, rồi in `ok` nếu input đúng và `no` nếu sai. Input đúng cũng chính là flag cần submit.

Điểm khó của bài không nằm ở thuật toán mã hóa cổ điển, mà nằm ở việc binary cố tình đánh lừa static analysis. Nếu chỉ mở `main` bình thường trong Ghidra/IDA/objdump thì mình sẽ thấy một checker khác và sinh ra flag giả.

---

## 2. Trap chính — ELF có `PT_LOAD` bị overlap

Lúc đầu mình đi theo đường rất tự nhiên:

```text
entry 0x402060
    -> __libc_start_main(0x401e00)
    -> main decoy
    -> SUBLEQ VM decoy
```

Đường này cho ra các chuỗi nhìn rất giống flag, ví dụ kiểu `this_should_not_be_solvable!?`, nhưng đó không phải checker thật.

Khi kiểm tra program header bằng `readelf -l`, mình thấy có 2 segment cùng map vào vùng quanh `0x402000`:

```text
LOAD off 0x001000 -> vaddr 0x401000  R E
LOAD off 0x1cb000 -> vaddr 0x402000  R E   <-- overlap
```

Vì loader map các `PT_LOAD` theo thứ tự program header, segment sau sẽ overwrite page runtime ở `0x402000`. Do đó disassembly theo section `.text` không phản ánh đúng byte thật lúc chạy.

Nếu lấy byte ở file offset `0x1cb000 + 0x60` rồi disassemble lại tại virtual address `0x402060`, `_start` thật là:

```asm
0x402078: mov rdi, 0x76c558
0x40207f: call __libc_start_main
```

Vậy `main` thật không phải `0x401e00`, mà là:

```text
real main = 0x76c558
```

Đây là lý do những lần giải trước bị sai: mình đã reverse nhầm VM decoy.

---

## 3. Real main làm gì?

Ở `0x76c558`, chương trình làm các bước chính:

1. Đọc input bằng `getline`.
2. Bỏ `
` / `
` cuối dòng.
3. Allocate một vùng nhớ kích thước `0x6c4d8`.
4. Copy VM image thật từ virtual address `0x700080` vào vùng nhớ này.
5. Ghi input length và tối đa 40 byte input vào các cell VM.
6. Chạy SUBLEQ interpreter.
7. Nếu VM halt và cell result bằng `1` thì in `ok
`, ngược lại in `no
`.

Các constant quan trọng:

| Ý nghĩa | Giá trị |
|---|---:|
| Real VM vaddr | `0x700080` |
| Real VM file offset | `0x1cc080` |
| Real VM size | `0x6c4d8` |
| VM qword count | `55451` |
| Max instruction cell index | `0xd89a` |
| Max VM step | `0x3626c` |

File offset `0x1cc080` lấy được bằng cách translate `0x700080` qua segment:

```text
LOAD off 0x1cc000 -> vaddr 0x700000
0x700080 - 0x700000 + 0x1cc000 = 0x1cc080
```

---

## 4. Phân tích SUBLEQ VM

VM dùng instruction dạng 3 qword:

```text
[a, b, c]
```

Semantics:

```python
mem[b] -= mem[a]
if mem[b] <= 0:
    pc = c
else:
    pc += 3
```

VM halt khi `pc < 0`. Sau khi halt, binary check:

```text
mem[0xd72f] == 1
```

Các cell quan trọng:

| Cell | Ý nghĩa |
|---:|---|
| `0xd722` | hằng số `0` |
| `0xd723` | hằng số `-1` |
| `0xd72d` | input length |
| `0xd72e` | error counter |
| `0xd72f` | result cell |
| `0xd733` | input buffer, 40 qword |
| `0xd75b` | 320 bit của input, MSB first |

Phần đầu VM check length bằng `40`, sau đó expand 40 byte thành 320 bit:

```text
input[0] bit 7 -> mem[0xd75b + 0]
input[0] bit 6 -> mem[0xd75b + 1]
...
input[39] bit 0 -> mem[0xd75b + 319]
```

Sau stage này, checker chính bắt đầu ở VM pc:

```text
11196
```

---

## 5. Cấu trúc checker thật

Checker có tổng cộng **48 decision trees**.

Mình nhận ra ranh giới mỗi check bằng pattern fail:

```text
subleq -1, error_counter, next_check
```

Tức trong memory:

```python
mem[pc]     == 0xd723   # cell -1
mem[pc + 1] == 0xd72e   # error counter
```

Mỗi khi đi vào node fail này, VM sẽ tăng error counter rồi nhảy sang check tiếp theo. Muốn pass thì input phải đi theo nhánh success của toàn bộ 48 tree.

### 5.1. 40 tree đầu

40 tree đầu check từng byte độc lập. Mỗi tree chỉ hỏi các bit của một byte, nên mình DFS tree đó để lấy domain printable cho byte tương ứng.

Ví dụ một vài domain sau khi solve tree byte-local:

```text
pos 00: !"$(ABDHP
pos 01: #&,CFLX
pos 02: -MYZ
pos 03: U
...
pos 09: {
pos 13: _
pos 16: u
pos 39: }
```

Các domain này chưa đủ để ra flag duy nhất, nhưng đã giảm search space rất mạnh.

### 5.2. 8 tree cuối

8 tree cuối không check từng byte nữa, mà check theo **bit-plane**:

```text
check 40: bit 7 của toàn bộ 40 byte
check 41: bit 6 của toàn bộ 40 byte
...
check 47: bit 0 của toàn bộ 40 byte
```

Nói cách khác, check 40 đọc các bit:

```text
0, 8, 16, 24, ..., 312
```

check 41 đọc:

```text
1, 9, 17, 25, ..., 313
```

và cứ thế đến check 47.

Vì vậy nếu chỉ solve 40 check đầu thì rất dễ ra chuỗi nhìn hợp lý nhưng vẫn sai. Phải dùng 8 bit-plane tree cuối để prune/verify toàn bộ candidate.

---

## 6. Intended path của mình

Flow giải cuối cùng:

```text
readelf -l
    -> phát hiện PT_LOAD overlap

lấy byte runtime tại 0x402060 từ LOAD sau
    -> __libc_start_main nhận real main = 0x76c558

reverse real main
    -> real VM image ở vaddr 0x700080
    -> file offset 0x1cc080
    -> size 0x6c4d8

load VM image thành list qword signed
    -> emulate SUBLEQ
    -> xác định các cell input/result/error/bits

tìm 48 fail node dạng subleq -1, error_counter, next_check
    -> dựng 48 decision trees

solve 40 byte-local trees
    -> domain printable cho từng byte

backtracking + check feasibility trên 8 bit-plane trees
    -> chỉ còn 1 printable solution

full emulate lại candidate
    -> mem[result] == 1
    -> flag đúng
```

---

## 7. Bug / lỗi dễ mắc

### 7.1. Lỗi lớn nhất: reverse nhầm `main`

`objdump`/Ghidra theo section sẽ cho `_start` gọi `main = 0x401e00`. Nhưng runtime byte thật bị segment overlap overwrite, nên `_start` thật gọi `0x76c558`.

Đây là nguyên nhân tạo ra fake flag. Những string từ decoy VM có thể rất giống flag, nhưng server/challenge thật không dùng checker đó.

### 7.2. Chỉ solve 40 byte-check là chưa đủ

40 check đầu chỉ constrain từng byte. Bài còn 8 check cuối theo bit-plane. Nếu bỏ 8 check này, solver có thể chọn suffix sai hoặc ra nhiều string trông hợp lý.

### 7.3. Phải dùng signed qword cho VM memory

VM memory là qword signed. Các cell như `-1`, jump `pc < 0`, và phép `mem[b] <= 0` đều phụ thuộc signed behavior. Nếu unpack unsigned rồi xử lý cẩu thả thì fail node / halt condition dễ sai.

### 7.4. Translate vaddr sang file offset phải dùng segment cuối cùng

Vì binary có overlap, một virtual address có thể nằm trong nhiều `PT_LOAD`. Với địa chỉ bị overlap, phải chọn mapping runtime thật, tức segment match sau cùng trong program header order.

---

## 8. Solve script

Script dưới đây không brute force flag mù. Nó parse ELF, load đúng VM thật, recover constraints, rồi verify candidate bằng full VM emulator.

Chạy:

```bash
python3 solve_chall.py './chall' --verbose
```

Output:

```text
[+] real VM vaddr = 0x700080
[+] real VM file offset = 0x1cc080
[+] VM qwords = 55451
[+] decision trees = 48
[+] printable solutions = 1
HCMUS-CTF{d1d_y0u_solv3_both_ch4lls_;))}
```

Có thể check không cần assume format bằng:

```bash
python3 solve_chall.py './chall' --verbose --no-format --all
```

Output vẫn chỉ có đúng 1 printable solution.

```python
#!/usr/bin/env python3
"""
Offline solver for chall.

The binary contains a decoy checker and a real checker.  The real checker is
reached through an overlapping PT_LOAD segment: the bytes actually mapped at
0x402000 differ from what normal section-based disassembly shows.  Runtime
_start passes 0x76c558 as main; that function copies the real SUBLEQ VM image
from vaddr 0x700080 and verifies a 40-byte input.

Usage:
    python3 solve_chall.py './chall'
"""
from __future__ import annotations

import argparse
import math
import pathlib
import struct
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Values recovered from the real main at 0x76c558.
REAL_VM_VADDR = 0x700080
REAL_VM_SIZE = 0x6C4D8
START_CHECK_PC = 11196
MAX_VM_INDEX = 0xD89A
MAX_VM_STEPS = 0x3626C

# Important VM cells.
ZERO_CELL = 0xD722       # contains 0
NEG_ONE_CELL = 0xD723    # contains -1
INPUT_LEN_CELL = 0xD72D
ERROR_CELL = 0xD72E
RESULT_CELL = 0xD72F
INPUT_BUF_CELL = 0xD733  # 40 qword cells
BIT_BASE_CELL = 0xD75B   # 320 extracted bits, MSB first per byte

PRINTABLE = set(range(0x20, 0x7F))


def u64(x: bytes) -> int:
    return struct.unpack("<Q", x)[0]


def i64s(x: bytes) -> Tuple[int, ...]:
    return struct.unpack(f"<{len(x) // 8}q", x)


def parse_load_segments(elf: bytes) -> List[Tuple[int, int, int, int, int]]:
    """Return [(p_offset, p_vaddr, p_filesz, p_memsz, p_flags), ...] for PT_LOAD."""
    if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
        raise ValueError("expected 64-bit little-endian ELF")

    e_phoff = u64(elf[0x20:0x28])
    e_phentsize = struct.unpack("<H", elf[0x36:0x38])[0]
    e_phnum = struct.unpack("<H", elf[0x38:0x3A])[0]

    loads: List[Tuple[int, int, int, int, int]] = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack("<II", elf[off:off + 8])
        p_offset = u64(elf[off + 0x08:off + 0x10])
        p_vaddr = u64(elf[off + 0x10:off + 0x18])
        p_filesz = u64(elf[off + 0x20:off + 0x28])
        p_memsz = u64(elf[off + 0x28:off + 0x30])
        if p_type == 1:  # PT_LOAD
            loads.append((p_offset, p_vaddr, p_filesz, p_memsz, p_flags))
    return loads


def vaddr_to_offset(loads: Sequence[Tuple[int, int, int, int, int]], vaddr: int) -> int:
    """Translate a runtime virtual address to file offset using the LAST matching LOAD.

    Last matching segment matters here because the ELF deliberately overlaps
    PT_LOAD ranges.  Linux maps them in program-header order, so later LOADs
    overwrite earlier bytes at the same virtual page.
    """
    chosen: Optional[Tuple[int, int, int, int, int]] = None
    for seg in loads:
        p_offset, p_vaddr, p_filesz, _p_memsz, _p_flags = seg
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            chosen = seg
    if chosen is None:
        raise ValueError(f"virtual address {vaddr:#x} is not inside a file-backed PT_LOAD")
    p_offset, p_vaddr, _p_filesz, _p_memsz, _p_flags = chosen
    return p_offset + (vaddr - p_vaddr)


class SubleqSolver:
    def __init__(self, mem: List[int]) -> None:
        self.mem0 = mem
        self.bad_checks: List[Tuple[int, int]] = []
        for pc in range(START_CHECK_PC, 55074, 3):
            if self.mem0[pc] == NEG_ONE_CELL and self.mem0[pc + 1] == ERROR_CELL:
                # This instruction is the fail edge for one decision tree:
                #   subleq -1, error_counter, next_check
                self.bad_checks.append((pc, self.mem0[pc + 2]))

        if len(self.bad_checks) != 48:
            raise RuntimeError(f"expected 48 decision trees, got {len(self.bad_checks)}")

        self.check_starts = [START_CHECK_PC] + [good for _bad, good in self.bad_checks[:-1]]
        self.assignment: List[Optional[int]] = [None] * 40

    def accepted_byte_domain(self, byte_index: int) -> Set[int]:
        """Solve one of the first 40 byte-local decision trees."""
        start = self.check_starts[byte_index]
        bad_pc, good_pc = self.bad_checks[byte_index]
        out: Set[int] = set()

        def expand_unknown_bits(k: int, value: int, known: Dict[int, int]) -> None:
            if k == 8:
                if value in PRINTABLE:
                    out.add(value)
                return
            bit = byte_index * 8 + k
            if bit in known:
                expand_unknown_bits(k + 1, (value << 1) | known[bit], known)
            else:
                expand_unknown_bits(k + 1, value << 1, known)
                expand_unknown_bits(k + 1, (value << 1) | 1, known)

        def dfs(pc: int, known: Dict[int, int]) -> None:
            if pc == bad_pc:
                return
            if pc == good_pc:
                expand_unknown_bits(0, 0, known)
                return

            a, b, c = self.mem0[pc:pc + 3]
            if a == ZERO_CELL and b == ZERO_CELL:
                dfs(c, known)              # unconditional branch
            elif a == ZERO_CELL and BIT_BASE_CELL <= b < BIT_BASE_CELL + 320:
                bit = b - BIT_BASE_CELL
                old = known.get(bit)
                if old is None:
                    known[bit] = 0         # bit cell <= 0, branch taken
                    dfs(c, known)
                    known[bit] = 1         # bit cell > 0, fallthrough
                    dfs(pc + 3, known)
                    del known[bit]
                elif old == 0:
                    dfs(c, known)
                else:
                    dfs(pc + 3, known)
            else:
                raise RuntimeError(f"unexpected instruction at pc={pc}: {(a, b, c)}")

        dfs(start, {})
        return out

    def assigned_bit(self, bit: int) -> Optional[int]:
        byte_i, bit_i = divmod(bit, 8)
        value = self.assignment[byte_i]
        if value is None:
            return None
        return (value >> (7 - bit_i)) & 1

    def final_tree_feasible(self, check_index: int) -> bool:
        """Can a partial assignment still pass one of the 8 bit-plane trees?"""
        start = self.check_starts[check_index]
        bad_pc, good_pc = self.bad_checks[check_index]
        seen: Set[int] = set()

        def dfs(pc: int) -> bool:
            if pc == bad_pc:
                return False
            if pc == good_pc:
                return True
            if pc in seen:
                return False
            seen.add(pc)

            a, b, c = self.mem0[pc:pc + 3]
            if a == ZERO_CELL and b == ZERO_CELL:
                return dfs(c)
            if a == ZERO_CELL and BIT_BASE_CELL <= b < BIT_BASE_CELL + 320:
                val = self.assigned_bit(b - BIT_BASE_CELL)
                if val is None:
                    return dfs(c) or dfs(pc + 3)
                return dfs(c) if val == 0 else dfs(pc + 3)
            raise RuntimeError(f"unexpected instruction at pc={pc}: {(a, b, c)}")

        return dfs(start)

    def all_final_trees_feasible(self) -> bool:
        return all(self.final_tree_feasible(i) for i in range(40, 48))

    def emulate(self, inp: bytes) -> bool:
        """Full VM emulator used as a final sanity check."""
        mem = self.mem0[:]
        mem[INPUT_LEN_CELL] = len(inp)
        for i in range(40):
            mem[INPUT_BUF_CELL + i] = inp[i] if i < len(inp) else 0

        pc = 0
        for _ in range(MAX_VM_STEPS):
            if pc < 0:
                return mem[RESULT_CELL] == 1
            if pc + 2 > MAX_VM_INDEX:
                return False
            a, b, c = mem[pc:pc + 3]
            if a < 0 or b < 0 or a > MAX_VM_INDEX or b > MAX_VM_INDEX:
                return False
            mem[b] -= mem[a]
            pc = c if mem[b] <= 0 else pc + 3
        return False

    def solve(self, enumerate_all: bool = False, assume_flag_format: bool = True) -> List[bytes]:
        domains = [self.accepted_byte_domain(i) for i in range(40)]

        # The VM itself already leaves only one printable solution.  Keeping the
        # common CTF wrapper here gives faster pruning and documents the expected
        # submission format.  Use --no-format to solve without this assumption.
        if assume_flag_format:
            prefix = b"HCMUS-CTF{"
            for i, ch in enumerate(prefix):
                domains[i] &= {ch}
            domains[39] &= {ord("}")}

        if any(not d for d in domains):
            raise RuntimeError("empty byte domain; constants are probably wrong")

        # Human-looking priority only affects which solution is printed first.
        # With this binary there is one printable solution anyway.
        priority = "HCMUS-CTF{d1d_y0u_solv3_both_ch4lls_;))}abcdefghijklmnopqrstuvwxyz0123456789_!?:;()"

        def sort_key(v: int) -> Tuple[int, int]:
            idx = priority.find(chr(v))
            return (idx if idx >= 0 else 999, v)

        ordered_domains: List[List[int]] = [sorted(d, key=sort_key) for d in domains]
        order = sorted(range(40), key=lambda i: len(ordered_domains[i]))
        solutions: List[bytes] = []

        def backtrack(k: int = 0) -> None:
            if solutions and not enumerate_all:
                return
            if k == len(order):
                candidate = bytes(v if v is not None else 0 for v in self.assignment)
                if self.emulate(candidate):
                    solutions.append(candidate)
                return

            pos = order[k]
            for value in ordered_domains[pos]:
                self.assignment[pos] = value
                if self.all_final_trees_feasible():
                    backtrack(k + 1)
                self.assignment[pos] = None

        backtrack()
        return solutions


def main() -> None:
    ap = argparse.ArgumentParser(description="Solve chall offline")
    ap.add_argument("binary", nargs="?", default="./chall", help="path to the challenge ELF")
    ap.add_argument("--all", action="store_true", help="print all printable solutions")
    ap.add_argument("--verbose", action="store_true", help="print VM location and decision-tree count")
    ap.add_argument("--no-format", action="store_true", help="do not assume the HCMUS-CTF{...} wrapper")
    args = ap.parse_args()

    blob = pathlib.Path(args.binary).read_bytes()
    loads = parse_load_segments(blob)
    vm_off = vaddr_to_offset(loads, REAL_VM_VADDR)
    vm_blob = blob[vm_off:vm_off + REAL_VM_SIZE]
    if len(vm_blob) != REAL_VM_SIZE:
        raise RuntimeError("truncated VM image")

    solver = SubleqSolver(list(i64s(vm_blob)))
    solutions = solver.solve(enumerate_all=args.all, assume_flag_format=not args.no_format)
    if not solutions:
        raise SystemExit("no printable solution found")

    if args.verbose:
        print(f"[+] real VM vaddr = {REAL_VM_VADDR:#x}")
        print(f"[+] real VM file offset = {vm_off:#x}")
        print(f"[+] VM qwords = {REAL_VM_SIZE // 8}")
        print(f"[+] decision trees = {len(solver.bad_checks)}")
        print(f"[+] printable solutions = {len(solutions)}")

    for s in solutions:
        print(s.decode("ascii"))


if __name__ == "__main__":
    main()

```

---

## 9. Flag

```text
HCMUS-CTF{d1d_y0u_solv3_both_ch4lls_;))}
```
