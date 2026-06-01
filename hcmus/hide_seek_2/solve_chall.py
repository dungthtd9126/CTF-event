#!/usr/bin/env python3
"""
Offline solver for chall(2).

The binary contains a decoy checker and a real checker.  The real checker is
reached through an overlapping PT_LOAD segment: the bytes actually mapped at
0x402000 differ from what normal section-based disassembly shows.  Runtime
_start passes 0x76c558 as main; that function copies the real SUBLEQ VM image
from vaddr 0x700080 and verifies a 40-byte input.

Usage:
    python3 solve_chall2_final.py './chall'
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
        priority = "HCMUS-CTF{test))}abcdefghijklmnopqrstuvwxyz0123456789_!?:;()"

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
    ap = argparse.ArgumentParser(description="Solve chall(2) offline")
    ap.add_argument("binary", nargs="?", default="./chall(2)", help="path to the challenge ELF")
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
