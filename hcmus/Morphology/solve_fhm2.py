#!/usr/bin/env python3
# Funny Helicopter Morphology - 2 solver (no pwntools / no z3)
# Usage: python3 solve_fhm2.py chall.blackpinker.com 20941
from __future__ import annotations

import argparse
import bisect
import itertools
import math
import random
import re
import socket
import sys
import time
from functools import reduce
from math import prod
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

TARGET_N = 16
AUX_N = 8
T_MIN = 1 << 59
T_MAX = 1 << 60
TWO64 = 1 << 64

# OpenFHE 60-bit first-tower primes commonly generated for this parameter set.
# The script also scans around the printed main q0.
LIKELY_QAUX = [
    1152921504606846577,
    1152921504606846097,
    1152921504606845777,
    1152921504606845473,
    1152921504606844913,
]

DEFAULT_CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "_-!?.@#$%^&*+=:,/"
)
HEX_RE = re.compile(r"[0-9a-fA-F]{6,}$")


def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)


def center_mod(x: int, q: int) -> int:
    x %= q
    return x - q if x > q // 2 else x


def center_vec(v: Sequence[int], q: int) -> List[int]:
    return [center_mod(x, q) for x in v]


def parse_int(label: str, text: str) -> int:
    m = re.search(rf"^{re.escape(label)}:\s*(-?\d+)\s*$", text, re.M)
    if not m:
        raise ValueError(f"cannot parse {label!r}; got:\n{text[:1000]}")
    return int(m.group(1))


def parse_enc(text: str) -> bytes:
    m = re.search(r"Encrypted flag:\s*([0-9a-fA-F]+)", text)
    if not m:
        raise ValueError(f"cannot parse encrypted flag; got:\n{text[:1000]}")
    return bytes.fromhex(m.group(1))


def parse_vec(label: str, text: str) -> List[int]:
    m = re.search(rf"{re.escape(label)}:\s*\[([^\]]*)\]", text)
    if not m:
        raise ValueError(f"cannot parse vector {label!r}; got:\n{text[:500]}")
    body = m.group(1).strip()
    return [] if not body else [int(x.strip()) for x in body.split(',')]


def recv_some(sock: socket.socket, timeout: float = 0.15) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            d = sock.recv(65536)
            if not d:
                break
            chunks.append(d)
        except socket.timeout:
            break
    return b''.join(chunks)


def recv_until(sock: socket.socket, regex: bytes, hard_timeout: float) -> bytes:
    end = time.time() + hard_timeout
    data = b''
    rgx = re.compile(regex)
    sock.settimeout(0.3)
    while time.time() < end:
        try:
            d = sock.recv(65536)
            if not d:
                break
            data += d
            if rgx.search(data):
                data += recv_some(sock, 0.08)
                return data
        except socket.timeout:
            if rgx.search(data):
                data += recv_some(sock, 0.08)
                return data
    return data


def recv_until_close(sock: socket.socket, hard_timeout: float) -> bytes:
    end = time.time() + hard_timeout
    data = b''
    sock.settimeout(0.4)
    while time.time() < end:
        try:
            d = sock.recv(65536)
            if not d:
                break
            data += d
        except socket.timeout:
            if data:
                break
    return data


def negacyclic_matrix(poly: Sequence[int]) -> List[List[int]]:
    """Matrix M with M*x = coeff(poly*x) in Z[x]/(x^n+1)."""
    n = len(poly)
    return [[(1 if k >= j else -1) * int(poly[(k - j) % n]) for j in range(n)] for k in range(n)]


def negacyclic_conv(a: Sequence[int], b: Sequence[int], q: Optional[int] = None) -> List[int]:
    n = len(a)
    out = [0] * n
    for i, ai in enumerate(a):
        if not ai:
            continue
        for j, bj in enumerate(b):
            if not bj:
                continue
            k = i + j
            v = int(ai) * int(bj)
            if k >= n:
                k -= n
                v = -v
            out[k] += v
    if q is not None:
        out = [x % q for x in out]
    return out


def dot(a: Sequence[int], b: Sequence[int]) -> int:
    return sum(int(x) * int(y) for x, y in zip(a, b))


def solve_linear_mod(A: Sequence[Sequence[int]], b: Sequence[int], m: int) -> List[int]:
    """Gaussian elimination over Z/mZ. Retries are cheap if no unit pivots exist."""
    aug = [[x % m for x in row] + [bb % m] for row, bb in zip(A, b)]
    rows, cols = len(aug), len(aug[0]) - 1
    where = [-1] * cols
    r = 0
    for c in range(cols):
        piv = None
        for i in range(r, rows):
            if math.gcd(aug[i][c], m) == 1:
                piv = i
                break
        if piv is None:
            continue
        aug[r], aug[piv] = aug[piv], aug[r]
        inv = pow(aug[r][c], -1, m)
        aug[r] = [(x * inv) % m for x in aug[r]]
        for i in range(rows):
            if i == r:
                continue
            f = aug[i][c] % m
            if f:
                aug[i] = [(aug[i][j] - f * aug[r][j]) % m for j in range(cols + 1)]
        where[c] = r
        r += 1
        if r == cols:
            break
    if any(w < 0 for w in where):
        raise ValueError("main linear system was not full rank modulo r")
    sol = [aug[where[c]][-1] % m for c in range(cols)]
    for row, bb in zip(A, b):
        if (dot(row, sol) - bb) % m != 0:
            raise ValueError("bad modular solution")
    return sol


def recover_main_S(q: int, q0: int, r: int,
                   c1s: Sequence[Sequence[int]], c0s: Sequence[Sequence[int]],
                   upper_slack: int, brute_limit: int) -> Tuple[List[int], Tuple[int, int]]:
    A: List[List[int]] = []
    y: List[int] = []
    for a_raw, c_raw in zip(c1s, c0s):
        a = center_vec(a_raw, q)
        c = center_vec(c_raw, q)
        A.extend(negacyclic_matrix(a))
        y.extend(c)

    s_mod = solve_linear_mod(A, [yy % r for yy in y], r)
    upper = min(T_MAX, q0 + upper_slack)
    choices = []
    for sm in s_mod:
        if sm > upper:
            raise ValueError("S residue is above lift upper bound; retry or increase --upper-slack")
        hi = (upper - sm) // r
        choices.append(range(hi + 1))
    total = prod(len(x) for x in choices)
    if total > brute_limit:
        raise ValueError(f"too many S lifts ({total}); retrying for a larger r")

    z = []
    for row, yy in zip(A, y):
        d = yy - dot(row, s_mod)
        if d % r != 0:
            raise ValueError("non-divisible main equation; unexpected wrap/noise model")
        z.append(d // r)

    best = None
    for hs in itertools.product(*choices):
        residuals = [zz - dot(row, hs) for row, zz in zip(A, z)]
        max_abs = max(abs(e) for e in residuals)
        score = sum(e * e for e in residuals)
        cand = (score, max_abs, hs)
        if best is None or cand < best:
            best = cand
    if best is None:
        raise ValueError("could not lift S")
    score, max_abs, hs = best
    if max_abs > 100:
        raise ValueError(f"bad S lift/noise max={max_abs}, score={score}")
    return [sm + r * h for sm, h in zip(s_mod, hs)], (score, max_abs)


def collect_one(host: str, port: int, timeout: float) -> Tuple[int, int, bytes, int, List[List[int]], List[List[int]], Dict[int, int]]:
    with socket.create_connection((host, port), timeout=timeout) as s:
        recv_some(s, 0.15)
        # PARAMS must be first; otherwise the server switches to encrypted_flag_1.
        s.sendall(b"PARAMS\n")
        params_txt = recv_until(s, rb"Encrypted flag:\s*[0-9a-fA-F]+\s*\n", timeout).decode("latin-1", "replace")
        q = parse_int("q", params_txt)
        q0 = parse_int("q0", params_txt)
        enc = parse_enc(params_txt)
        zeros = " ".join(["0"] * TARGET_N)
        s.sendall(f"CHALLENGE 10 {zeros}\n".encode())
        chall_txt = recv_until_close(s, timeout).decode("latin-1", "replace")

    r = parse_int("r", chall_txt)
    c1s, c0s = [], []
    for i in range(10):
        m = re.search(rf"SAMPLE {i}\s*C1:\s*\[[^\]]*\]\s*C0:\s*\[[^\]]*\]", chall_txt, re.S)
        if not m:
            raise ValueError(f"missing sample {i}; got:\n{chall_txt[:1000]}")
        block = m.group(0)
        c1s.append(parse_vec("C1", block))
        c0s.append(parse_vec("C0", block))
    hints = {int(i): int(v) for i, v in re.findall(r"E\[(\d+)\]:\s*(-?\d+)", chall_txt)}
    if 0 not in hints or 1 not in hints:
        raise ValueError("server reply did not include E[0]/E[1]")
    return q, q0, enc, r, c1s, c0s, hints


def collect_instances(args) -> List[dict]:
    out = []
    last_err = None
    for attempt in range(1, args.tries + 1):
        if len(out) >= args.instances:
            break
        try:
            eprint(f"[+] collect {len(out)+1}/{args.instances}, try {attempt}/{args.tries}")
            q, q0, enc, r, c1s, c0s, hints = collect_one(args.host, args.port, args.timeout)
            eprint(f"    q0={q0} q_bits={q.bit_length()} r={r} enc_len={len(enc)} hints=({hints[0]},{hints[1]})")
            if r <= (q0 + args.upper_slack) // 2:
                raise ValueError("skip: r too small, S has too many lifts")
            S, stat = recover_main_S(q, q0, r, c1s, c0s, args.upper_slack, args.lift_limit)
            eprint(f"    recovered S: score={stat[0]} max_main_noise={stat[1]}")
            out.append({"q": q, "q0": q0, "enc": enc, "r": r, "S": S, "hints": hints})
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            last_err = exc
            eprint(f"[-] {exc}")
            time.sleep(args.sleep)
    if len(out) < args.instances:
        raise SystemExit(f"not enough good instances ({len(out)}/{args.instances}); last error: {last_err}")
    return out


def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for a in small:
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def qaux_candidates(q0: int, max_s: int, manual: Sequence[int], scan: int) -> List[int]:
    seen = set()
    out = []

    def add(x: int):
        if max_s < x < T_MAX and x not in seen:
            seen.add(x)
            out.append(x)

    for x in manual:
        add(x)
    for x in LIKELY_QAUX:
        add(x)
    add(q0)
    if scan > 0:
        lo = max(max_s + 1, q0 - scan)
        hi = min(T_MAX - 1, q0 + scan)
        # OpenFHE NTT primes for aux ringDim=8 are 1 mod 16.
        start = lo + ((1 - lo) % 16)
        for p in range(start, hi + 1, 16):
            if is_probable_prime(p):
                add(p)
    return out


def mat_inv_mod(A: Sequence[Sequence[int]], q: int) -> Optional[List[List[int]]]:
    n = len(A)
    aug = [[x % q for x in row] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(A)]
    r = 0
    for c in range(n):
        piv = None
        for i in range(r, n):
            if math.gcd(aug[i][c], q) == 1:
                piv = i
                break
        if piv is None:
            return None
        aug[r], aug[piv] = aug[piv], aug[r]
        inv = pow(aug[r][c], -1, q)
        aug[r] = [(x * inv) % q for x in aug[r]]
        for i in range(n):
            if i != r and aug[i][c] % q:
                f = aug[i][c] % q
                aug[i] = [(aug[i][j] - f * aug[r][j]) % q for j in range(2 * n)]
        r += 1
    return [row[n:] for row in aug]


def mat_vec(M: Sequence[Sequence[int]], v: Sequence[int], q: Optional[int] = None) -> List[int]:
    out = [sum(int(M[i][j]) * int(v[j]) for j in range(len(v))) for i in range(len(M))]
    if q is not None:
        out = [x % q for x in out]
    return out


def mat_mul(A: Sequence[Sequence[int]], B: Sequence[Sequence[int]], q: int) -> List[List[int]]:
    n = len(A)
    return [[sum(int(A[i][k]) * int(B[k][j]) for k in range(n)) % q for j in range(n)] for i in range(n)]


TERNARY = [list(t) for t in itertools.product((-1, 0, 1), repeat=AUX_N) if any(t)]


def find_B_pairs(S0: Sequence[int], S1: Sequence[int], q: int, bound: int) -> List[Tuple[int, int, List[int], List[int], List[int]]]:
    table = []
    for idx, b0 in enumerate(TERNARY):
        v = negacyclic_conv(b0, S1, q)
        table.append((v[0], idx, v))
    table.sort(key=lambda x: x[0])
    keys = [x[0] for x in table]
    hits = []
    for b1 in TERNARY:
        v1 = negacyclic_conv(b1, S0, q)
        c = v1[0]
        intervals = [(max(0, c - bound), min(q - 1, c + bound))]
        if c < bound:
            intervals.append((q + c - bound, q - 1))
        if c > q - 1 - bound:
            intervals.append((0, c + bound - q))
        for lo, hi in intervals:
            L = bisect.bisect_left(keys, lo)
            R = bisect.bisect_right(keys, hi)
            for _, idx, v0 in table[L:R]:
                dif = [center_mod(v1[k] - v0[k], q) for k in range(AUX_N)]
                if all(abs(x) <= bound for x in dif):
                    hits.append((sum(d * d for d in dif), max(abs(d) for d in dif), TERNARY[idx], b1, dif))
    hits.sort(key=lambda x: (x[1], x[0]))
    return hits


def key_bytes_from_X(X: Sequence[int], qaux: int) -> bytes:
    out = []
    for x in X:
        # Server signs the first tower residue. For this parameter range the signed
        # coefficient is always original_T - q_aux.
        u = (int(x) - qaux) % TWO64
        for j in range(8):
            out.append((u >> (8 * j)) & 0xff)
    return bytes(out)


def decrypt_with_X(enc: bytes, X: Sequence[int], qaux: int) -> bytes:
    kb = key_bytes_from_X(X, qaux)
    return bytes(c ^ kb[i % len(kb)] for i, c in enumerate(enc))


def gen_T_candidates(B0: Sequence[int], B1: Sequence[int], S0: Sequence[int], S1: Sequence[int],
                     k01: Tuple[int, int], qaux: int, K: int):
    Inv = mat_inv_mod(negacyclic_matrix(B0), qaux)
    if Inv is None:
        return
    A = mat_mul(negacyclic_matrix(B1), Inv, qaux)
    AS0 = mat_vec(A, S0, qaux)
    # K1 = S1 - A*S0 + A*K0. K0[0:2] is leaked.
    base = [center_mod(S1[i] - AS0[i] + A[i][0] * k01[0] + A[i][1] * k01[1], qaux) for i in range(AUX_N)]
    cols = [[A[i][j] % qaux for i in range(AUX_N)] for j in range(2, AUX_N)]
    vals = range(-K, K + 1)

    left = []
    for us in itertools.product(vals, repeat=3):
        vec = [sum(cols[j][i] * us[j] for j in range(3)) % qaux for i in range(AUX_N)]
        left.append((vec[0], us, vec))
    left.sort(key=lambda x: x[0])
    keys = [x[0] for x in left]

    for vs in itertools.product(vals, repeat=3):
        vec = [sum(cols[j + 3][i] * vs[j] for j in range(3)) % qaux for i in range(AUX_N)]
        target = (-base[0] - vec[0]) % qaux
        intervals = [(max(0, target - K), min(qaux - 1, target + K))]
        if target < K:
            intervals.append((qaux + target - K, qaux - 1))
        if target > qaux - 1 - K:
            intervals.append((0, target + K - qaux))
        for lo, hi in intervals:
            L = bisect.bisect_left(keys, lo)
            R = bisect.bisect_right(keys, hi)
            for _, us, pvec in left[L:R]:
                k1 = [center_mod(base[i] + pvec[i] + vec[i], qaux) for i in range(AUX_N)]
                if max(abs(x) for x in k1) > K:
                    continue
                k0 = [k01[0], k01[1]] + list(us) + list(vs)
                Rv = mat_vec(Inv, [(S0[i] - k0[i]) % qaux for i in range(AUX_N)], qaux)
                X = []
                ok = True
                for r in Rv:
                    x = r if r >= T_MIN else r + qaux
                    if not (T_MIN <= x < T_MAX):
                        ok = False
                        break
                    X.append(x)
                if ok and all(X[i] <= X[i + 1] for i in range(AUX_N - 1)):
                    yield X, k0, k1


def prune_best(cands: Dict[bytes, int], limit: int) -> Dict[bytes, int]:
    if len(cands) <= limit:
        return cands
    return dict(sorted(cands.items(), key=lambda kv: kv[1])[:limit])


def enumerate_plain_candidates(inst: dict, qaux: int, charset: str, pair_bound: int,
                               max_k: int, keep: int, verbose: bool) -> Dict[bytes, int]:
    allowed = set(charset.encode("latin-1"))
    S = inst["S"]
    S0, S1 = S[:AUX_N], S[AUX_N:]
    if max(max(S0), max(S1)) >= qaux:
        return {}
    hints = inst["hints"]
    k01 = (int(hints[0]), int(hints[1]))
    start_k = max(3, abs(k01[0]), abs(k01[1]))
    hits = find_B_pairs(S0, S1, qaux, pair_bound)
    if verbose:
        eprint(f"        qaux={qaux}: B-pair hits={len(hits)}")
    if not hits:
        return {}

    out: Dict[bytes, int] = {}
    for K in range(start_k, max_k + 1):
        before = len(out)
        for pair_score, pair_max, B0, B1, dif in hits:
            for X, k0, k1 in gen_T_candidates(B0, B1, S0, S1, k01, qaux, K):
                pt = decrypt_with_X(inst["enc"], X, qaux)
                if all(ch in allowed for ch in pt):
                    score = sum(abs(x) for x in k0 + k1) + pair_max
                    old = out.get(pt)
                    if old is None or score < old:
                        out[pt] = score
        out = prune_best(out, keep)
        if verbose:
            eprint(f"        K={K}: candidates {before} -> {len(out)}")
    return out


def common_prefix_rank(candidate_maps: Sequence[Dict[bytes, int]], min_len: int, max_len: int):
    for L in range(max_len, min_len - 1, -1):
        common = set(p[:L] for p in candidate_maps[0])
        for mp in candidate_maps[1:]:
            common &= set(p[:L] for p in mp)
        if not common:
            continue
        ranked = []
        for pref in common:
            total = 0
            for mp in candidate_maps:
                best = min(score for p, score in mp.items() if p.startswith(pref))
                total += best
            ranked.append((total, pref))
        ranked.sort(key=lambda x: (x[0], x[1]))
        return L, ranked
    return None, []


def strip_hex_padding(s: str) -> str:
    return HEX_RE.sub("", s)


def solve(args):
    instances = collect_instances(args)
    enc_len = min(len(inst["enc"]) for inst in instances)
    max_s = max(max(inst["S"]) for inst in instances)
    q0 = instances[0]["q0"]
    qauxes = qaux_candidates(q0, max_s, args.qaux, args.scan_qaux)
    if not qauxes:
        raise SystemExit("no q_aux candidates; retry with --scan-qaux larger or pass --qaux")
    eprint(f"[+] q_aux candidates ({len(qauxes)}): {qauxes[:20]}{' ...' if len(qauxes) > 20 else ''}")

    best_global = None
    for qaux in qauxes:
        eprint(f"[+] trying q_aux={qaux}")
        maps = []
        ok = True
        for idx, inst in enumerate(instances):
            t0 = time.time()
            mp = enumerate_plain_candidates(inst, qaux, args.charset, args.pair_bound,
                                            args.max_k, args.keep, args.verbose)
            eprint(f"    instance {idx}: {len(mp)} plaintext candidates in {time.time() - t0:.2f}s")
            if not mp:
                ok = False
                break
            maps.append(mp)
        if not ok:
            continue
        L, ranked = common_prefix_rank(maps, args.min_len, enc_len)
        if ranked:
            eprint(f"[+] common prefix length={L}, {len(ranked)} candidate(s)")
            for score, pref in ranked[:10]:
                body = pref.decode("latin-1", "replace")
                eprint(f"    score={score:4d}  HCMUS-CTF{{{body}}}")
            best_global = (qaux, L, ranked)
            break

    if best_global is None:
        raise SystemExit("no common plaintext found; try --instances 6 --max-k 8 --keep 100000 --pair-bound 200")

    qaux, L, ranked = best_global
    body = ranked[0][1].decode("latin-1", "replace")
    stripped = strip_hex_padding(body)
    print(f"[+] q_aux={qaux}, common_len={L}, score={ranked[0][0]}")
    print(f"[+] raw body: {body}")
    if stripped != body:
        print(f"[+] stripped body: {stripped}")
        body = stripped
    print(f"HCMUS-CTF{{{body}}}")


def main():
    ap = argparse.ArgumentParser(description="Solve Funny Helicopter Morphology - 2")
    ap.add_argument("host", nargs="?", default="chall.blackpinker.com")
    ap.add_argument("port", nargs="?", type=int, default=20941)
    ap.add_argument("--instances", type=int, default=5, help="good independent instances to collect")
    ap.add_argument("--tries", type=int, default=80)
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--sleep", type=float, default=0.05)
    ap.add_argument("--upper-slack", type=int, default=1 << 22, help="q_aux may be slightly above printed main q0")
    ap.add_argument("--lift-limit", type=int, default=1_000_000)
    ap.add_argument("--qaux", action="append", type=int, default=[], help="manual aux prime; may repeat")
    ap.add_argument("--scan-qaux", type=int, default=10000)
    ap.add_argument("--pair-bound", type=int, default=100)
    ap.add_argument("--max-k", type=int, default=5, help="Gaussian K bound; use 6 or 8 if unlucky (slower)")
    ap.add_argument("--keep", type=int, default=50000, help="keep this many best plaintext candidates per instance")
    ap.add_argument("--min-len", type=int, default=6, help="minimum common flag-body length to report")
    ap.add_argument("--charset", default=DEFAULT_CHARSET)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    solve(args)


if __name__ == "__main__":
    main()
