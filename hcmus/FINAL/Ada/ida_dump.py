# IDA Python script: dump P2 images from reverse/Ada Lovelace .i64
# Usage GUI: open chall.i64 in IDA -> File -> Script file... -> choose this file
# Usage batch Linux: idat64 -A -S/path/to/ida_dump_p2_images.py /path/to/chall.i64
# Usage batch Windows: ida64.exe -A -S"C:\\path\\ida_dump_p2_images.py" "C:\\path\\chall.i64"
# Output: p2_dump/ next to the IDB/input path, with PNG/PBM/DOT/JSON candidates.
# Deps: none inside IDA. Graphviz is optional for rendering DOT.

from __future__ import annotations

import os
import sys
import json
import math
import struct
import zlib
import shutil
import subprocess
from typing import Dict, Iterable, List, Tuple

try:
    import idaapi
    import idautils
    import ida_bytes
    import ida_funcs
    import ida_idaapi
    import ida_kernwin
    import ida_loader
    import ida_name
    import ida_ua
except Exception as e:
    print("[!] This script must be run inside IDA Python")
    print("    error:", e)
    raise

# Switch/junk function recovered from the IDB.
SWITCH_TABLE = 0x0804EE80
SWITCH_CASES = 41
SWITCH_DISPATCH = 0x0804EF40
REGION_START = 0x0804EF40
REGION_END   = 0x08057110

WIDTHS = [16, 20, 21, 26, 29, 32, 40, 41, 52, 58, 73, 80, 104, 130]


def msg(s: str) -> None:
    try:
        ida_kernwin.msg(s + "\n")
    except Exception:
        print(s)


def get_outdir() -> str:
    forced = os.environ.get("IDA_P2_OUT")
    if forced:
        out = forced
    else:
        # Best effort: put p2_dump next to the IDB, else cwd.
        base = None
        for getter in (
            lambda: ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
            lambda: ida_loader.get_path(ida_loader.PATH_TYPE_ID0),
            lambda: idaapi.get_input_file_path(),
        ):
            try:
                p = getter()
                if p:
                    base = os.path.dirname(os.path.abspath(p))
                    break
            except Exception:
                pass
        if not base:
            base = os.getcwd()
        out = os.path.join(base, "p2_dump")
    os.makedirs(out, exist_ok=True)
    return out


def read_bytes(ea: int, n: int) -> bytes:
    b = ida_bytes.get_bytes(ea, n)
    return b or b""


def get_dword(ea: int) -> int:
    return ida_bytes.get_dword(ea) & 0xFFFFFFFF


def decode_insn_size(ea: int) -> int:
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea):
        return int(insn.size)
    return 0


def get_mnem(ea: int) -> str:
    try:
        return idaapi.print_insn_mnem(ea).lower()
    except Exception:
        return ""


def is_jump_mnem(m: str) -> bool:
    # keep direct conditional jumps and direct jmp; skip calls/returns.
    return m.startswith("j")


def is_cond_jump(m: str) -> bool:
    return m.startswith("j") and m != "jmp"


def collect_cases() -> List[int]:
    cases = []
    for i in range(SWITCH_CASES):
        cases.append(get_dword(SWITCH_TABLE + 4 * i))
    return cases


def collect_branches() -> List[Dict[str, int | str]]:
    branches: List[Dict[str, int | str]] = []
    for ea in idautils.Heads(REGION_START, REGION_END):
        m = get_mnem(ea)
        if not is_jump_mnem(m):
            continue
        size = decode_insn_size(ea)
        if size <= 0:
            continue
        try:
            tgt = int(idaapi.get_operand_value(ea, 0)) & 0xFFFFFFFF
        except Exception:
            tgt = 0
        # Ignore indirect dispatch jmp and non-local jumps unless useful.
        direct_local = REGION_START <= tgt < REGION_END
        if not direct_local:
            continue
        data = read_bytes(ea, size)
        disp = (tgt - (ea + size)) & 0xFFFFFFFF
        branches.append({
            "ea": ea,
            "mnem": m,
            "size": size,
            "target": tgt,
            "disp": disp,
            "bytes_hex": data.hex(),
            "cond": 1 if is_cond_jump(m) else 0,
        })
    branches.sort(key=lambda x: int(x["ea"]))
    return branches


def write_png_gray(path: str, pixels: List[List[int]], scale: int = 8, border: int = 2, invert: bool = False) -> None:
    """Write a no-dependency 8-bit grayscale PNG. pixels values: 0/1 or 0..255."""
    if not pixels:
        pixels = [[0]]
    h = len(pixels)
    w = max(len(r) for r in pixels)
    # Normalize to rectangular, scale, and add border.
    out_w = w * scale + border * 2
    out_h = h * scale + border * 2
    bg = 255
    img = bytearray([bg] * (out_w * out_h))
    for y, row in enumerate(pixels):
        for x in range(w):
            v = row[x] if x < len(row) else 0
            if v in (0, 1):
                val = 0 if v else 255
            else:
                val = max(0, min(255, int(v)))
            if invert:
                val = 255 - val
            for yy in range(y * scale + border, (y + 1) * scale + border):
                off = yy * out_w + x * scale + border
                img[off:off + scale] = bytes([val]) * scale
    raw = bytearray()
    for y in range(out_h):
        raw.append(0)  # filter type 0
        raw.extend(img[y * out_w:(y + 1) * out_w])

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", out_w, out_h, 8, 0, 0, 0, 0))  # grayscale
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def bits_to_rows(bits: List[int], width: int) -> List[List[int]]:
    rows = []
    for i in range(0, len(bits), width):
        row = bits[i:i + width]
        if len(row) < width:
            row = row + [0] * (width - len(row))
        rows.append(row)
    return rows


def transpose(rows: List[List[int]]) -> List[List[int]]:
    if not rows:
        return rows
    h, w = len(rows), len(rows[0])
    return [[rows[y][x] for y in range(h)] for x in range(w)]


def pack_bits(bits: List[int], msb: bool = False) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        v = 0
        for j in range(8):
            if msb:
                v |= (bits[i + j] & 1) << (7 - j)
            else:
                v |= (bits[i + j] & 1) << j
        out.append(v)
    return bytes(out)


def bit(v: int, k: int) -> int:
    return (v >> k) & 1


def make_bitstreams(branches: List[Dict[str, int | str]]) -> Dict[str, List[int]]:
    streams: Dict[str, List[int]] = {}
    eas = [int(b["ea"]) for b in branches]
    tgts = [int(b["target"]) for b in branches]
    disps = [int(b["disp"]) for b in branches]
    sizes = [int(b["size"]) for b in branches]
    conds = [int(b["cond"]) for b in branches]

    # Raw address/target/displacement bit planes.
    for k in range(16):
        streams[f"src_addr_bit{k}"] = [bit(ea, k) for ea in eas]
        streams[f"tgt_addr_bit{k}"] = [bit(t, k) for t in tgts]
        streams[f"disp_bit{k}"] = [bit(d, k) for d in disps]
        streams[f"delta17_bit{k}"] = [bit(((t - ea) // 17) & 0xFFFFFFFF, k) for ea, t in zip(eas, tgts)]

    # Bytes from the branch instruction itself.
    for byte_idx in range(6):
        for k in range(8):
            arr = []
            for b in branches:
                data = bytes.fromhex(str(b["bytes_hex"]))
                arr.append(bit(data[byte_idx], k) if byte_idx < len(data) else 0)
            streams[f"opcode_byte{byte_idx}_bit{k}"] = arr

    # Structural streams.
    streams["is_conditional_jump"] = conds
    streams["size_bit0"] = [bit(s, 0) for s in sizes]
    streams["size_bit1"] = [bit(s, 1) for s in sizes]

    # Case-like grouping by nearest case target lower bound.
    cases = collect_cases()
    cases_sorted = sorted(cases)
    def case_idx(ea: int) -> int:
        idx = 0
        for i, c in enumerate(cases_sorted):
            if ea >= c:
                idx = i
            else:
                break
        return idx
    csrc = [case_idx(ea) for ea in eas]
    ctgt = [case_idx(t) for t in tgts]
    for k in range(6):
        streams[f"src_case_bit{k}"] = [bit(c, k) for c in csrc]
        streams[f"tgt_case_bit{k}"] = [bit(c, k) for c in ctgt]
        streams[f"case_delta_bit{k}"] = [bit((b - a) & 0x3F, k) for a, b in zip(csrc, ctgt)]
    streams["same_case"] = [1 if a == b else 0 for a, b in zip(csrc, ctgt)]
    return streams


def write_stream_images(outdir: str, streams: Dict[str, List[int]]) -> List[Tuple[str, str, int, bool, bool]]:
    hits = []
    imgdir = os.path.join(outdir, "bitstreams")
    os.makedirs(imgdir, exist_ok=True)

    # Search p2 marker in both bit orders for all streams.
    for name, bits in streams.items():
        for msb in (False, True):
            payload = pack_bits(bits, msb=msb)
            marker = payload.find(b"p2{")
            if marker >= 0:
                ctx = payload[max(0, marker - 16):marker + 96]
                mode = "msb" if msb else "lsb"
                hits.append((name, mode, marker, False, False))
                with open(os.path.join(outdir, f"HIT_{name}_{mode}.bin"), "wb") as f:
                    f.write(payload)
                with open(os.path.join(outdir, f"HIT_{name}_{mode}.txt"), "wb") as f:
                    f.write(ctx)

    # Do not render thousands of files: render the likely/compact streams plus any hits.
    likely = set()
    for k in range(8):
        likely.update({
            f"src_addr_bit{k}", f"tgt_addr_bit{k}", f"disp_bit{k}",
            f"opcode_byte0_bit{k}", f"opcode_byte1_bit{k}",
            f"src_case_bit{k if k < 6 else 5}", f"tgt_case_bit{k if k < 6 else 5}",
        })
    likely.update(name for name, _, _, _, _ in hits)
    likely.update(["is_conditional_jump", "same_case"])

    for name in sorted(likely):
        bits = streams.get(name)
        if not bits:
            continue
        for width in WIDTHS:
            rows = bits_to_rows(bits, width)
            for inv in (False, True):
                write_png_gray(os.path.join(imgdir, f"{name}_w{width}_inv{int(inv)}.png"), rows, scale=6, border=2, invert=inv)
            # Transpose often helps if the hidden image is column-major.
            if len(rows) > 1 and len(rows[0]) > 1:
                tr = transpose(rows)
                write_png_gray(os.path.join(imgdir, f"{name}_w{width}_transpose_inv0.png"), tr, scale=6, border=2, invert=False)
                write_png_gray(os.path.join(imgdir, f"{name}_w{width}_transpose_inv1.png"), tr, scale=6, border=2, invert=True)
    return hits


def write_scatter_images(outdir: str, branches: List[Dict[str, int | str]]) -> None:
    imgdir = os.path.join(outdir, "scatter")
    os.makedirs(imgdir, exist_ok=True)
    eas = [int(b["ea"]) for b in branches]
    tgts = [int(b["target"]) for b in branches]
    base = min(min(eas), min(tgts)) if branches else REGION_START
    for div in [1, 2, 4, 8, 16, 17, 32, 64]:
        pts = [((t - base) // div, (ea - base) // div) for ea, t in zip(eas, tgts)]
        if not pts:
            continue
        maxx = max(x for x, _ in pts)
        maxy = max(y for _, y in pts)
        # Avoid gigantic images; skip too-large raw divs.
        if maxx > 4000 or maxy > 4000:
            continue
        rows = [[0 for _ in range(maxx + 1)] for __ in range(maxy + 1)]
        for x, y in pts:
            rows[y][x] = 1
        scale = 1 if max(maxx, maxy) > 800 else 2
        write_png_gray(os.path.join(imgdir, f"src_vs_tgt_div{div}_inv0.png"), rows, scale=scale, border=4, invert=False)
        write_png_gray(os.path.join(imgdir, f"src_vs_tgt_div{div}_inv1.png"), rows, scale=scale, border=4, invert=True)


def write_case_table_images(outdir: str, cases: List[int]) -> None:
    imgdir = os.path.join(outdir, "case_table")
    os.makedirs(imgdir, exist_ok=True)
    vals = cases
    # Bitplanes of 41 case target addresses.
    for src_name, nums in [("case_target", vals), ("case_offset", [v - min(vals) for v in vals])]:
        for k in range(16):
            bits = [bit(v, k) for v in nums]
            for width in [8, 16, 20, 41]:
                rows = bits_to_rows(bits, width)
                write_png_gray(os.path.join(imgdir, f"{src_name}_bit{k}_w{width}_inv0.png"), rows, scale=10, border=2, invert=False)
                write_png_gray(os.path.join(imgdir, f"{src_name}_bit{k}_w{width}_inv1.png"), rows, scale=10, border=2, invert=True)


def write_dot(outdir: str, branches: List[Dict[str, int | str]]) -> None:
    dot_path = os.path.join(outdir, "switch_branch_edges.dot")
    with open(dot_path, "w", encoding="utf-8") as f:
        f.write("digraph switch_jumps {\n")
        f.write("  rankdir=LR;\n")
        f.write("  node [shape=point,width=0.05,label=\"\"];\n")
        for b in branches:
            ea = int(b["ea"])
            tgt = int(b["target"])
            color = "black" if b["mnem"] == "jmp" else "gray40"
            f.write(f"  n{ea:x} -> n{tgt:x} [color={color}];\n")
        f.write("}\n")
    # Optional render via graphviz if available in IDA environment.
    dot = shutil.which("dot")
    sfdp = shutil.which("sfdp")
    if dot:
        try:
            subprocess.run([dot, "-Tpng", dot_path, "-o", os.path.join(outdir, "switch_branch_edges_dot.png")], check=False)
        except Exception as e:
            msg(f"[!] dot render failed: {e}")
    if sfdp:
        try:
            subprocess.run([sfdp, "-Tpng", dot_path, "-o", os.path.join(outdir, "switch_branch_edges_sfdp.png")], check=False)
        except Exception as e:
            msg(f"[!] sfdp render failed: {e}")


def dump_json(outdir: str, cases: List[int], branches: List[Dict[str, int | str]], hits: List[Tuple[str, str, int, bool, bool]]) -> None:
    data = {
        "switch_table": hex(SWITCH_TABLE),
        "switch_dispatch": hex(SWITCH_DISPATCH),
        "region": [hex(REGION_START), hex(REGION_END)],
        "cases": [hex(x) for x in cases],
        "branch_count": len(branches),
        "branches": branches,
        "marker_hits": [{"stream": a, "bit_order": b, "offset": c} for a, b, c, _, _ in hits],
    }
    with open(os.path.join(outdir, "p2_dump.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main() -> None:
    outdir = get_outdir()
    msg(f"[*] output dir: {outdir}")
    msg("[*] waiting for IDA auto-analysis...")
    try:
        idaapi.auto_wait()
    except Exception:
        pass

    cases = collect_cases()
    branches = collect_branches()
    msg(f"[*] switch cases: {len(cases)}")
    msg(f"[*] direct local jumps collected: {len(branches)}")
    if len(branches) < 100:
        msg("[!] very few jumps collected; check REGION_START/REGION_END or re-run after analysis finishes")

    with open(os.path.join(outdir, "cases.txt"), "w", encoding="utf-8") as f:
        for i, ea in enumerate(cases):
            f.write(f"case {i:02d}: 0x{ea:08x}\n")
    with open(os.path.join(outdir, "branches.txt"), "w", encoding="utf-8") as f:
        for b in branches:
            f.write(f"0x{int(b['ea']):08x} {b['mnem']:4s} 0x{int(b['target']):08x} size={int(b['size'])} disp=0x{int(b['disp']):08x} bytes={b['bytes_hex']}\n")

    write_dot(outdir, branches)
    write_scatter_images(outdir, branches)
    write_case_table_images(outdir, cases)
    streams = make_bitstreams(branches)
    hits = write_stream_images(outdir, streams)
    dump_json(outdir, cases, branches, hits)

    if hits:
        msg("[+] found p2{ marker in bitstream(s):")
        for name, mode, off, _, _ in hits:
            msg(f"    stream={name} bit_order={mode} byte_offset={off}")
            txt = os.path.join(outdir, f"HIT_{name}_{mode}.txt")
            try:
                ctx = open(txt, "rb").read()
                msg(f"    context={ctx!r}")
            except Exception:
                pass
    else:
        msg("[*] no ASCII p2{ marker found in simple bitstreams; inspect PNGs/DOT under p2_dump/")

    msg("[*] done")
    if os.environ.get("IDA_P2_BATCH") == "1":
        try:
            import ida_pro
            ida_pro.qexit(0)
        except Exception:
            ida_idaapi.qexit(0)


if __name__ == "__main__":
    main()