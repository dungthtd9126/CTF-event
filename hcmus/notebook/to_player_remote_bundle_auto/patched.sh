#!/usr/bin/env bash
set -euo pipefail

src="${1:-prob}"
out="${2:-prob_patched}"
old_interp="/lib64/ld-linux-x86-64.so.2"
new_interp="./libs/ld-linux-x86-64.so.2"
loader="libs/ld-linux-x86-64.so.2"
runpath="\$ORIGIN/libs"

if [[ ! -f "$src" ]]; then
    echo "missing source binary: $src" >&2
    exit 1
fi

if [[ ! -x "$loader" ]]; then
    echo "missing executable loader: $loader" >&2
    exit 1
fi

if [[ ${#old_interp} -ne ${#new_interp} ]]; then
    echo "interpreter strings must be the same length for in-place patching" >&2
    exit 1
fi

python3 - "$src" "$out" "$old_interp" "$new_interp" "$runpath" <<'PY'
import shutil
import struct
import sys

src, out, old_interp, new_interp, runpath = sys.argv[1:]

PT_LOAD = 1
PT_DYNAMIC = 2
PT_NOTE = 4
PF_R = 4
DT_NULL = 0
DT_STRTAB = 5
DT_STRSZ = 10
DT_RUNPATH = 0x1D


def align_up(value, align):
    return (value + align - 1) & ~(align - 1)


def unpack_from(fmt, data, offset):
    return struct.unpack_from(fmt, data, offset)


def pack_into(fmt, data, offset, *values):
    struct.pack_into(fmt, data, offset, *values)


shutil.copyfile(src, out)
with open(out, "r+b") as f:
    data = bytearray(f.read())

    old = old_interp.encode() + b"\0"
    new = new_interp.encode() + b"\0"
    if len(old) != len(new):
        raise SystemExit("interpreter strings must be the same length")
    if data.count(old) != 1:
        raise SystemExit("interpreter string not found exactly once")
    interp_off = data.index(old)
    data[interp_off:interp_off + len(old)] = new

    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit("expected little-endian ELF64")

    e_phoff = unpack_from("<Q", data, 32)[0]
    e_shoff = unpack_from("<Q", data, 40)[0]
    e_phentsize = unpack_from("<H", data, 54)[0]
    e_phnum = unpack_from("<H", data, 56)[0]
    e_shentsize = unpack_from("<H", data, 58)[0]
    e_shnum = unpack_from("<H", data, 60)[0]
    e_shstrndx = unpack_from("<H", data, 62)[0]
    if e_phentsize != 56:
        raise SystemExit("unexpected program header size")
    if e_shentsize not in (0, 64):
        raise SystemExit("unexpected section header size")

    phdrs = []
    for index in range(e_phnum):
        off = e_phoff + index * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = unpack_from(
            "<IIQQQQQQ", data, off
        )
        phdrs.append({
            "index": index,
            "off": off,
            "type": p_type,
            "flags": p_flags,
            "offset": p_offset,
            "vaddr": p_vaddr,
            "paddr": p_paddr,
            "filesz": p_filesz,
            "memsz": p_memsz,
            "align": p_align,
        })

    loads = [ph for ph in phdrs if ph["type"] == PT_LOAD]
    dynamic = next((ph for ph in phdrs if ph["type"] == PT_DYNAMIC), None)
    carrier = next((ph for ph in phdrs if ph["type"] == PT_NOTE), None)
    if dynamic is None:
        raise SystemExit("PT_DYNAMIC not found")
    if carrier is None:
        raise SystemExit("no PT_NOTE header available for dynstr carrier")

    def vaddr_to_offset(vaddr):
        for ph in loads:
            start = ph["vaddr"]
            end = start + ph["filesz"]
            if start <= vaddr < end:
                return ph["offset"] + (vaddr - start)
        raise SystemExit(f"virtual address 0x{vaddr:x} is not file-backed")

    dyn_off = dynamic["offset"]
    dyn_count = dynamic["filesz"] // 16
    dyn_entries = []
    for i in range(dyn_count):
        entry_off = dyn_off + i * 16
        tag, val = unpack_from("<QQ", data, entry_off)
        dyn_entries.append((entry_off, tag, val))

    strtab_entry = next((entry for entry in dyn_entries if entry[1] == DT_STRTAB), None)
    strsz_entry = next((entry for entry in dyn_entries if entry[1] == DT_STRSZ), None)
    null_entry = next((entry for entry in dyn_entries if entry[1] == DT_NULL), None)
    if strtab_entry is None or strsz_entry is None:
        raise SystemExit("DT_STRTAB/DT_STRSZ not found")
    if null_entry is None:
        raise SystemExit("DT_NULL slot not found")

    old_strtab_vaddr = strtab_entry[2]
    old_strsz = strsz_entry[2]
    old_strtab_off = vaddr_to_offset(old_strtab_vaddr)
    old_dynstr = bytes(data[old_strtab_off:old_strtab_off + old_strsz])
    if not old_dynstr.endswith(b"\0"):
        raise SystemExit("dynamic string table is not NUL-terminated")

    runpath_bytes = runpath.encode() + b"\0"
    runpath_offset = len(old_dynstr)
    new_dynstr = old_dynstr + runpath_bytes

    new_offset = align_up(len(data), 0x1000)
    new_vaddr = align_up(max(ph["vaddr"] + ph["memsz"] for ph in loads), 0x1000)

    if len(data) < new_offset:
        data.extend(b"\0" * (new_offset - len(data)))
    data.extend(new_dynstr)

    pack_into("<QQ", data, strtab_entry[0], DT_STRTAB, new_vaddr)
    pack_into("<QQ", data, strsz_entry[0], DT_STRSZ, len(new_dynstr))
    pack_into("<QQ", data, null_entry[0], DT_RUNPATH, runpath_offset)

    pack_into(
        "<IIQQQQQQ",
        data,
        carrier["off"],
        PT_LOAD,
        PF_R,
        new_offset,
        new_vaddr,
        new_vaddr,
        len(new_dynstr),
        len(new_dynstr),
        0x1000,
    )

    if e_shoff and e_shentsize == 64 and e_shnum and e_shstrndx < e_shnum:
        shstr_off = e_shoff + e_shstrndx * e_shentsize
        _, _, _, _, shstr_offset, shstr_size, _, _, _, _ = unpack_from("<IIQQQQIIQQ", data, shstr_off)
        shstr = bytes(data[shstr_offset:shstr_offset + shstr_size])

        for index in range(e_shnum):
            sh_off = e_shoff + index * e_shentsize
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = unpack_from(
                "<IIQQQQIIQQ", data, sh_off
            )
            name_end = shstr.find(b"\0", sh_name)
            if name_end == -1:
                continue
            name = shstr[sh_name:name_end]
            if name == b".dynstr":
                pack_into(
                    "<IIQQQQIIQQ",
                    data,
                    sh_off,
                    sh_name,
                    sh_type,
                    sh_flags,
                    new_vaddr,
                    new_offset,
                    len(new_dynstr),
                    sh_link,
                    sh_info,
                    sh_addralign,
                    sh_entsize,
                )
                break

    f.seek(0)
    f.write(data)
    f.truncate()
PY

chmod +x "$out"

echo "patched $out"
echo "interpreter: $new_interp"
echo "runpath: $runpath"
