# simple_file_manager — fix for the failed Ubuntu 22.04 / glibc 2.35 exploit

The previous `*_final.py` script had the right **2.35 leak stage**, but the wrong **post-leak fake-directory layout**.

## What was wrong

After `writef(12, payload)`, the stale `fs[1]` pointer is interpreted as a **directory starting at the beginning of the file object**, not at the start of `payload`.

That means the layout under the fake directory is:

- `f2+0x00..0x17` = real file header written by `write_file()`
- `f2+0x18..`      = attacker-controlled `payload`

So if you want fake directory **slot 1** to point to fake chunk `A`, you must place `A` at `payload[0:8]`, because:

- dir slot 0 = `[f2+0x10]`
- dir slot 1 = `[f2+0x18]`  ← first 8 bytes of payload

The broken `*_final.py` version instead used a new `build_fake_dir_payload(fake_b, fake_a)` layout that put the wrong values at the wrong fake directory slots, so the later `readf(1)` / `writef(7)` sequence was no longer operating on the intended fake chunk.

## Correct fix

Keep the working old fake-dir / fake-chunk endgame from the earlier local script, and combine it with the corrected Ubuntu 22.04 leak stage:

1. Fill `tcache[0xa0]` with seven 0x78 files.
2. Free the large chunk to unsorted.
3. Free the target 0xa0 chunk while tcache is full.
4. `mkdir(1)` reuses that target chunk as a directory.
5. Stale-read slot 0 to leak:
   - `heap_page = u64(leak[0xc8:0xd0]) << 12`
   - `libc_base = u64(leak[0x528:0x530]) - 0x21a300`
6. Reallocate `BIG = heap_page + 0x880` for the fake FILE / wide-data / vtable blob.
7. Drain the seven real 0xa0 tcache entries.
8. Reallocate `F2 = heap_page + 0x340` as a controlled file.
9. Use the **old** payload so fake dir slot 1 points to:
   - `A = heap_page + 0x380`
10. Enter stale `fs[1]` with `cd(1)`.
11. Free fake chunk `A`, corrupt its tcache key through fake dir slot 7, free `A` again, then poison the 0xa0 tcache entry to land on `_IO_list_all`.
12. Exit and trigger the House-of-Apple2 flush path.

## Why this should fix your failure

Your failure happened after the script moved to the new `fake_b/fake_a` overlap path. The earlier script's UAF+double-free logic was internally consistent:

- fake dir slot 1 points to `A`
- fake dir slot 7 overlaps `A+8`, which is exactly where glibc stores the tcache key

That is the relationship the final script accidentally broke.

## New fixed script

Use:

```bash
python3 simple_file_manager_exploit_fix.py --strategy leak235_fixed
```

If you are running against the patched local Ubuntu 22.04 runtime:

```bash
python3 simple_file_manager_exploit_fix.py --bin ./prob_patched --libc ./libc.so.6 --strategy leak235_fixed
```

For remote:

```bash
python3 simple_file_manager_exploit_fix.py --host HOST --port PORT --libc ./libc.so.6 --strategy leak235_fixed
```

## Extra robustness added

The new script also does one more thing the earlier versions did not:

- it tries multiple aligned poison targets below `_IO_list_all` so the safe-linked encoded pointer does **not** contain scanf-whitespace bytes.

That avoids losing the `mkdir(2, <encoded>)` write when the encoded bytes contain spaces/newlines/tabs.

## Local validation status

Inside this sandbox I could validate the host-glibc path again, and it still reaches:

```text
PWNED
HCMUS_CTF{fake_flag}
```

I could not fully re-run the exact Ubuntu 22.04 `glibc 2.35` path here because the matching `libc.so.6` / `ld-linux-x86-64.so.2` pair was not uploaded into this environment.

So the honest status is:

- host path: re-validated
- 2.35 leak offsets: taken from the corrected earlier note
- main logic bug in the failed final script: fixed
- exact 2.35 runtime re-test in this sandbox: not possible without the matching runtime files
