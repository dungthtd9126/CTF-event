# bmpcutter3 notes

## Classification

- Category: `pwn`
- Target: stripped PIE ELF, NX, canary, full RELRO, SHSTK, IBT
- Bundled runtime: `ld-2.39.so`, `libc.so.6`

## Root bug

- In tile pixel extraction (`0x2099` in the binary), row padding is computed as:
  - `pad = 4 - (raw & 3)`
- That is wrong for already aligned rows (`raw % 4 == 0`), where pad should be `0`.
- For `32bpp` tiles this always adds 4 extra bytes per row.
- Result: per-row copy overruns the destination tile buffer.

## Key reversing results

- `parse_bmp` validates the original BMP reasonably well.
- `make_bmp` (`0x1d85`) trusts tile header fields when reserializing:
  - allocates `bfSize`
  - copies 14-byte file header + 40-byte DIB header
  - copies `biSizeImage` bytes from `pixel_ptr` to `out + bfOffBits`
- That means a corrupted tile struct gives:
  - controlled `bfSize`
  - controlled `bfOffBits`
  - controlled `biSizeImage`
  - controlled `pixel_ptr`

## Stable heap leak already working

- Current reliable 2-turn setup:
  1. Turn 1: `5 x 64`, `24bpp`, split `1 / 5`
  2. Turn 2: `4 x 64`, `32bpp`, split `4 / 1`
- Turn 2 with `4x64 32bpp` gives 4-byte overflow per row.
- For per-tile height 16, total overflow is `0x40`, which corrupts tile0's struct and leaks heap.
- Observed turn-3 `0x110` reuse order after the stable leak:
  - `pixel3` = lowest reused chunk
  - `pixel2`
  - `pixel1`
  - `pixel0`
  - `tiles_array` = `pixel3 + 0x110 + 0x330`

More concretely from the current scaffold:

- `tiles_array = highest_leaked + 0x110`
- `pixel0 = highest_leaked`
- `pixel1 = next`
- `pixel2 = next`
- `pixel3 = lowest`

## Important glibc facts

- `_IO_2_1_stdout_` offset: `0x2045c0`
- `_IO_file_jumps` offset: `0x202030`
- `_IO_wfile_jumps` offset: `0x202228`
- `system` offset: `0x58750`

Observed locally:

- `stdout->vtable = _IO_file_jumps`
- `stdout->_chain` points into libc data
- `stdout->_wide_data` points into libc data
- `stdout->_wide_data->_wide_vtable = _IO_wfile_jumps`

## Working ptrace proof of concept

- `bmpcutter3_ptrace_flag.py` proves the exit-time primitive:
  - write command at `stdout`
  - set `stdout->vtable = _IO_wfile_jumps`
  - set `wide_data->_wide_vtable` to a fake table whose `__doallocate = system`
- This prints local `flag.txt` (currently fake in the bundle).

## More promising non-ptrace direction

- Turn 3 should still use `0x110` tile chunks, but with a better geometry than the old `4x64 / 4x1` leak layout.
- If each 32bpp tile is `1 x 64`, then:
  - correct image size = `0x100`
  - buggy copy size = `0x200`
  - overflow per tile = `0x100`
- That should let `pixel0` overwrite the full `0x100` tile-array chunk, i.e. all 4 tile structs, not just tile0.

If that holds, turn 3 can likely do multiple arbitrary writes.

## Candidate final strategy

Use partial overwrites only, avoiding an exact libc leak:

1. Write command string at `stdout`.
2. Partial-overwrite `stdout->vtable` from `_IO_file_jumps` to `_IO_wfile_jumps`.
3. Partial-overwrite `real_wide_data->_wide_vtable` from `_IO_wfile_jumps` to `stdout`.
4. Partial-overwrite `stdout->_chain` into a `system` candidate.

Reasoning:

- `_IO_wdoallocbuf` calls `fp->_wide_data->_wide_vtable[0x68/8](fp)`.
- If `_wide_vtable = stdout`, then slot `+0x68` resolves to `stdout->_chain`.
- If `stdout->_chain` is turned into `system`, `system(stdout)` runs the command stored at the start of `stdout`.

## Remaining blockers

- Need to confirm the `1 x 64` turn-3 layout/overwrite map precisely.
- Need a reliable target above the forged `make_bmp` allocation, because
  `bfOffBits` is an unsigned 32-bit addition.
- Need to confirm whether the last step only needs a brute-force over the 8 possible 2MB-alignment cases for libc.

Current guess:

- `_IO_file_jumps -> _IO_wfile_jumps` needs only a 2-byte partial overwrite.
- `wide_vtable -> stdout` should also need only a 2-byte partial overwrite.
- `chain -> system` likely needs 3 low bytes, with 8 candidates because libc base is 2MB-aligned.

## Correction after non-invasive gdb calibration

For the real glibc 2.39 run:

- forged `malloc(0x30000)` returned `0x7ffff7f87010`
- `_IO_2_1_stdout_` was `0x7ffff7e045c0`
- allocation is `0x182a50` bytes *above* stdout

Therefore the old direct-write idea using:

`out + bfOffBits = stdout`

does not work, because `bfOffBits` is unsigned and stdout is below the mmap
allocation.

The stack is above this allocation, so a forged output buffer can potentially
overwrite a saved return address instead. The next work item is calibrating and
stabilizing the relative mmap-to-stack offset, then checking whether turn 2 can
leak a stack pointer or whether a bounded brute force is practical.
