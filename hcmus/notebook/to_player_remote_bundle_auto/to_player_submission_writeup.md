# to_player - Short Write-up

## Summary

The bug is in the custom allocator used by `NoteBook`. During backward consolidation, the allocator updates the next chunk's `priv_size` with the size of the **original** chunk instead of the size of the **merged** chunk. This lets us create two overlapping free chunks. From there, we turn `book 1` metadata into controlled data, build an arbitrary read, leak addresses, and finally overwrite `__exit_funcs` so that exiting the program runs `system("cat flag")`.

## 1. Building the overlap

For each scan group, the exploit allocates four chunks in `book 0`:

- `A = 0x170`
- `B = 0x170`
- `C = 0x2f0`
- `D = 0xf0`

Then it frees `B`, `A`, and `C` in that order. Because of the broken consolidation, this produces overlapping free chunks. The script then switches to another book and reallocates a `0x2f0` chunk on `book 0`, so the new writer chunk overlaps the `Note[]` array of the other book. In the script this is done by `setup_group()` and repeated in `setup_scan_groups()`.

## 2. Arbitrary read from forged notes

Each forged `Note` is just:

- `size`
- `data`

When the program reads a note, it effectively does `write(1, data, size)`. So if we overwrite note metadata with `(size, addr)`, we can leak memory from any readable address. The helper functions for this are:

- `writer_payload()` to forge note entries
- `leak_specs()` / `leak()` / `leak_qword()` to batch memory reads
- `read_menu_batch()` to make the leak fast enough remotely

## 3. Finding stack, PIE, and libc

The exploit does not rely on `/proc`.

First, it scans the high user-space range for any readable address with `probe_readable()` and `find_stack_anchor()`. Once it finds one hit, it refines nearby pages with `refine_stack_mapping()` and dumps the whole stack region with `dump_stack()`.

Then `find_auxv_and_pie()` parses `auxv` from the dumped stack and uses `AT_PHDR - e_phoff` to recover the PIE base.

After PIE is known, the exploit leaks `write@GOT` and walks backward page by page with `find_elf_base()` until it finds the ELF header of libc.

## 4. Recovering `pointer_guard`

glibc mangles function pointers stored in `__exit_funcs` as:

`rol(real_function ^ pointer_guard, 17)`

The script leaks `__exit_funcs`, looks for an existing destructor entry that points back into the PIE, and recovers `pointer_guard` using the known binary destructor offset (`CAGE_DTOR_OFFSET`). This is implemented in `recover_pointer_guard()`.

## 5. Overwriting `__exit_funcs`

The final stage is in `final_overwrite()`.

The exploit leaks `books[0]` and the current writer chunk pointer, then uses that writer chunk to place:

- a fake exit handler list
- the string `"cat flag"`
- a fake chunk header

Next it forces the custom allocator to split a large chunk so that the remainder lands on top of `__exit_funcs`. A final allocation writes a pointer to the fake exit-handler list.

The forged exit entry is set up so that when the program exits, glibc executes:

`system("cat flag")`

Finally, the script sends menu option `6` to trigger normal program termination and print the flag.

## Exploit flow

1. Create overlapping free chunks with the custom allocator bug.
2. Overlap a writer chunk with another book's `Note[]` metadata.
3. Forge notes to get arbitrary read.
4. Scan readable memory to locate the stack.
5. Parse `auxv` to recover PIE.
6. Leak `write@GOT` and recover libc base.
7. Recover `pointer_guard` from `__exit_funcs`.
8. Overwrite `__exit_funcs` with a fake list containing `system("cat flag")`.
9. Exit the program to execute the handler.

## Run

```bash
python3 solve.py --host chall.blackpinker.com --port 20767
```
