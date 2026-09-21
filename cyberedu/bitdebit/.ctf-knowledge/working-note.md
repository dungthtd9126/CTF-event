# bitdebit2 working note

## Objective

Validate the local FSOP exploit and recover the supplied local challenge result without outside remote connections.

## Confirmed

- `chall` is x86-64 PIE with Full RELRO, canary, NX, and CET markers.
- `malloc(0x10000000)` leak gives libc base with local `GAP=0`.
- One bit of `_IO_list_all` redirects exit-time flushing into the controlled mapping.
- Fake FILE -> `_IO_wfile_jumps` -> wide callback -> `setcontext+61` -> `mmap` -> ROP copy -> shellcode.
- Challenge seccomp allows syscall numbers `9` and `295` without an architecture check.
- Local trace showed `mmap`, i386 `openat`, x86-64 `preadv`, then intentional `SIGILL`.
- Full local oracle recovered the supplied 10-byte local result.

## Environment boundary

The Codex sandbox adds an outer seccomp policy. Sandboxed child runs returned `SIGSYS`; escalated local validation reached the intended `SIGILL`. No remote endpoint was used.

## Files

- `quang/solve.py`
- `solve.md`
- `write_up_train/bitdebit2/wu.md`
- `write_up_train/KNOWLEDGE.md`

## Next actions

1. Run artifact validators if desired.
2. Keep generalized entries free of challenge flag and one-off addresses.
