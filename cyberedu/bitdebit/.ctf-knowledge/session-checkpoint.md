# bitdebit2 checkpoint

- Objective: solve the provided local pwn challenge; no outside remote.
- Status: solved and locally validated.
- Artifact: `chall`, supplied `libc.so.6`, `ld-2.39.so`.
- Solver: `quang/solve.py`; command `GAP=0 NBYTES=10 JOBS=4 python3 quang/solve.py`.
- Confirmed chain: one-bit write -> libc leak -> `_IO_list_all` -> fake FILE -> `setcontext+61` -> RWX `mmap` -> shellcode -> timing oracle.
- Seccomp: syscall numbers `9` and `295`; no architecture check; `openat` via i386 ABI and `preadv` via x86-64 ABI.
- Validation: outside outer harness, trace reached `mmap`, `openat`, `preadv`, intentional `SIGILL`; full oracle recovered local result.
- Known environment issue: inherited sandbox seccomp causes misleading `SIGSYS` before chain completion.
- Required artifacts: `solve.md`, `write_up_train/bitdebit2/wu.md`, metadata, attempts, knowledge entries, index, episodes.
