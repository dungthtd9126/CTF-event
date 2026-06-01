# elite_ball_knowledge write-up

Flag: `grey{3l1t3_b4lL_kn0wLedge_is_just_more_syscalls}`

## Summary

The binary is a static, non-PIE x86-64 ELF with a trivial stack overflow:

```c
char buf[0x10];
fgets(buf, 0x676700, stdin);
setup_sandbox();
return 0;
```

The overflow happens before seccomp is installed, but control returns through the smashed stack after seccomp is live.

The challenge seccomp filter deny-lists syscall numbers `0..335`, except:

- `60` (`exit`)
- `231` (`exit_group`)

Everything above `335` is still allowed. That leaves newer syscalls like:

- `io_uring_setup` (`425`)
- `io_uring_enter` (`426`)
- `close_range` (`436`)
- `openat2` (`437`)

The intended solve is to ROP into newer syscalls and use `io_uring` to perform the blocked old ones indirectly.

## Binary facts

- `main = 0x40187d`
- `setup_sandbox = 0x401775`
- useful raw syscall gadget: `0x4558f9` (`syscall ; ret`)
- useful gadgets:
  - `pop rdi ; ret = 0x403873`
  - `pop rsi ; ret = 0x4023e8`
  - `pop rdx ; pop rbx ; ret = 0x48d1cb`
  - `pop rax ; ret = 0x425d4c`
  - `mov [rsi], rax ; ret = 0x459545`

The ELF advertises `IBT, SHSTK` in GNU properties, but `x86_Thread_features` is empty at runtime in the provided jail, so CET is not actually enabled there.

## Important runtime details

The Dockerfile copies the flag to `/srv/app/flag.txt`, and `pwn.red/jail` bind-mounts `/srv` to `/`, so inside the jail the correct path is:

`/app/flag.txt`

The provided `nsjail` wrapper also matters for the exploit client:

- if the Python client does `shutdown(SHUT_WR)` right after sending the payload, the jailed child gets killed
- keeping the socket write side open while reading fixes this

That was a real bug in the earlier solver attempts.

## Exploitation plan

1. Overflow the stack and ROP after `setup_sandbox()`.
2. Call `close_range(3, 0xffffffff, 0)` to stabilize fd allocation.
3. Call `io_uring_setup()` with `IORING_SETUP_NO_MMAP`.
4. Build SQ/CQ memory and SQEs in writable global memory.
5. Submit:
   - linked `IORING_OP_OPENAT` for `/app/flag.txt`
   - `IORING_OP_READ` from fd `4` into a buffer
   - `IORING_OP_WRITE` to fd `1`
6. Read the flag from the socket.

After `close_range(3, ...)`, the fd model becomes:

- `0` stdin
- `1` stdout
- `2` stderr
- `3` io_uring fd
- `4` opened flag fd

## The two bugs that mattered

### 1. Bad writable addresses

Early payloads placed ring state in low `.bss`, assuming it was scratch space.

That was wrong. In this static glibc binary, low `.bss` contains live globals. For example:

- stdio locks
- loader state
- locale state

Using addresses like `0x4e3400` and `0x4e4000` corrupted real state.

The fix was to move all exploit state into the `__pthread_keys` slab:

- `__pthread_keys = 0x4e4240`
- size `0x4000`

Final layout:

- `RING = 0x4e5000`
- `SQES = 0x4e6000`
- `PARAM = 0x4e7000`
- `PATH = 0x4e7100`
- `BUF = 0x4e7200`

### 2. Half-closing the remote socket

The local bare binary and `docker exec` path both worked even with:

```python
s.shutdown(socket.SHUT_WR)
```

But the real jail listener did not. Removing that line made the exploit work immediately against both:

- local `pwn.red/jail`
- remote challenge service

## Final solver

The working solver is:

- [solve_elite_ball_knowledge_v14.py](/home/saitomu/Downloads/grey-cat/elite/dist-elite_ball_knowledge/solve_elite_ball_knowledge_v14.py)

Local jail test:

```bash
python3 solve_elite_ball_knowledge_v14.py 127.0.0.1 5001 --flag-path /app/flag.txt --read-len 0x40
```

Remote solve:

```bash
python3 solve_elite_ball_knowledge_v14.py elijah-balls.chal.zip 32267 --flag-path /app/flag.txt --read-len 0x80
```

## Why this works

The seccomp policy is a deny-list over old syscall numbers, not a true allow-list. That leaves the modern `io_uring` interface available. Once `io_uring_setup` and `io_uring_enter` are reachable through ROP, the kernel performs the actual open/read/write operations on the process's behalf, which bypasses the direct syscall ban in userland.

That is the whole trick here: elite ball knowledge is just knowing which newer syscalls still do the old work.
