# cage

Category: `pwn`

Status: local exploit chain verified, remote flag not recovered yet.

## Challenge Summary

The binary is a fork-per-connection service. `main()` creates a shared anonymous RW `mmap(0x100000)` once, listens on TCP port `5000`, then forks a child for each client:

- parent keeps accepting
- child closes the listening socket
- child runs `setgid(counter)` then `setuid(counter)`
- child handles request opcodes in a loop

Protections:

- PIE
- Full RELRO
- Canary
- NX
- stripped

Relevant files that were checked:

- `prob`
- `libc.so.6`
- `ld-2.39.so`
- `Dockerfile`
- `docker-compose.yml`

The Docker image runs the service as `root`, and the local `flag` file inside the container is world-readable.

## Opcode Map

Recovered handler behavior from disassembly:

- `op1`: parses a tiny TLV-like input and copies some fields into the reply header; not useful for exploitation
- `op2`: sets `state->off` from a big-endian dword if it is `<= state->size`
- `op3`: `memcpy(state->buf + state->off, user, len)` after bounds checks
- `op4`: `memcpy(state + 0x20 + state->off, user, len)` with only `len <= 0x20`
- `op5`: returns up to `0x20` bytes from `state + 0x20`
- `op6`: exits
- `op7`: copies a length-prefixed blob to `state + 0x48`, capped at `0x10`
- `op8`: returns 8 bytes built from `state->magic` and the dword at `state + 0x10`

## Bug

The heap `state` object contains:

- `state + 0x14`: current offset
- `state + 0x18`: logical size, initialized to `0x100000`
- `state + 0x20`: scratch area
- `state + 0x40`: pointer to the shared 1 MB RW `mmap`

The exploit primitive comes from composing `op4` and `op3`:

1. `op4` writes to `state + 0x20 + off`.
2. If `off = 0x20`, that destination becomes `state + 0x40`.
3. `state + 0x40` is the live `buf` pointer used by `op3`.
4. After overwriting `buf`, `op3` becomes an arbitrary write to `buf + off`.

So the service gives a reliable arbitrary write without any read primitive.

## Useful Observations

### Shared mmap and libc relation

In every exact-environment container that was checked:

- the service's shared anonymous RW `mmap` is directly below libc
- `mmap_base + 0x103000 == libc_base`

That matches the container's live mappings and the provided `libc.so.6`.

### libc offsets

The provided `libc.so.6` matches the deployed libc offsets that were observed locally:

- `read = 0x11ba80`
- `open = 0x11b150`
- `write = 0x11c590`
- `exit = 0x47ba0`
- `syscall = 0x127270`

Usable `syscall; ret` gadgets exist in the provided libc. The one used successfully is:

- `syscall; ret = 0x98fb6`

### No easy arbitrary read

`op5` only returns data from `state + 0x20` and cannot be redirected to arbitrary memory with the discovered bug. `op8` only leaks 8 bytes derived from fixed state fields. So the working path is blind write + control-flow hijack, not leak + ROP.

## Working Exploit Path

The clean chain that works locally is:

1. Find the live `op3` saved return address on the child stack.
2. Find the shared RW `mmap`.
3. Derive `libc_base = mmap_base + 0x103000`.
4. Overwrite the current `op3` saved RIP with absolute `libc read`.
5. Write `syscall; ret` and a full `rt_sigreturn` frame immediately after it on the same stack.
6. Send 15 bytes so the hijacked `read()` returns `rax = 15`.
7. `syscall; ret` executes `rt_sigreturn`.
8. The sigreturn frame performs:

```c
execve("/bin/sh", ["sh", "-c", "cat /home/pwn/flag >&4"], NULL)
```

That writes the flag to the accepted socket directly.

### Shell variant

If interactive shell is preferred over printing the flag directly, the same SROP path can use:

```sh
exec 0<&4 1>&4 2>&4; exec /bin/sh -i
```

inside the `sh -c` command string. The accepted client socket is fd `4` in the child.

## Local Validation

The final libc-only SROP chain was validated end to end against one exact-environment container instance.

Known-good command:

```bash
python3 exploit.py 127.0.0.1 5003 --saved-rip 0x7ffd3f27ff98 --libc-base 0x7fdcd5977000 --timeout 1.5
```

Observed output:

```text
HCMUS-CTF{fake_local_flag}
```

This proves the final payload and libc offsets are correct.

## Saved RIP Offsets Observed Locally

This is the main blocker for fully blind remote exploitation.

The exact live `op3` saved RIP is not stable across fresh process trees. Measured local values:

| Environment | stack_end | op3 saved RIP | offset |
| --- | --- | --- | --- |
| `cage-debug` on `5003` | `0x7ffd3f282000` | `0x7ffd3f27ff98` | `0x2068` |
| `cage-local` on `5001` | `0x7ffe9e67c000` | `0x7ffe9e6793a8` | `0x2c58` |
| `cage-stable` on `5002` | `0x7ffc15a9e000` | `0x7ffc15a9b298` | `0x2d68` |
| `cage-gdb` launched via `docker exec -d` on `5004` | `0x7ffe38d6f000` | `0x7ffe38d6c378` | `0x2c88` |

So the exploit cannot hardcode a single `stack_end - const` and expect it to work remotely.

## What `exploit.py` Currently Does

The current script already contains the correct final payload and helper probes:

- arbitrary-write packet helpers
- writable-address probing
- saved-RIP probing
- mmap/libc discovery
- SROP payload construction

The known-good local path is the direct one:

- overwrite saved RIP with absolute `libc read`
- place `syscall; ret`
- place `SigreturnFrame`
- return into `read`
- force `rax = 15`
- let `rt_sigreturn` drive `execve`

## Remote Blocker

The remaining failure is discovery cost, not payload correctness.

Two issues remain:

1. The exact live `op3` saved RIP moves by a few KB between process trees.
2. The current online search strategy in `exploit.py` still needs to rediscover:
   - the high stack mapping
   - the exact saved-RIP slot
   - the shared RW `mmap` below libc

The original scan direction was too expensive for the remote service because it searched canonical ranges from low addresses upward. A practical next revision should:

- scan the stack range from high addresses downward
- scan the shared-library range from high addresses downward
- keep the shell payload but trim the script around that path

## Commands Used

Primary remote target:

```bash
nc chall.blackpinker.com 20647
```

Current exploit entrypoint:

```bash
python3 exploit.py chall.blackpinker.com 20647
```

## Conclusion

What is solved:

- vulnerability identified
- arbitrary write confirmed
- libc relation confirmed
- SROP payload confirmed
- local flag path confirmed

What is not solved yet:

- reliable remote auto-discovery of the live `op3` saved RIP and shared `mmap` quickly enough to finish against the challenge server
