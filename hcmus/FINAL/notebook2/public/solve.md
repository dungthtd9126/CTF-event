# notebook2

## Category

`pwn`

## Files inspected

- `prob`
- `prob_patched`
- `libc.so.6`
- `ld-2.39.so`
- `Dockerfile`
- `docker-compose.yml`
- `entrypoint.sh`
- `goodluck.bin`
- `solve.py`
- `notebook2_solve_local.py`
- `notebook2_solve_local_standalone.py`

## Service model

The binary is a threaded TCP server. Each accepted socket gets a dedicated thread and a per-connection slot in the global `conns` array.

Symbols and handlers from the binary:

- `do_create`
- `do_open`
- `do_edit`
- `do_view`
- `do_close`
- `do_list`
- `do_rename`
- `do_truncate`
- `do_stat`
- `do_copy`
- `handle_event`

The wire format is:

- magic: `0xbeef1337`
- outer length: 4 bytes
- inner type: 4 bytes
- payload length: 4 bytes
- payload

Observed control bits:

- `0x2000` for hub commands
- `0x10` channel bit
- low nibble is the opcode

Useful opcodes:

- `1` create
- `2` open
- `3` edit
- `4` view
- `5` close
- `6` list
- `7` rename
- `8` truncate
- `9` stat
- `10` copy

## Important structs

### Note

Reconstructed from `do_create` and related functions:

```c
struct note {
    char name[0x20];
    char token[0x20];
    uint32_t deleted;   // offset 0x40
    uint32_t size;      // offset 0x44
    void *content;      // offset 0x48
    struct note *next;  // offset 0x50
}; // size 0x58
```

### Connection slot

`conns` is `256 * 24` bytes, so each slot is 24 bytes:

- fd at offset `+0x0`
- active flag at offset `+0x4`
- thread handle / `pthread_t` at offset `+0x8`
- current open note pointer at offset `+0x10`

## Wrapper behavior

`entrypoint.sh` does two things:

1. starts `./prob 5000`
2. connects back once and sends `goodluck.bin`

`goodluck.bin` is just a valid `create` frame for a `goodluck` note with 16-byte content.

## Security properties

From `checksec` on `prob`:

- Full RELRO
- Canary
- NX
- PIE

So this is not a trivial GOT overwrite challenge.

## Core vulnerability

### 1. Shared-note double free

The server allows the same note to be opened by multiple connections.

`do_close`:

- frees `note->content`
- sets `note->deleted = 1`
- clears only the current connection slot

It does **not** refcount open handles, and it does **not** null out `note->content`.

That means:

1. `conn1` opens note `A`
2. `conn2` opens the same note `A`
3. `conn1` closes `A` -> first free
4. `conn2` closes `A` -> second free of the same pointer

Because each connection has its own handler thread, the same chunk gets inserted into two different per-thread tcaches.

This is the main bug.

### 2. The exact reuse on Ubuntu 24.04 / glibc 2.39

I instrumented the provided Docker runtime with an `LD_PRELOAD` malloc/free logger to verify allocator behavior on the intended libc.

Confirmed pattern for 0x58-sized note content:

1. create `A` with size `0x58`
2. open `A` in two connections
3. close both connections
4. create `B` with size `0x58`

Result on glibc 2.39:

- `B.note` is allocated fresh
- `B.content` reuses the double-freed `A.content`

So on the intended runtime the overlap lands on **`B.content`**, not `B.note`.

This is different from my first local assumption.

### 3. Why opcode 9 matters

Opcode `9` (`do_stat`) is useful because its event payload can be made `0x49` bytes long, which falls into the same `0x60` chunk class as note contents of requested size `0x58`.

On the second connection thread:

- `malloc(0x49)` reclaims the stale `B.content` chunk from its tcache
- after the handler finishes, `handle_conn` frees that payload again

So the second thread temporarily treats live `B.content` as an event buffer and then returns it to its tcache while `B` still points to it.

This gives a tcache-poisoning style primitive.

## What I confirmed with instrumentation

I added `malloc_logger.c` and built `malloc_logger.so` to trace `malloc/calloc/free` inside the Docker container.

Relevant verified sequence:

1. `A.content` allocated at some `0x...c80`
2. `conn1` close frees `0x...c80`
3. `conn2` close frees `0x...c80` again
4. create `B`
5. `B.note` allocated fresh at `0x...d50`
6. `B.content` reuses `0x...c80`
7. `conn2` opcode 9 does `malloc(0x49) = 0x...c80`
8. later `free(0x...c80)` happens again on that thread

I also confirmed the bundled libc exports:

- `main_arena` at `0x203ac0`
- `__free_hook` at `0x20a148`
- `system` at `0x58750`

## Exploit direction that is likely correct

The intended chain now looks like this:

1. trigger the cross-thread double free on a `0x58` content chunk
2. create `B` so that `B.content` reuses the freed chunk
3. recover the stale-chunk safe-linking mask `chunk_addr >> 12`
4. use `B.edit()` to poison the first qword of `B.content` with `target ^ mask`
5. use `conn2` opcode `9` to re-free `B.content` into `conn2`'s tcache
6. consume the poisoned tcache entry with two same-size creates on `conn2`
7. make the second created note’s `content` pointer land on an arbitrary aligned target
8. use that note for arbitrary read/write
9. leak `main_arena` from a freed large chunk to get libc base
10. write `system` to `__free_hook`
11. create a `/bin/sh` note and close it

## Current prototype status

I partially validated the poisoning path, but I have **not** finished the final stable exploit yet.

What is confirmed:

- the bug is real
- the allocator behavior on the intended runtime is real
- the stale live chunk is `B.content`
- the bundled libc still has `__free_hook`

What is not finished yet:

- turning the poisoned `conn2` tcache entry into a stable arbitrary-target note
- final libc leak and `__free_hook` write

My last two probes:

- first failed because I parsed the stale-chunk mask in the wrong endianness
- second used the corrected little-endian mask, but the service still crashed when I tried to materialize the arbitrary-target note

So the current remaining work is in the exact create/open ordering after the tcache poison, not in the basic bug identification.

## Runtime caveats

### `prob_patched`

Running `./prob_patched` directly on this host crashes during init with SIGSEGV, so validating the intended libc had to be done in Docker.

### Local flag

The provided local `flag` file is:

```text
HCMUS-CTF{fake_flag}
```

So even after the exploit is finished, the local artifact only gives a fake placeholder flag.

## Commands used

Build the intended runtime:

```bash
docker build -t notebook2-ctf .
```

Run it:

```bash
docker run -d -p 5003:5000 --name notebook2-ctf-run notebook2-ctf
```

Build the allocator logger:

```bash
gcc -shared -fPIC -O2 -o malloc_logger.so malloc_logger.c -ldl
```

Run the challenge with the logger preloaded:

```bash
docker run -d \
  -e LD_PRELOAD=/home/pwn/malloc_logger.so \
  -v "$PWD/malloc_logger.so:/home/pwn/malloc_logger.so:ro" \
  -p 5003:5000 \
  --name notebook2-ctf-debug \
  notebook2-ctf
```

## Most useful next step

Resume from the corrected poison attempt and inspect the exact allocation order after:

1. `B.edit(p64(target ^ mask) + ...)`
2. `conn2` opcode `9`
3. first same-size create on `conn2`
4. second same-size create on `conn2`

The remaining bug is almost certainly there.
