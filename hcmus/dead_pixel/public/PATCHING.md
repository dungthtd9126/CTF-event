# Dead Pixel Local Patch

The Docker service runs `./dead_pixel` inside Ubuntu 24.04. To reproduce that locally, use the bundled Ubuntu 24.04 loader and libraries in `libs/`.

## Patch

Regenerate the patched binary from the pristine challenge binary:

```bash
./patch_dead_pixel.sh
```

## How It Works

The patcher starts from the original `dead_pixel` every time and writes `dead_pixel_patched`.

First, it changes the ELF interpreter string:

```text
/lib64/ld-linux-x86-64.so.2 -> ./libs/ld-linux-x86-64.so.2
```

Those strings have the same byte length, so the interpreter can be replaced in place.

Second, it adds a `DT_RUNPATH` of `$ORIGIN/libs`, so direct execution resolves libc and the C++ runtime from the bundled `libs/` directory.

The patcher does this manually instead of using `patchelf`:

1. It copies the original dynamic string table.
2. It appends `$ORIGIN/libs` to that copied string table.
3. It appends the new string table to the end of the file.
4. It repurposes one unused `PT_NOTE` program header as a read-only `PT_LOAD` segment for the appended string table.
5. It updates `DT_STRTAB` and `DT_STRSZ` to point at the new string table.
6. It reuses a spare dynamic NULL slot as `DT_RUNPATH`.
7. It updates the `.dynstr` section header too, so tools like `readelf` and `patchelf --print-rpath` report the new RUNPATH normally.

The important constraint is that the original executable mappings stay in place: `.init`, `.plt`, `.text`, `.fini`, GOT, and data keep their original virtual addresses.

This is important for this binary because `patchelf --set-rpath` moves `.init`/`.plt` metadata in a way that makes the binary crash before startup.

## Environment And Layout

This patch makes local execution use the same bundled dynamic loader and shared libraries that are in `libs/`:

```text
./libs/ld-linux-x86-64.so.2
./libs/libstdc++.so.6
./libs/libm.so.6
./libs/libgcc_s.so.1
./libs/libc.so.6
```

That gives you the same libc/libstdc++ ABI and symbol behavior as the bundled Ubuntu 24.04 runtime.

It does not make the whole process identical to Docker. The host run still differs in things like environment variables, `argv[0]`, absolute path length, current working directory, auxiliary vector details, open file descriptors, filesystem view, process limits, and the host kernel. Those can affect stack contents and some mappings.

The memory layout is also not fixed. PIE, libc, the loader, heap, stack, and mmap bases are randomized by ASLR on each run, both locally and in Docker unless ASLR is disabled. What should remain stable are binary-relative offsets, libc-relative offsets, symbol versions, and the original executable segment layout of `dead_pixel`.

For the closest possible match to the challenge service, run the binary inside the same Docker image/container. Use `dead_pixel_patched` locally when you need the same bundled libc without the overhead of entering Docker.

## Run

Run the patched binary directly:

```bash
./dead_pixel_patched
```

The wrapper still works, but it is no longer required:

```bash
./run_patched.sh
```

For pwntools, launch the patched binary directly:

```python
p = process(["./dead_pixel_patched"])
```

## Verify

Check the interpreter:

```bash
patchelf --print-interpreter dead_pixel_patched
```

Expected:

```text
./libs/ld-linux-x86-64.so.2
```

Check the embedded runpath:

```bash
patchelf --print-rpath dead_pixel_patched
```

Expected:

```text
$ORIGIN/libs
```

Check dependency resolution:

```bash
LD_TRACE_LOADED_OBJECTS=1 ./dead_pixel_patched
```

Expected dependencies should resolve to `./libs/libstdc++.so.6`, `./libs/libm.so.6`, `./libs/libgcc_s.so.1`, and `./libs/libc.so.6`.
