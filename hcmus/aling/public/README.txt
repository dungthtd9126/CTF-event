=============================================================================
xv6-riscv kernel challenge
=============================================================================

OVERVIEW
--------
The flag is loaded into the last physical page of RAM:

    flag_phys = PHYSTOP - PGSIZE = 0x87fff000

QEMU loads flag.txt at that address (see the `-device loader,...` line in
chall.sh). The patch removes that page from the kernel's free list so it is
never returned by kalloc() (see THE PATCH below).


BASE COMMIT
-----------
    origin = https://github.com/mit-pdos/xv6-riscv.git
    commit = 5474d4bf72fd95a6e5c735c2d7f208f58990ceab

(See BASE_COMMIT_INFO.)


THE PATCH (kernel.diff)
-----------------------
Two edits, both in the kernel:

  kernel/memlayout.h
    + #define FLAG_PHYS (PHYSTOP - PGSIZE)
      Names the physical page where the flag is loaded.

  kernel/kalloc.c
    - freerange(end, (void*)PHYSTOP);
    + freerange(end, (void*)FLAG_PHYS);
      kinit() now frees memory only up to FLAG_PHYS instead of PHYSTOP, so the
      final page (holding the flag) is excluded from the allocator.


GETTING THE SOURCE AND APPLYING THE PATCH
-----------------------------------------
    git clone https://github.com/mit-pdos/xv6-riscv.git
    cd xv6-riscv
    git checkout 5474d4bf72fd95a6e5c735c2d7f208f58990ceab
    git apply /path/to/kernel.diff

Build (needs a riscv64 toolchain + qemu-system-riscv64):

    make

The kernel in this directory were produced from the patched
tree, so you do not need to rebuild the kernel, or the mkfs file
to solve the challenge -- you only need to build your own user program.


INTERACTING WITH THE CHALLENGE
------------------------------
The remote service (chall.sh) does the following per connection:

  1. Prints a prompt asking for your program.
  2. Reads a single line containing the decimal byte length of your program.
     The value must be all digits; non-numeric input is rejected. It is
     capped at 8388608 (8 MiB) -- larger values are truncated to that limit.
  3. Reads exactly that many raw bytes from the connection and writes them
     into user/_init. No base64 encoding, and no EOF marker -- the server
     reads precisely `len` bytes, so the connection need not be shut down.
  4. Rebuilds the filesystem image with mkfs and boots qemu with an 8-second
     timeout.

So you supply the *init process*. Whatever ELF you send becomes PID 1; xv6
runs it directly, and its console output is returned over the connection.

The wire protocol is therefore:

    <decimal-length>\n<that many raw bytes>

send_file.py implements exactly this: it reads the file, sends its byte
length as the first line, then sends the raw bytes, and drops into an
interactive session to view the kernel/program output.

Connect and upload your init file using the provided helper:

    ./send_file.py <host> <port> path/to/your_init.elf

For example, if you build the xv6 in xv6-riscv/, you can run the original _init with:

    ./send_file.py localhost 1337 xv6-riscv/user/_init

Your program must be a statically-linked RISC-V ELF built against the xv6 user
library (see the user/ directory for the standard utilities to model yours on, 
especially the init.c file).

Good luck trying to do priviledge escalation from userspace code execution
to kernel space code execution.

For debugging, just ask your AI how to config the chall.sh and docker-compose file.
And if you don't know yet, you can debug the xv6 kernel with source too, just
like normal linux kernel.
=============================================================================
