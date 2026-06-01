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

  1. Prompts you for a base64-encoded ELF.
  2. Reads base64 lines (max 256 chars each) until a line containing "EOF".
  3. Decodes it into user/_init, rebuilds the filesystem image with mkfs,
     and boots qemu with an 8-second timeout.

So you supply the *init process*. Whatever ELF you send becomes PID 1; xv6
runs it directly, and its console output is returned over the connection.

Connect and upload your init file using provided helper:

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
