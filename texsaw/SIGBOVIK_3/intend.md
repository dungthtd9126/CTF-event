Command-by-Command Breakdown
Phase 1: Set rdx = 7 (PROT_READ | PROT_WRITE | PROT_EXEC)

The mprotect syscall needs rdx to be 7 to grant full execution permissions. We use the LAMBDA command to do this, but LAMBDA has internal type checks that will crash the program if the stack isn't set up properly.

    LOAD 0: Pushes a 0 (a "Fixnum" type) onto the VM stack.

    VECTOR: Pops the 0, creates an empty Vector object, and pushes it onto the stack.

    LOAD 0: Pushes another 0 (Fixnum) onto the stack.

        State: The VM stack now holds a Fixnum and a Vector. This perfectly satisfies LAMBDA's strict type checks.

    LAMBDA 7: The CPU executes the LAMBDA assembly. It grabs our immediate value (7) and puts it directly into the rdx register (mov rdx, [rsp-8]). Because we set up the stack, it safely passes the internal checks and returns to our chain.

Phase 2: Set rsi = 1 (Length of memory to protect)

mprotect automatically aligns lengths to the system page size (4096 bytes). Asking it to protect 1 byte will successfully make the entire page executable. We use a hidden fragment inside the LT (Less Than) instruction to set this.

    LOAD 0: Pushes a 0 onto the stack.

    STRING: Pops the 0. The STRING instruction naturally zeroes out both rdi and rsi. Because the length we passed is 0, it safely exits.

    LOAD 0: Pushes a 0 to the stack.

    LT: Pops the 0 into the rdi register. The LT assembly then executes mov esi, 1 (setting our target register!). Because rdi is 0, the instruction realizes there is nothing to compare, and safely returns without looping or crashing.

Phase 3: Set rdi = buf_addr and Call mprotect

We need rdi to hold the exact memory address of our buffer. We abuse a feature in PRIMAPPLY that automatically unpacks Lisp lists into registers before calling native C functions.

    LOAD {buf_shifted}: Pushes the raw memory address of our buffer onto the stack.

    LOAD NULL: Pushes the list terminator (0x2f) onto the stack.

    CONS: Pops both values and stitches them together into a Lisp list: (buf_addr). It pushes the pointer to this list back onto the stack.

    LOAD 0

    LOAD 0: We push two dummy values. Why? Because the PRIMAPPLY assembly is hardcoded to look for its list at [rbx+0x10] (two slots down the stack). Pushing these zeroes slides our list pointer into the exact slot PRIMAPPLY expects.

    PRIMAPPLY {mprotect_addr}: The grand finale. PRIMAPPLY reaches down into the stack, grabs our list, and unpacks the first item (buf_addr) directly into the rdi register. It then natively jumps to mprotect.

        Result: The CPU executes mprotect(buf_addr, 1, 7). Our memory is now executable!

Phase 4: The Escape (Raw Shellcode)

Notice that we deleted the DONE command in the Python script.

    <shellcode_address>: When mprotect finishes its job, it executes a standard C ret instruction. Unlike the VM's ret 8, a standard ret pops the next 8 bytes of our payload directly into the Instruction Pointer (RIP). By placing the address of our shellcode here, we hijack the CPU's execution flow, permanently escaping the Lisp VM.

    <Raw Shellcode Bytes>: The CPU lands here and executes the raw x86_64 execve("/bin/sh") shellcode, giving you the shell!