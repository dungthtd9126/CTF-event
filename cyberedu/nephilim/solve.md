# NEPHILIM module review

## Scope and classification

- Local artifact review only. No external connections.
- Category: kernel pwn / kernel-module reverse engineering.
- Memory mode: normal.
- Target surface: `nknet.ko` UDP protocol feeding `nkrcu.ko`; `nkmon.ko` asynchronous callback consumer.

## Confirmed artifact facts

- Kernel/module vermagic: Linux `6.1.184 SMP preempt mod_unload`.
- `run.sh` launches QEMU with SMEP, SMAP, KASLR, PTI, one CPU, and UDP forwarding for port `31337`.
- `nknet` accepts `NKTP` packets and dispatches operations 1-7.
- Operations expose descriptor create, snapshot, remove, info, spray allocate/free, and RCU sync.
- `nkrcu_create()` and `nkrcu_spray_alloc()` allocate `0xa20` bytes from the same kmalloc path.
- `nkrcu_info()` returns descriptor fields including module/kernel pointers.
- `nkrcu_snap_create()` stores a descriptor pointer in a global snapshot table without a reference.
- `nkrcu_remove()` unlinks the descriptor and schedules `kfree()` through RCU; snapshots are not invalidated.
- `nkmon` periodically iterates snapshots and dereferences the stored descriptor pointer.
- `nk_mon_cb()` calls a function pointer reached through descriptor offset `0x10`.
- `nkrcu_pivot()` performs `mov rsp, [rdi]; ret` and is stored in a descriptor field at offset `0x20`.

## Current vulnerability hypothesis

Confirmed: snapshot use-after-free. Validated chain: 
```
create -> snapshot -> remove -> RCU sync -> same-size controlled spray reuse -> monitor stale-pointer dereference -> indirect call/stack pivot. 
```
`nkrcu_info()` supplies KASLR-relevant leaks before removal.

The spinlocks are not the primary race. `nk_list_lock` protects list
mutation, while `nk_snap_lock` protects snapshot slots; neither protects the
descriptor lifetime. `nkrcu_snap_create()` also drops its RCU read-side
section before publishing `slot->desc`, so a concurrent remove can commit a
pointer after its grace-period free has become possible.

## Findings

### Critical: snapshot UAF to kernel control flow

- `nkrcu_snap_create()` stores the raw descriptor pointer at snapshot offset `+0x8`.
- `nkrcu_remove()` unlinks the descriptor and schedules `kfree()` through `call_rcu()` but never invalidates snapshots.
- `nkmon` runs every 5 seconds, reads the stale pointer, then calls through `[descriptor+0x10]` and its first function pointer.
- `nkrcu_spray_alloc()` allocates the same `0xa20` size and copies 128 attacker-controlled bytes, allowing deterministic replacement on the supplied one-CPU guest.
- The replacement can set `[descriptor+0x10]` to a table inside the object and `[descriptor+0x20]` to exported `nkrcu_pivot()` (`mov rsp, [rdi]; ret`).

### High: KASLR-relevant pointer disclosure

- Create response returns the descriptor address.
- `nkrcu_info()` returns the ops-table pointer, `_printk()` pointer, and `nkrcu_pivot()` pointer.
- The supplied `nknet` protocol has no authentication or pointer scrubbing.

### Medium: snapshot/resource exhaustion

- Snapshots are never deleted or invalidated. Only eight slots exist, so an attacker can permanently consume snapshot capacity.
- Spray allocations remain live until the exact leaked pointer is submitted to op 6; 64 entries can be occupied.

### Race variant

`nkrcu_snap_create()` drops the RCU read lock before storing the descriptor pointer. A concurrent remove can free the descriptor before the snapshot is committed, creating the same stale-pointer condition without a prior snapshot.

## Evidence commands

- `rtk file modules/*.ko`
- `rtk readelf -sW modules/*.ko`
- `rtk objdump -drwC -Mintel modules/nkrcu.ko`
- `rtk objdump -drwC -Mintel modules/nknet.ko`
- `rtk sed -n '1,220p' run.sh`
- `rtk sh -c "gzip -dc initrd.cpio.gz | cpio -itv"`

## Dynamic status

- QEMU was run with host forwarding bound only to `127.0.0.1`.
- `rtk python3 solve.py uaf-probe` reported identical descriptor and spray addresses.
- `rtk python3 solve.py control-probe` reported reuse plus valid kernel/module leaks.
- Guest console printed `NK-CONTROL`, then faulted at the controlled string address in workqueue `nk_mon_work_fn [nkmon]`; this confirms the indirect call and stack pivot.
- `control-probe` intentionally panics the local guest after the proof and is not a flag-winning exploit.
- `exploit.py` reached `call_usermodehelper` with `UMH_NO_WAIT`, slept in-kernel
  long enough for the helper, and guest serial emitted the flag from
  `/bin/cat /flag >/dev/ttyS0`.
- The expected final NULL-instruction-fetch panic occurs only after the flag
  is printed because the synthetic ROP stack has no normal workqueue return.

## Harness pitfall captured

An initial control payload assigned a 12-byte marker into a 16-byte bytearray slice, shrinking the request from 128 to 124 bytes. Op 5 then correctly skipped spraying because its threshold is `payload_len > 0x7f`. The harness now preserves length.

## Reproduction

1. Start the local guest: `./run.sh`.
2. Run the exploit: `rtk python3 exploit.py`.
3. Read the flag from the QEMU serial console. `run.sh` binds host UDP/GDB
   forwarding to loopback only; the default helper command is local console
   output and does not contact an outsider server.

The exploit dynamically grooms a helper chunk above the fake stack when SLUB
returns adjacent chunks in the opposite order. It uses the leaked `_printk()`
address to derive the kernel base, installs `nkrcu_pivot()` as the stale
callback, invokes `call_usermodehelper("/bin/sh", argv, envp, UMH_NO_WAIT)`,
then calls `msleep(1000)` before the intentional terminal fault.

## Flag

`CTF{f644a0c731ea53bc32f770ae89031f163cb0d4d471d91a839e2cf61c53ac6aef}`
