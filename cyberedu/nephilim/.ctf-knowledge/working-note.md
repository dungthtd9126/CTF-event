# NEPHILIM working note

## Objective

Review the supplied kernel modules for exploitable vulnerabilities. Keep all activity local.

## Fingerprint

Kernel pwn target: x86-64 Linux 6.1.184, relocatable modules, SMEP/SMAP/KASLR/PTI enabled by launcher, UDP protocol on guest port 31337, same-size kmalloc object and asynchronous RCU consumer.

## Confirmed observations

- `nknet.ko` exposes create/snapshot/remove/info/spray/sync commands.
- `nkrcu_snap_create()` records raw descriptor pointers.
- `nkrcu_remove()` frees descriptors after RCU but never removes or invalidates snapshots.
- `nkmon` periodically consumes snapshots and performs an indirect callback through descriptor memory.
- `nkrcu_spray_alloc()` allocates the same `0xa20` size and copies 128 attacker-controlled bytes.
- `nkrcu_info()` leaks descriptor fields containing module and kernel pointers.
- `nkrcu_pivot()` is `mov rsp, [rdi]; ret`.
- Local QEMU confirmed exact same-address descriptor reuse after RCU sync.
- A crafted replacement drove `nkrcu_pivot`, called leaked `_printk`, printed `NK-CONTROL`, then faulted at the next controlled stack word in `nk_mon_work_fn`.
- Final ROP invoked `call_usermodehelper` with `UMH_NO_WAIT`; `/bin/cat /flag >/dev/ttyS0` emitted the flag on the QEMU serial console.
- `UMH_WAIT_PROC` is unsafe on this fake stack because the kernel stores its completion object on object-backed ROP memory; `msleep(1000)` provides scheduler time before the intentional terminal fault.

## Active hypothesis / result

Use-after-free plus controlled same-cache replacement reaches attacker-controlled indirect call, stack pivot, root usermode helper, and local flag output. Runtime validated.

## Scope boundary

`run.sh` now binds UDP and GDB forwarding to `127.0.0.1`; the default helper command is local serial output.

## Best next tests

1. Re-run `rtk python3 exploit.py` against a fresh guest if reproducibility is needed.
2. Keep `run.sh` loopback-bound and the default helper command local-only.
3. Complete the local write-up and knowledge capture.

## Investigation pitfall

An early payload marker was assigned into a larger bytearray slice, shrinking the packet below op 5's `> 0x7f` threshold. Preserve exact bytearray length when patching binary payloads.
