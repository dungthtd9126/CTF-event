# NEPHILIM session checkpoint

## Objective and scope

Review the supplied `modules/` directory for vulnerabilities. Local challenge artifacts only. No outsider server contacted.

## Classification

Kernel pwn / kernel-module reverse engineering. Linux 6.1.184, x86-64, SMEP/SMAP/KASLR/PTI, one-CPU QEMU guest.

## Confirmed facts

- `nknet.ko` exposes unauthenticated UDP commands on guest port 31337.
- `nkrcu_create()` and `nkrcu_spray_alloc()` use the same `0xa20` allocation size.
- `nkrcu_snap_create()` stores raw descriptor pointers; `nkrcu_remove()` frees descriptors through RCU without clearing snapshots.
- `nkmon` dereferences stale snapshot descriptors and calls an attacker-shaped function pointer.
- `nkrcu_info()` leaks descriptor/module/kernel pointers; `nkrcu_pivot()` is `mov rsp, [rdi]; ret`.
- Local dynamic run reused the descriptor address, printed `NK-CONTROL`, then faulted in `nk_mon_work_fn` at the crafted return address.

## Current files

- `exploit.py`: validated local-only UAF/ROP flag exploit.
- `solve.py`: local protocol probe, UAF reuse probe, and intentional control-flow proof.
- `solve.md`: evidence-backed findings, reproduction, and flag.
- `write_up_train/nephilim/wu.md`: local solve capture.
- `.ctf-knowledge/working-note.md`: compact investigation state.

## Killed or bounded paths

- No external target access.
- Flag-winning stage validated locally through root `call_usermodehelper` and QEMU serial output.
- The final workqueue return intentionally faults after exfiltration; use a fresh guest for another run.

## Best next steps

1. Keep the final local-only launcher/exploit reproducible.
2. Review `write_up_train/nephilim/wu.md` and generalized knowledge entries.
3. Report the validated flag and expected terminal panic.
