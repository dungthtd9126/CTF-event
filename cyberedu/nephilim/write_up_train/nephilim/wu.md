# NEPHILIM

## Metadata

- **Challenge ID:** nephilim
- **Category:** kernel pwn / kernel-module reverse engineering
- **Event/source:** local supplied challenge bundle
- **Date solved:** 2026-09-19
- **Memory mode:** resume
- **Architecture/runtime:** x86-64 Linux 6.1.184, QEMU, one CPU
- **Mitigations/constraints:** SMEP, SMAP, PTI, KASLR-capable kernel, local UDP only
- **Files:** `modules/nkrcu.ko`, `modules/nkmon.ko`, `modules/nknet.ko`, `exploit.py`, `run.sh`
- **Remote:** none
- **Final result:** root kernel ROP executed a local helper and printed the flag on QEMU serial
- **Solution reuse:** true; continued from the local handoff and existing exploit harness

## Challenge Summary

The `nknet` module exposes an unauthenticated NKTP UDP protocol. `nkrcu`
manages descriptor objects and snapshots; `nkmon` periodically walks snapshots
from a workqueue. Create, snapshot, remove, RCU-sync, and same-size spray
operations expose a stale descriptor to an attacker-controlled replacement.

## Environment and Fingerprint

### Artifact identity

Source-level reconstructions are present as `nkrcu.c`, `nkmon.c`, and
`nknet.c`; compiled modules are under `modules/`. The supplied `vmlinux`
contains the kernel symbols used by the local ROP chain.

### Runtime / version boundary

The tested guest uses Linux `6.1.184`, x86-64, a single QEMU CPU, and the
provided out-of-tree modules. Allocation reuse was reliable after explicit
RCU synchronization in this guest.

### Important constraints

The host forwarding must bind to `127.0.0.1`. The exploit's default helper
command writes to the guest serial device; it does not contact an outsider
server. Op 5 requires a payload longer than `0x7f` bytes.

## Root Cause

`nkrcu_snap_create()` stores a raw `struct nk_desc *` in a snapshot without a
reference or lifetime pin. It releases the RCU read-side critical section
before publishing that pointer. `nkrcu_remove()` unlinks the descriptor under
`nk_list_lock`, releases the lock, and schedules the object for `kfree()` via
RCU, but it never clears or invalidates snapshots. The monitor later trusts
the stale pointer and calls `desc->ops->validate(desc)`.

The spinlocks serialize metadata updates only. `nk_list_lock` and
`nk_snap_lock` protect different structures and do not establish descriptor
lifetime. The premature RCU unlock also creates a direct publication/removal
race.

## Derived Primitives

| Primitive | How obtained | Verification signal | Scope/limitations |
| --- | --- | --- | --- |
| Same-cache UAF reclaim | Free a descriptor, RCU-sync, spray another `0xa20` object | Spray address equals stale descriptor address | Depends on allocator state; groomed locally |
| Kernel/module pointer leak | Query op 4 before removal | Response includes `_printk()` and `nkrcu_pivot()` pointers | Pointer disclosure is protocol-visible |
| Indirect call control | Replace the descriptor's `ops` pointer with an object-local table | Monitor reaches controlled callback | Requires monitor timer/workqueue execution |
| Stack pivot | Set the stale descriptor's pivot field to `nkrcu_pivot()` | Controlled ROP marker appears on serial | Fake stack is object-backed and has limited space |
| Root command execution | ROP-call `call_usermodehelper` with `UMH_NO_WAIT` | `/bin/cat /flag` output on QEMU serial | Terminal workqueue return intentionally faults |

## Key Observations

- `nkrcu_create()` and `nkrcu_spray_alloc()` use the same `0xa20` allocation
  size and op 5 copies 128 attacker-controlled bytes.
- The monitor runs every five seconds and calls through the stale descriptor.
- `nkrcu_info()` leaks the kernel `_printk()` pointer and the module pivot
  pointer before removal.
- A helper chunk must sit above the fake stack; the final harness grooms for
  either SLUB adjacency order.

## Decision Trace

### A1 - Separate metadata locking from lifetime

- **Observation/state:** snapshots contain raw descriptor pointers; remove uses
  list locking and RCU freeing.
- **Hypothesis:** the lock pairing prevents the UAF.
- **Why plausible:** list and snapshot mutations are serialized separately.
- **Smallest discriminating test:** snapshot, remove, RCU-sync, then spray one
  same-size object and compare returned addresses.
- **Why this test first:** it directly tests lifetime/reuse rather than timing
  assumptions.
- **Expected signal:** spray address equals the stale snapshot descriptor.
- **Actual signal:** identical addresses in the local QEMU guest.
- **Outcome:** supported
- **Interpretation:** metadata locks do not pin the object.
- **Decision/pivot:** build the fake descriptor and callback control payload.
- **Retry/transfer condition:** use explicit RCU synchronization when allocator
  reuse is not immediate.
- **Evidence:** `nkrcu.c:145`, `nkrcu.c:165`, `nkrcu.c:226`; `solve.py`

### A2 - Validate control flow before full exfiltration

- **Observation/state:** op 4 leaks `_printk()` and `nkrcu_pivot()`.
- **Hypothesis:** the stale callback can pivot into object memory.
- **Why plausible:** monitor dereferences `desc->ops->validate` with no type or
  lifetime validation.
- **Smallest discriminating test:** object-local ops table, pivot, and a
  `_printk()` marker.
- **Why this test first:** it isolates callback control from command execution.
- **Expected signal:** marker on QEMU serial, then a controlled fault.
- **Actual signal:** `NK-CONTROL` printed and the fault address came from the
  crafted object memory.
- **Outcome:** successful_stage
- **Interpretation:** indirect call and stack pivot are confirmed.
- **Decision/pivot:** add a kernel ROP call to a root usermode helper.
- **Retry/transfer condition:** none for this primitive.
- **Evidence:** `solve.py`, `nkmon.c:36`, `nkmon.c:48`

### A3 - Avoid wait-mode completion on a fake stack

- **Observation/state:** the first helper chain used `UMH_WAIT_PROC`.
- **Hypothesis:** the helper can wait normally after a ROP call.
- **Why plausible:** wait mode is the conventional synchronous helper API.
- **Smallest discriminating test:** run the chain with a simple local command and
  inspect the guest trace.
- **Why this test first:** it distinguishes command failure from return-stack
  corruption.
- **Expected signal:** command output followed by a normal helper return.
- **Actual signal:** `complete()` dereferenced object-backed fake-stack memory
  and panicked.
- **Outcome:** rejected
- **Interpretation:** the kernel stored its completion pointer on the synthetic
  ROP stack, not a real workqueue stack.
- **Decision/pivot:** use `UMH_NO_WAIT`, then call `msleep(1000)` before the
  intentional terminal return.
- **Retry/transfer condition:** wait mode is usable only with a valid
  completion object and real stack lifetime.
- **Evidence:** `vmlinux` disassembly of `call_usermodehelper_exec()` and
  `call_usermodehelper_exec_async()`; `exploit.py:162`

### A4 - Make allocator placement explicit

- **Observation/state:** adjacent spray chunks occasionally appeared in the
  opposite address order.
- **Hypothesis:** fixed allocation order is sufficient for helper placement.
- **Why plausible:** the one-CPU guest usually reused the freed chunk directly.
- **Smallest discriminating test:** record both addresses and require the helper
  to be above the descriptor before arming the snapshot.
- **Why this test first:** it prevents a late ROP-frame overwrite of helper data.
- **Expected signal:** helper address greater than descriptor address.
- **Actual signal:** one run reversed the pair; dynamic extra spray found a
  valid higher helper chunk.
- **Outcome:** successful_stage
- **Interpretation:** address ordering is an allocator-state property, not a
  protocol guarantee.
- **Decision/pivot:** retain the grooming loop in the final exploit.
- **Retry/transfer condition:** re-groom on a fresh guest when a candidate is
  unavailable.
- **Evidence:** `exploit.py:112`

## Exploitation / Solution Strategy

```text
raw snapshot pointer
  -> RCU-delayed descriptor free
  -> same-size controlled reclaim
  -> fake ops table and nkrcu_pivot
  -> leaked-kernel-address ROP
  -> root call_usermodehelper
  -> /bin/cat /flag >/dev/ttyS0
```

## Detailed Solution

### Stage 1 - Reclaim the stale descriptor

Reserve two same-size spray chunks. Free the intended target, create a
descriptor, and verify that the descriptor reclaims that address. Query op 4
for the `_printk()` leak and module pivot. If the helper chunk is below the
descriptor, allocate additional spray chunks until a live chunk is above it;
free only the unused candidates.

Create a snapshot, remove the descriptor, and issue op 7 so the RCU callback
has completed. The final op 5 payload replaces the stale object while keeping
the spray entry live.

**Intermediate verification:** returned spray address equals the descriptor
address; serial proof chain printed `NK-CONTROL` during earlier control tests.

### Stage 2 - Root helper and flag output

The replacement sets the fake `ops->validate` target to `nkrcu_pivot()`. The
ROP chain derives the kernel base from the leaked `_printk()` address, loads
`/bin/sh`, `argv`, `envp`, and `UMH_NO_WAIT` into the System V argument
registers, then calls `call_usermodehelper`. The helper runs
`/bin/cat /flag >/dev/ttyS0`. `msleep(1000)` gives the helper process time to
run before the object-backed continuation faults.

**Intermediate verification:** QEMU serial output contained the complete flag;
the subsequent NULL instruction-fetch panic was expected and occurred after
the output.

## Meaningful Failed Paths and Pivots

### UMH wait-mode completion

- **Context:** ROP stack lives inside the reclaimed kmalloc object.
- **Expected:** synchronous helper returns normally.
- **Observed:** `complete()` wrote through an invalid object-backed completion
  pointer and the guest panicked.
- **Root cause/unknown:** `call_usermodehelper_exec()` uses its current stack
  for completion state; the pivoted stack is not a valid kernel call stack.
- **This does not prove:** wait mode is universally unusable; a real stack or
  valid completion storage could support it.
- **Do not retry when:** the chain still returns into object memory without
  initializing a valid completion object.
- **Retry when:** the exploit has a stable real stack continuation.
- **Lesson:** audit asynchronous kernel APIs for hidden stack-owned state.

### Fixed spray ordering

- **Context:** SLUB returned the initial helper below the descriptor once.
- **Expected:** two allocations always provide the desired order.
- **Observed:** the final placement check rejected the layout.
- **Root cause/unknown:** freelist state determines adjacency direction.
- **This does not prove:** same-cache reclaim is unreliable; only the helper
  placement assumption was brittle.
- **Do not retry when:** the helper remains below the fake stack.
- **Retry when:** extra live spray slots can provide a higher chunk.
- **Lesson:** make cross-object stack/data ordering a runtime invariant.

### Op 5 payload truncation

- **Context:** an early marker assignment shrank a `bytearray` slice.
- **Expected:** the marker changes while the request remains 128 bytes.
- **Observed:** op 5 silently skipped the spray because payload length became
  124 bytes.
- **Root cause/unknown:** Python slice assignment changed container length.
- **This does not prove:** the protocol rejected valid 128-byte payloads.
- **Do not retry when:** payload length is not asserted before sending.
- **Retry when:** the payload is fixed-size and length-checked.
- **Lesson:** assert serialized lengths at protocol boundaries.

## Final Exploit / Reproduction

- **Exploit/script:** `exploit.py`
- **Usage:** start `./run.sh`, then run `rtk python3 exploit.py`
- **Reliability notes:** `exploit.py` expects the guest service on host
  `127.0.0.1:31337`; restart after the expected panic. `run.sh` now binds
  UDP and GDB forwarding to loopback only.

## Validation

- **Local:** successful on the supplied QEMU guest.
- **Remote:** not used.
- **Success signal:** QEMU serial emitted the flag after root helper execution.

## Research Findings

No external research or server access was used.

## New Knowledge

### Challenge-specific

- The monitor interval is five seconds and the target modules use a shared
  `0xa20` allocation path.

### Reusable candidates

- Metadata locks do not imply object lifetime; inspect RCU/refcount scope.
- Fake-stack kernel ROP must account for asynchronous APIs that store wait
  state on the current stack.
- Cross-object payloads need allocator-order assertions and bounded grooming.

## General Bugs and Debugging Lessons

- Python mutable-slice assignment can shrink a binary payload; assert exact
  serialized lengths before protocol submission.

## Transfer to Future Challenges

### Recognition cues

- A snapshot/cache stores raw object pointers while removal only unlinks and
  asynchronously frees the object.
- A background worker later calls through fields in that object.

### Preconditions

- A same-size or otherwise compatible reclaim allocation is attacker-shaped.
- A stale callback is reached after the reclaim and a useful kernel pointer is
  available or calculable.

### Fast checks

- Compare a freed object's leaked address with the next controlled allocation.
- Trace lock scope versus RCU/refcount lifetime separately.
- Test whether wait-mode kernel helpers write completion state on the pivoted
  stack.

### Negative cues / stop conditions

- No stale consumer exists after free, or the object is refcount-pinned.
- The replacement cannot control the callback table or obtain a safe kernel
  continuation.

### Version/mitigation boundary

Allocator ordering, kernel helper internals, and gadget availability are
version/build dependent. Re-check on each supplied kernel image.

## Dataset / Evaluation Notes

- **Suggested split:** unassigned
- **Exact prior solution used:** true
- **Potential near-duplicate family:** kernel snapshot/RCU UAF with same-cache reclaim
- **Safe for generalized training export:** no; this local write-up contains the flag

## Evidence

- `nkrcu.c:145`
- `nkrcu.c:165`
- `nkrcu.c:226`
- `nkmon.c:36`
- `exploit.py:112`
- `exploit.py:162`
- `run.sh:19`

## Flag

`CTF{f644a0c731ea53bc32f770ae89031f163cb0d4d471d91a839e2cf61c53ac6aef}`
