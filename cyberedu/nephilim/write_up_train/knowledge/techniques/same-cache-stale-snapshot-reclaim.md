---
schema_version: "1.0"
kind: technique
id: "same-cache-stale-snapshot-reclaim"
category: "kernel-pwn"
status: draft
claim_state: "confirmed"
evidence_scope: ["single_challenge", "implementation_verified"]
tested_versions: ["Linux 6.1.184, x86-64"]
source_challenges: ["nephilim"]
---

# Same-Cache Stale-Snapshot Reclaim

## Trigger

### Recognition cues

- A cache or snapshot stores a raw object pointer.
- Removal unlinks and asynchronously frees the object without invalidating
  every stored pointer.
- A later worker dereferences fields or calls a function pointer from it.

### Decision rule

Test object lifetime independently from metadata lock coverage. If a
same-size controlled allocation can reclaim the address, shape only the
fields consumed by the stale worker first.

## Preconditions

- A stale consumer runs after the free.
- Reclaim allocation size/cache is compatible.
- The replacement remains live long enough for the worker.

## Fast discriminating checks

1. Record the object address before removal.
2. Complete the relevant RCU grace period.
3. Allocate one controlled same-size object and compare addresses.

## Procedure

1. Create and snapshot the object.
2. Remove it and perform any available grace-period synchronization.
3. Groom a replacement allocation; assert the returned address.
4. Replace only the callback/table/pivot fields needed by the consumer.

### Verification points

- Reclaim address equals the stale pointer.
- The worker reaches the controlled callback.
- A benign marker confirms control before a full payload is attempted.

## Expected observations

- Metadata operations can appear correctly locked while object contents are
  already freed or reused.

## Counterexamples / Negative cues

### Do not apply blindly when

- A reference count or RCU read-side section remains held until all consumers
  finish.
- The worker clears snapshots before dereference.

### Known failure modes

- Assuming allocator adjacency order is fixed.
- Freeing the replacement before the asynchronous consumer fires.

### Retry / transfer boundary

- Re-groom when allocator state changes; do not generalize exact placement.

## Version / Mitigation Boundary

SLUB order, cache size, RCU timing, and pointer-hardening behavior are
kernel/build dependent. Verify address reuse on the target image.

## Retrieval Cues

- raw snapshot pointer
- RCU delayed free
- same-size kmalloc spray
- background callback UAF

## Evidence

- `nkrcu.c:145-199`
- `nkrcu.c:226-249`
- `nkmon.c:36-52`
