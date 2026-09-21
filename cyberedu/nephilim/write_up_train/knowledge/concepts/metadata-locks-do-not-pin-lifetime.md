---
schema_version: "1.0"
kind: concept
id: "metadata-locks-do-not-pin-lifetime"
category: "kernel-concurrency"
status: draft
claim_state: "confirmed"
evidence_scope: ["single_challenge", "source_backed"]
tested_versions: ["Linux 6.1.184"]
source_challenges: ["nephilim"]
---

# Metadata Locks Do Not Pin Object Lifetime

## Mental Model

A spinlock can serialize list membership or snapshot-slot writes without
keeping the pointed-to object alive. Lifetime requires a reference, an RCU
read-side section spanning the dereference/publication, or an equivalent
ownership protocol.

### Observable Consequences

- A list lookup can return a pointer safely under one lock, then the object can
  be freed after the lock is released.
- A different lock protecting a cache of those pointers cannot repair that
  lifetime gap.

## Decision Rule

For each pointer, map the complete interval from acquisition through the last
consumer dereference. Compare that interval with refcount/RCU protection, not
just with the lock held around the container.

### Fast Discriminating Checks

- Find where the RCU read lock is released relative to pointer publication.
- Find whether removal clears all aliases before scheduling `kfree()`.

## Limitations

- A worker may be safe if it takes its own reference before the producer can
  remove the object.

### Common Misconception

"Both paths use spinlocks" does not imply "the object cannot be freed between
paths." Lock identity and lifetime ownership are separate questions.

## Examples

### Positive Example

`nkrcu_snap_create()` stores a descriptor after leaving RCU read-side
protection, while `nkrcu_remove()` later frees it without clearing snapshots.

### Negative / Boundary Example

A snapshot that stores an ID and re-lookups under a lifetime-safe reference
would not preserve the raw-pointer UAF primitive.

## Retrieval Cues

- spinlock versus refcount
- RCU pointer publication
- stale container alias
- asynchronous worker lifetime

## Evidence

- `nkrcu.c:165-199`
- `nkrcu.c:145-163`
