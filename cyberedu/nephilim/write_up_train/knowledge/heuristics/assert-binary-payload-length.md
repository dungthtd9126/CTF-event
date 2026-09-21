---
schema_version: "1.0"
kind: heuristic
id: "assert-binary-payload-length"
category: "exploit-debugging"
status: draft
claim_state: "confirmed"
evidence_scope: ["single_challenge"]
source_challenges: ["nephilim"]
---

# Assert Binary Payload Length

## Situation

A protocol accepts a binary payload only above a size threshold, while the
exploit patches a mutable byte array with variable-length slices.

## Heuristic

Assert the final serialized length immediately before every send; use explicit
offset writes or fixed-size buffers for marker changes.

## Why It Helps

In Python, assigning a differently sized slice changes the byte-array length.
The protocol may then take a silent short-input branch, making a valid memory
payload look like an allocator or timing failure.

## Cheap Check / Next Action

Print or assert `len(payload)` equals the protocol minimum and expected copy
size before constructing the packet.

## Stop Conditions

- The length assertion fails; fix serialization before changing exploit state.

## Known Boundaries

- The exact threshold is protocol-specific.

## Retrieval Cues

- mutable bytearray slice assignment
- silent short-payload branch
- binary protocol length threshold

## Evidence

- `nknet.c:226-249`
- `solve.md` harness pitfall
