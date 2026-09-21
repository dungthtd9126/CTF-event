---
schema_version: "1.0"
kind: failure
id: "fake-stack-usermode-helper-wait"
category: "kernel-pwn"
status: draft
claim_state: "confirmed"
evidence_scope: ["single_challenge", "implementation_verified"]
tested_versions: ["Linux 6.1.184, x86-64"]
source_challenges: ["nephilim"]
---

# Fake-Stack Usermode-Helper Wait Failure

## Hypothesis

`call_usermodehelper(..., UMH_WAIT_PROC)` can be called from a ROP chain whose
stack is attacker-controlled object memory.

### Why It Was Reasonable

Wait mode is a normal kernel helper API and avoids a race with the child
process.

## Context

- Architecture/runtime: x86-64 kernel ROP from a workqueue callback
- Version: Linux 6.1.184
- Mitigations: SMEP/SMAP/PTI
- Relevant primitive/state: `mov rsp, [rdi]; ret` pivot into a kmalloc object
- Required prerequisite: stable object-backed ROP stack

## Attempt

### Bounded Procedure

Pass wait mode through the controlled `rcx` register and execute a local helper
command.

### Expected Signal

The helper completes and the ROP chain returns.

### Cost

medium

## Observed Result

The helper path reached `kernel_execve`, but the completion path later used
fake-stack object memory and faulted in `complete()`.

### Discriminating Value

This separated helper argument correctness from continuation-stack validity.

## Root Cause / Missing Assumption

The wait implementation stores completion state using the current stack. A
pivoted object is writable memory, but it is not a valid live kernel call stack
for that hidden state.

### This Result Does Not Prove

All wait-mode helpers fail under ROP. A real stack continuation or a valid
completion object could make the mode usable.

## Retry Conditions

### Do Not Retry When

- The helper still uses object memory as an uninitialized completion stack.

### Retry When

- The chain has a real kernel stack or explicitly initialized completion state.

### Where This Direction Can Succeed

- ROP with a controlled kernel stack pivot into a valid task/workqueue stack
  region, or a call sequence that avoids stack-owned completion.

## Debugging Recognition Cues

- `complete()` fault with a completion pointer inside the fake stack
- helper arguments intact but no normal ROP return

## Retrieval Cues

- UMH_WAIT_PROC fake stack
- asynchronous kernel helper ROP
- hidden stack-owned completion

## Evidence

- `vmlinux` disassembly of `call_usermodehelper_exec()`
- QEMU panic trace from the initial helper chain
