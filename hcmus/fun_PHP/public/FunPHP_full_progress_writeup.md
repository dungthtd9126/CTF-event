# FunPHP — Investigation Write-up, Current Findings, and Intended Path

## Challenge Summary

- **Challenge name:** `web/Fun PHP`
- **Hint/description:** *“PHP is tricky bro... find the trick by yourself”*

At this point, the challenge is **not solved yet**, but the investigation has narrowed the space of plausible solutions a lot. The strongest remaining hypothesis is that the intended solution is a **PHP stream/filter trick**, most likely centered on making:

```php
file_get_contents($reference)
```

return the **exact 12-byte operator approval ticket**, which then unlocks the privileged session.

---

## 1. Core Primitive Confirmed: Arbitrary File Read / LFI

The `/reports/download` endpoint is vulnerable to path traversal.

It effectively reads from:

```text
/var/www/storage/reports/<user-controlled-file>
```

and can be escaped with `../../../../...` to reach arbitrary absolute paths.

### Files successfully leaked
We confirmed readable leaks for many files, including:

- `/etc/passwd`
- `/usr/local/etc/php/php.ini`
- `/readflag`
- `/var/www/secrets/admin_ticket.txt`
- `/var/www/config/reports.php`
- `/var/www/html/index.php`
- multiple files under `/var/www/app/...`

This gives us a stable and reliable **LFI/source disclosure primitive**.

---

## 2. `/readflag` Exists But Is Not Directly Usable

We leaked `/readflag` and confirmed it is an **ELF binary**.

We also confirmed:

- `/flag.txt` comes back empty under the web context
- `/readflag` appears to be the intended privileged accessor for the real flag
- therefore, the main problem is not “where is the flag?” but rather:

> how to trigger a code path that either executes `/readflag` or unlocks the hidden privileged behavior that ultimately leads to it

---

## 3. The Remote Admin Ticket Is Exactly 12 Bytes

Remote `admin_ticket.txt` was leaked successfully and equals:

```text
2026ctfhcmus
```

This is important because `DashboardController::importReference()` only enables operator access if:

1. `file_get_contents($reference)` returns a string
2. that string has **exactly length 12**
3. that string matches the secret approval bytes exactly

So the goal of the current intended path is:

```text
make file_get_contents($reference) return exactly: 2026ctfhcmus
```

---

## 4. Remote and Local Code Are Almost Identical

A local-versus-remote diff was performed.

### Result
- Most important application files are **identical**
- The only meaningful intentional diff found was:

```text
secrets/admin_ticket.txt
```

This matters because it strongly suggests:

- the intended solve is **not** hidden in a secret remote-only app feature
- the intended solve should work using the **normal existing code paths**
- the “PHP trick” is likely the real intended solve path

---

## 5. Hidden Action / Module Files Were Leaked and Analyzed

We leaked many hidden PHP files, including:

- `app/insight/action/cacheaction.php`
- `app/insight/action/exportaction.php`
- `app/insight/action/filteraction.php`
- `app/insight/action/scheduleaction.php`
- `app/insight/action/campaignaction.php`
- `app/insight/action/chartaction.php`
- `app/insight/action/revenueaction.php`
- `app/insight/action/segmentaction.php`
- `app/insight/action/trafficaction.php`
- `app/insight/module/billinginsights.php`
- `app/insight/module/campaigninsights.php`

We also successfully dispatched many of their methods through forged `DashboardPreset` imports.

### Important conclusion
These files are mostly **stubs**.

They return strings like:
- `Preview cache artifact updated.`
- `CSV export staged in report queue.`
- `Schedule dry-run completed with no conflicts.`

But they **do not** contain:
- `exec`
- `shell_exec`
- `system`
- `proc_open`
- meaningful attacker-controlled file writes
- `/readflag` execution sinks

So the “hidden class/method” route was useful for reconnaissance, but it does **not** currently appear to be the real solve path.

---

## 6. SnapshotPublisher / Enterprise Path Was Ruled Out

An earlier idea was to abuse the deserialization/import path to reach something like:

- `SnapshotPublisher`
- enterprise snapshot/export logic
- possible file write / webshell path

But on the target:

- the related enterprise feature path is unavailable
- `SnapshotPublisher` is not found
- that path is dead on remote

So this was ruled out.

---

## 7. `expect://` Wrapper Path Was Ruled Out

A large set of `expect://` payloads were tested, including:

- direct command execution
- `sh -c '/readflag > ...'`
- using `printf` or `echo -n` to emit the ticket exactly
- redirecting output into a readable report file

### Result
- no operator unlock
- no flag exfil
- no useful artifact creation
- responses consistently indicated mismatch / rejection

So `expect://` is not working on this target.

---

## 8. Confirmed Privileged Sink: `publish-manifest`

Inside `DashboardController`, we confirmed the following logic:

### Import reference
`/dashboard/integrations/import-reference`
- reads attacker-supplied reference with `file_get_contents($reference)`
- compares it against `/var/www/secrets/admin_ticket.txt`
- if matched, enables operator/admin session for that browser session

### Publish manifest
`/dashboard/operations/publish-manifest`
- requires operator/admin session
- writes to:

```text
/var/www/storage/reports/admin-export-manifest.txt
```

- writes literal contents:

```text
EXPORT_READY
```

So the only confirmed privileged write sink so far is:

- **fixed path**
- **fixed content**
- no immediate flag or code exec

This means one of two things is true:

1. Unlocking admin is only an intermediate step, and another behavior becomes accessible afterward
2. The manifest path itself is part of a bigger trick that we have not yet identified

---

## 9. Paths Already Tried

## A. Forged `DashboardPreset` / method dispatch
Status:
- good for reconnaissance
- not enough for flag
- many hidden methods are harmless stubs

## B. Artifact side-effect hunting
We invoked methods that sounded like they might create files:
- cache
- preview
- export
- report queue
- schedule/report calendar

Then scanned likely storage directories for created artifacts.

Status:
- no useful artifact hit
- no flag-bearing output recovered

## C. `expect://`
Status:
- dead

## D. Basic Synacktiv `php_filter_chain_generator`
Status:
- promising, but incomplete

A generated chain was tested and, in the PHP environment, it appeared to produce output beginning with the correct ticket followed by extra garbage bytes.

That is important because it suggests:

> the ticket can likely be synthesized, but the output is not yet **exactly** 12 bytes

## E. Basic `wrapwrap`
Status:
- current invocation model is wrong / unproductive

We tested `wrapwrap` in both host and container validation flows.

Result:
- no exact 12-byte local match
- in the most recent docker-local brute force, every attempt had:
  - `chain_len = 2535`
  - `local_len = 0`
  - `local_match_ticket = false`

This means the current `wrapwrap + php://temp + suffix=""` strategy is not producing the desired output model.

### Strong conclusion
This brute force was **not** failing because the search space was too small.

It was failing because the current use of the tool is wrong for the desired behavior.

---

## 10. Docker-Local Validation Changed the Investigation

A very important improvement in the investigation was to stop trusting host-PHP validation and instead validate candidate chains in the **same PHP runtime as the challenge**, by using:

```bash
docker exec insightboard php -r 'echo file_get_contents($argv[1]);' '<chain>'
```

This was critical because it let us prove:

- some ideas fail **even before** reaching the web app
- some tool usage patterns are wrong locally, not just remotely
- brute forcing the wrong local model is a dead end

This was one of the most useful pivots in the whole process.

---

## 11. What the Current Evidence Strongly Suggests

All current evidence points toward:

### The intended solve is probably a PHP filter/stream trick

Why:

1. The hint explicitly points to a **PHP trick**
2. The app directly calls `file_get_contents($reference)` on attacker input
3. Blacklist filtering blocks some obvious terms but does **not** block:
   - `php://filter`
   - `php://temp`
4. The approval check requires a **very precise output**
   - exactly 12 bytes
   - matching the secret ticket
5. Remote app code is almost identical to local app code, meaning the trick is likely embedded in normal PHP behavior, not in hidden remote-only business logic

So the most plausible intended route remains:

1. Generate a crafted `php://filter/.../resource=...` reference
2. Make `file_get_contents()` return exactly the operator ticket
3. Unlock operator/admin session
4. Re-check privileged behavior after unlock for the final flag path

---

## 12. Current Blocker

The current blocker is **not** discovery anymore.

It is now very focused:

> We still do not have a chain that makes `file_get_contents($reference)` return **exactly** `2026ctfhcmus` inside the correct PHP runtime.

We have moved past broad enumeration and into exact output synthesis.

---

## 13. Current Intended Path

The intended path now is:

## Main plan
Continue the **PHP filter exact-output** line, but do it correctly:

1. Validate everything inside the **challenge container PHP**
2. Use `php_filter_chain_generator.py` as the stronger current lead
3. Treat the problem as a **trimming / normalization** problem:
   - the ticket already appears at the front of the generated output
   - the problem is extra garbage bytes after it
4. Search for **post-filters** (especially `iconv`-style transformations) that preserve the ASCII ticket but eliminate or normalize trailing garbage
5. Only when container-side output is exactly 12 bytes should the chain be sent to the web app

This is why the latest intended script path moved toward:
- generating Synacktiv base chains
- validating inside docker PHP
- appending candidate post-filters
- looking for an exact 12-byte match before touching the web endpoint

---

## 14. Honest Current Assessment

We are **not solved yet**, but the search space is now much smaller than at the start.

### What we have solidly confirmed
- working LFI / arbitrary file read
- source disclosure of the whole relevant app
- leaked remote 12-byte approval ticket
- remote ≈ local app code
- hidden `Action/*` files are real but mostly harmless stubs
- `SnapshotPublisher` path is dead
- `expect://` path is dead
- current `wrapwrap` approach is dead in its present form
- the container PHP runtime is the correct place to validate chains

### What we still do not have
- a container-validated chain whose output is **exactly** the 12-byte ticket
- a confirmed post-admin path to the real flag

### Strongest current hypothesis
The intended path is still a **PHP filter trick**, but it is more subtle than the first brute-force attempts.

---

## 15. Current Bottom Line

### What we got
- stable LFI
- full enough source disclosure
- remote ticket: `2026ctfhcmus`
- local/remote code parity
- confirmation that most obvious alternative paths are dead

### What failed
- hidden class RCE ideas
- enterprise snapshot path
- `expect://`
- artifact side-effect hunting
- current `wrapwrap + php://temp` brute-force model

### What we intend now
- continue with **Synacktiv chain + container-side trimming / post-filter search**
- only trust outputs that are exact 12-byte matches in the container PHP runtime
- if such a chain is found, retry operator unlock and then inspect any post-admin behavior again

### Current blocker
- no exact 12-byte container-side chain yet

---

## 16. Practical Next Step

Use the latest **container-validated Synacktiv trimming search** approach:

- generate base filter chains
- inspect container-side output
- search for post-filters that trim the trailing bytes
- only then attempt local or remote unlock

This is the most grounded remaining path given all current evidence.
