# The Real TARget – current status

I re-checked the challenge after the first exploit failed.

## What the failure means

The previous script hit `HTTP 500 {"error":"File untarred unsuccessfully"}` **before** the worker-restart stage mattered.
That means the archive is being rejected during `tarfile.open(...).extractall(...)`, not that the import-hijack step merely needed more restart time.

## Why that matters

The distributed Dockerfile uses:

```dockerfile
FROM python:3.14.5
```

Python 3.14.5's changelog states that it addresses the tarfile extraction-filter bugs including **CVE-2025-4138** and **CVE-2025-4517**.
So the public PATH_MAX symlink-chain bypass is not expected to work on a stock `python:3.14.5` image.

## Strongest current conclusion

If the remote behaves like the Dockerfile says, then:

- a benign tar upload should still return **200**;
- classic traversal should return **500**;
- the exact CVE-2025-4517-shaped archive should also return **500**.

That would mean the challenge, as deployed, is effectively patched against the intended tarfile route.

## Deliverable

Use `real_target_probe.py` to verify the instance behavior cleanly:

```bash
./real_target_probe.py http://chall.blackpinker.com:20400
```

If the results are:

```text
benign -> 200
direct -> 500
cve    -> 500
```

then the instance is very likely broken/unintended, not just mistuned.
