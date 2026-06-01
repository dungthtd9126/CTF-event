# allocator notes

The target gate appears near `0x404130`, and the intended patch value is probably `0x41414141`.

Suggested shortcut:

```text
create -> delete -> edit fd to 0x404130 -> create -> hidden 1337
```

This is a stale note from the non-revenge binary. The released binary must be solved from its own symbols/behavior.

Fake accepted flag observed during dry run: `0xV01D{tcache_without_safe_linking}`
