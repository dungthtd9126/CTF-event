# Flagchecking as a Service

For extra security, we encrypt our flagchecker and only let it run on our trusted servers.

```sh
$ cat flagchecker.enc - | ncat --ssl XXX.chal-kalmar.ctf 1337
```
