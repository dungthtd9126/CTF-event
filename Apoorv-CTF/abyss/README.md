# the abyss

**category:** pwn  
**author:** shura356  
**flag format:** `apoorvctf{...}`

---

```
nc <HOST> 1333
```

figure out what it does. the binary is in this archive.

`flag.txt` here is a dummy — swap in whatever string you want for local testing.

## running locally

ubuntu 22.04 + libseccomp2:

```
chmod +x ./abyss
./abyss
```

or with docker (same setup as remote):

```
docker compose up --build -d
nc localhost 1333
```

the compose file has `seccomp:unconfined` set — the binary installs its own seccomp filters and docker's default profile blocks the syscalls it needs. don't remove that line.

```
docker compose down
```

flag is at `/flag.txt` inside the container.
