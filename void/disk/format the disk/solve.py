#!/usr/bin/env python3
from pwn import *
import time

HOST = "34.62.69.250"
PORT = 41059

BAD = [
    b"mktemp:",
    b"No space left on device",
    b"wineprefix32",
    b"ctf_runs",
]

context.log_level = "info"

def build_payload():
    # Put your real exploit payload here.
    # Example:
    # return b"AAAA...."
    raise NotImplementedError("fill in your exploit payload")

def connect_until_challenge_ready():
    while True:
        try:
            io = remote(HOST, PORT, timeout=3)
            data = io.recvrepeat(1.0)

            if any(x in data for x in BAD):
                log.failure(f"launcher still broken: {data.decode(errors='ignore').strip()}")
                io.close()
                time.sleep(2)
                continue

            log.success(f"service looks alive, first output: {data!r}")
            return io, data

        except Exception as e:
            log.failure(f"connect failed: {e}")
            time.sleep(2)

def main():
    io, banner = connect_until_challenge_ready()

    payload = build_payload()
    io.send(payload)

    try:
        resp = io.recvrepeat(1.0)
        if resp:
            log.info(f"response: {resp!r}")
    except EOFError:
        pass

    io.interactive()

if __name__ == "__main__":
    main()