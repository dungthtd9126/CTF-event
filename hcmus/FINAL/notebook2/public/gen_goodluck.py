#!/usr/bin/env python3
# Regenerates goodluck.bin -- the single CREATE frame the warm-up client posts
# to the board on startup (see entrypoint.sh). It just leaves a "good luck :)"
# note named "goodluck" on the shared board.
import struct

MAGIC, CTRL, CH, CREATE = 0xBEEF1337, 0x2000, 0x10, 1

name    = b"goodluck".ljust(0x20, b"\x00")
token   = b"t".ljust(0x20, b"\x00")
clen    = 0x10
content = b"good luck :)".ljust(clen, b"\x00")[:clen]

data  = name + token + struct.pack("<II", 0, clen) + content        # flags, clen, content
body  = struct.pack("<II", CTRL | CREATE | CH, len(data)) + data    # type, size, data
frame = struct.pack("<II", MAGIC, len(body)) + body                 # magic, body_len

with open("goodluck.bin", "wb") as f:
    f.write(frame)
print("wrote goodluck.bin (%d bytes)" % len(frame))
