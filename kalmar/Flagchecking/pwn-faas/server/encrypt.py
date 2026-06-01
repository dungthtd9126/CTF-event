from hashlib import sha256
from pathlib import Path
import struct
import sys

from Crypto.Cipher import AES

PROG_SIZE = 0x10000
SIG_SIZE = 0x20

data = Path(sys.argv[1]).read_bytes()

assert len(data) <= PROG_SIZE
data = data.ljust(PROG_SIZE, b"\0")

sig = sha256(data).digest()
assert len(sig) == SIG_SIZE

key = Path("key").read_bytes()
enc_data = AES.new(key, AES.MODE_CBC, b"\0" * 16).encrypt(data)

Path(sys.argv[2]).write_bytes(enc_data + sig)
