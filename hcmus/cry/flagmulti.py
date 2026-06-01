import socket
import re
from ast import literal_eval
from sage.all import *
import time

HOST = 'chall.blackpinker.com'
PORT = 20458

def get_matrix(poly_list, dim):
    M = matrix(ZZ, dim, dim)
    for i in range(dim):
        for j in range(dim):
            if i >= j:
                M[i, j] = poly_list[i - j]
            else:
                M[i, j] = -poly_list[dim + i - j]
    return M

def center_mod(val, mod):
    val = val % mod
    if val > mod // 2:
        val -= mod
    return val

def get_negacyclic_shifts(T_list):
    n = len(T_list)
    shifts = []
    for k in range(n):
        shifted = []
        for i in range(n):
            if i < k:
                shifted.append(-T_list[n - k + i])
            else:
                shifted.append(T_list[i - k])
        shifts.append(shifted)
        shifts.append([-x for x in shifted])
    return shifts

def decrypt_with_T(T_list, q0, enc_flag_hex):
    T_signed = []
    for t in T_list:
        t = int(t) % q0
        if t > q0 // 2:
            T_signed.append(t - q0)
        else:
            T_signed.append(t)
            
    key_bytes = []
    for t in T_signed:
        for j in range(8):
            key_bytes.append((t >> (j * 8)) & 0xff)
            
    enc_bytes = bytes.fromhex(enc_flag_hex)
    flag = bytearray()
    for i in range(len(enc_bytes)):
        flag.append(enc_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return flag

def attempt_solve():
    s = socket.socket()
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        return None
        
    def recv_until(prompt):
        data = b''
        while prompt.encode() not in data:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        return data.decode()

    try:
        recv_until("===\n")
        s.sendall(b"PARAMS\n")
        res = b""
        while b"Encrypted flag:" not in res:
            res += s.recv(4096)
        res_str = res.decode()
        
        q = int(re.search(r"q:\s*(\d+)", res_str).group(1))
        q0 = int(re.search(r"q0:\s*(\d+)", res_str).group(1))
        enc_flag2_hex = re.search(r"Encrypted flag:\s*([0-9a-f]+)", res_str).group(1)
        
        s.sendall(b"CHALLENGE 10 0\n")
        res = b""
        while b"E[" not in res:
            res += s.recv(4096)
        res_str = res.decode()

        r = int(re.search(r"r:\s*(\d+)", res_str).group(1))
        c1_matches = re.findall(r"C1:\s*(\[.*?\])", res_str)
        c0_matches = re.findall(r"C0:\s*(\[.*?\])", res_str)
        
        C1s = [literal_eval(c) for c in c1_matches]
        C0s = [literal_eval(c) for c in c0_matches]
    except Exception:
        s.close()
        return None
    finally:
        s.close()

    # 1. Phục hồi S_exact
    C1_centered = [[center_mod(x, q) for x in C1] for C1 in C1s]
    C0_centered = [[center_mod(x, q) for x in C0] for C0 in C0s]
    
    R_mod = IntegerModRing(r)
    A_mod_list, Y_mod_list = [], []
    for i in range(10):
        M_a = get_matrix(C1_centered[i], 16)
        A_mod_list.append(matrix(R_mod, M_a))
        Y_mod_list.extend(C0_centered[i])

    A_mod_mat = block_matrix(10, 1, A_mod_list)
    Y_vec = vector(R_mod, Y_mod_list)
    
    At = A_mod_mat.transpose()
    S_mod = (At * A_mod_mat).solve_right(At * Y_vec)
    S_mod_ints = [int(x) for x in S_mod]

    A_real_list, V_real_list = [], []
    for i in range(10):
        M_a = get_matrix(C1_centered[i], 16)
        A_real_list.append(M_a)
        S_mod_vec = vector(QQ, S_mod_ints)
        C0_vec = vector(QQ, C0_centered[i])
        V_real_list.extend(list((C0_vec - M_a * S_mod_vec) / r))

    A_real_mat = block_matrix(10, 1, A_real_list)
    V_vec = vector(QQ, V_real_list)
    
    k_approx = (A_real_mat.transpose() * A_real_mat).inverse() * A_real_mat.transpose() * V_vec
    k = [round(x) for x in k_approx]
    S_exact = [S_mod_ints[i] + k[i] * r for i in range(16)]

    # 2. LLL tìm B
    S0, S1 = S_exact[:8], S_exact[8:]
    M_S0, M_S1 = get_matrix(S0, 8), get_matrix(S1, 8)
    A_LWE = block_matrix(1, 2, [M_S1, -M_S0])
    
    L = block_matrix([
        [identity_matrix(ZZ, 16), matrix(ZZ, A_LWE.transpose())],
        [zero_matrix(ZZ, 8, 16), q0 * identity_matrix(ZZ, 8)]
    ])
    
    L_red = L.LLL()
    B_vec = None
    for row in L_red:
        if all(x in [-1, 0, 1] for x in row[:16]) and any(x != 0 for x in row[:16]):
            B_vec = list(row[:16])
            break

    if not B_vec:
        return None

    # 3. CVP tìm K
    B0, B1 = B_vec[:8], B_vec[8:]
    M_B0, M_B1 = get_matrix(B0, 8), get_matrix(B1, 8)
    M_B_T = block_matrix(1, 2, [M_B0.transpose(), M_B1.transpose()])
    
    W = 100
    L_cvp = block_matrix([
        [M_B_T, zero_matrix(ZZ, 8, 1)],
        [q0 * identity_matrix(ZZ, 16), zero_matrix(ZZ, 16, 1)],
        [matrix(ZZ, 1, 16, S_exact), matrix(ZZ, 1, 1, [W])]
    ])
    
    L_cvp_red = L_cvp.LLL()
    K_vec = None
    for row in L_cvp_red:
        if row[-1] == W:
            K_vec = list(row[:-1])
            break
        elif row[-1] == -W:
            K_vec = [-x for x in row[:-1]]
            break
            
    if K_vec is None: 
        return None

    # 4. Phục hồi T
    V = [S_exact[i] - K_vec[i] for i in range(16)]
    R_q0 = IntegerModRing(q0)
    M_B_mod = matrix(R_q0, block_matrix(2, 1, [M_B0, M_B1]))
    V_mod = vector(R_q0, V)
    T_mod = M_B_mod.solve_right(V_mod)
    T_exact = [int(x) for x in T_mod]

    # 5. Duyệt 16 trường hợp Shift và lấy cờ có ASCII đẹp nhất (dù có chứa rác)
    best_flag = None
    best_score = -1
    
    for T_cand in get_negacyclic_shifts(T_exact):
        flag_bytes = decrypt_with_T(T_cand, q0, enc_flag2_hex)
        score = sum(1 for b in flag_bytes if 32 <= b <= 126)
        if score > best_score:
            best_score = score
            best_flag = flag_bytes
            
    if best_flag:
        raw_str = best_flag.decode(errors='ignore').rstrip('\x00')
        return f"HCMUS-CTF{{{raw_str}}}", best_score
        
    return None

if __name__ == '__main__':
    print("=== BỘ CÔNG CỤ THU THẬP FLAG NHIỄU ===")
    try:
        N = int(input("Nhập số lần (N) lấy flag thành công: "))
    except ValueError:
        print("[-] Lỗi: N phải là số nguyên.")
        exit(1)

    success_count = 0
    file_name = "flag_samples.txt"
    
    with open(file_name, "a", encoding="utf-8") as f:
        f.write(f"\n--- Bắt đầu phiên thu thập {N} mẫu ---\n")
        
        while success_count < N:
            print(f"[*] Đang lấy sample thứ {success_count + 1}/{N}...")
            result = attempt_solve()
            
            if result:
                flag_str, score = result
                success_count += 1
                
                # Ghi vào file kèm điểm số (số ký tự ASCII in được)
                log_line = f"[Score: {score:02d}] {flag_str}"
                f.write(log_line + "\n")
                f.flush() # Đẩy dữ liệu vào file ngay lập tức
                
                print(f"[+] LLL thành công! Đã lưu: {log_line}")
                time.sleep(0.5) # Nghỉ một chút để tránh spam server quá gắt
            else:
                # Bỏ qua những lần xịt mạng lưới và ngầm thử lại
                pass
                
    print(f"\n[+] Thu thập hoàn tất! Kiểm tra file {file_name} để đoán flag cuối cùng.")