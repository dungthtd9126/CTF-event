import socket
import re
from ast import literal_eval
from sage.all import *

HOST = 'chall.blackpinker.com'
PORT = 20147

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
    except Exception:
        return False
        
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
        
        # Lấy Hint
        e_matches = re.findall(r"E\[\d+\]:\s*(-?\d+)", res_str)
        E_hints = [int(x) for x in e_matches]
        if len(E_hints) < 2: return False
        
        C1s = [literal_eval(c) for c in c1_matches]
        C0s = [literal_eval(c) for c in c0_matches]
    except Exception:
        s.close()
        return False
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
    try:
        S_mod = (At * A_mod_mat).solve_right(At * Y_vec)
    except Exception:
        # Xảy ra khi r không nguyên tố làm hệ pt vô nghiệm, ta bỏ qua và thử lại
        return False
        
    S_mod_ints = [int(x) for x in S_mod]

    A_real_list, V_real_list = [], []
    for i in range(10):
        M_a = get_matrix(C1_centered[i], 16)
        A_real_list.append(M_a)
        V_real_list.extend(list((vector(QQ, C0_centered[i]) - M_a * vector(QQ, S_mod_ints)) / r))

    A_real_mat = block_matrix(10, 1, A_real_list)
    k_approx = (A_real_mat.transpose() * A_real_mat).inverse() * A_real_mat.transpose() * vector(QQ, V_real_list)
    k = [round(x) for x in k_approx]
    S_exact = [S_mod_ints[i] + k[i] * r for i in range(16)]

    # 2. LLL tìm đa thức B
    M_S0, M_S1 = get_matrix(S_exact[:8], 8), get_matrix(S_exact[8:], 8)
    A_LWE = block_matrix(1, 2, [M_S1, -M_S0])
    
    L = block_matrix([
        [identity_matrix(ZZ, 16), matrix(ZZ, A_LWE.transpose())],
        [zero_matrix(ZZ, 8, 16), q0 * identity_matrix(ZZ, 8)]
    ])
    
    B_vec = None
    for row in L.LLL():
        if all(x in [-1, 0, 1] for x in row[:16]) and any(x != 0 for x in row[:16]):
            B_vec = list(row[:16])
            break
    if not B_vec: return False

    # 3. CVP tìm Vector v (chính là B * T) có sử dụng HINTS
    M_B0, M_B1 = get_matrix(B_vec[:8], 8), get_matrix(B_vec[8:], 8)
    G = block_matrix([
        [block_matrix(1, 2, [M_B0.transpose(), M_B1.transpose()])],
        [q0 * identity_matrix(ZZ, 16)]
    ])
    
    W_lock = 10**20  # Trọng số khổng lồ để ép CVP khóa chặt 2 giá trị đầu
    G_scaled = matrix(ZZ, G)
    for j in range(24):
        G_scaled[j, 0] *= W_lock
        G_scaled[j, 1] *= W_lock
        
    # Target CVP vector là S_exact, được scale ở 2 tọa độ đầu theo hint nhiễu
    T_scaled = list(S_exact)
    T_scaled[0] = (S_exact[0] - E_hints[0]) * W_lock
    T_scaled[1] = (S_exact[1] - E_hints[1]) * W_lock
    
    W_cvp = 100
    L_cvp = block_matrix([
        [G_scaled, zero_matrix(ZZ, 24, 1)],
        [matrix(ZZ, 1, 16, T_scaled), matrix(ZZ, 1, 1, [W_cvp])]
    ])
    
    v_scaled = None
    for row in L_cvp.LLL():
        if row[-1] == W_cvp:
            v_scaled = list(row[:-1])
            break
        elif row[-1] == -W_cvp:
            v_scaled = [-x for x in row[:-1]]
            break
            
    if not v_scaled: return False
    
    # 4. Phục hồi K và kiểm tra chuẩn
    v_L = list(v_scaled)
    v_L[0] = v_L[0] // W_lock
    v_L[1] = v_L[1] // W_lock
    
    # Kính thưa các loại vector, K thực sự là S_exact - v_L
    K_vec = [int(S_exact[i] - v_L[i]) for i in range(16)]
    
    # Nếu nhiễu K vượt quá 100 thì mới báo lỗi Least Squares
    if any(abs(k) > 100 for k in K_vec):
        return False
        
    # Phục hồi T
    R_q0 = IntegerModRing(q0)
    M_B_mod = matrix(R_q0, block_matrix(2, 1, [M_B0, M_B1]))
    V_mod = vector(R_q0, v_L)
    try:
        T_exact = [int(x) for x in M_B_mod.solve_right(V_mod)]
    except Exception:
        return False

    # 5. Dò Shift qua Sorted Properties và Giải Mã Cờ
    best_T = None
    for T_cand in get_negacyclic_shifts(T_exact):
        T_pos = [int(t) % q0 for t in T_cand]
        is_sorted = all(T_pos[i] <= T_pos[i+1] for i in range(len(T_pos)-1))
        
        if is_sorted:
            best_T = T_cand
            break

    if not best_T:
        return False

    flag_bytes = decrypt_with_T(best_T, q0, enc_flag2_hex)
    raw_str = flag_bytes.decode(errors='ignore').rstrip('\x00')
    
    print("\n" + "="*50)
    print("🚀 ĐÃ KHÓA LƯỚI THÀNH CÔNG NHỜ HINTS!")
    print(f"FLAG TÌM ĐƯỢC CHÍNH XÁC LÀ: HCMUS-CTF{{{raw_str}}}")
    print("="*50 + "\n")
    return True

if __name__ == '__main__':
    print("[*] Đang khởi động mạng lưới CVP (Precision Mode)... Vui lòng chờ")
    while not attempt_solve():
        pass