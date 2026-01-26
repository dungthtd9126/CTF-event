# 0xlaugh-ctf-write-up
## new age
- This chall is pretty simple, the program will execute my shellcode
<img width="708" height="323" alt="image" src="https://github.com/user-attachments/assets/f4e71097-bd50-4119-836e-30266b5fbb3e" />
- What make it hard is the seccomp

<img width="817" height="676" alt="image" src="https://github.com/user-attachments/assets/533c79d9-d9dc-4fb3-9f71-9066e9e9cc3c" />

- We can see that the seccomp jailed high byte of our buf when using read / write
- Also, we cant call shell. So our only way is to read flag with some strange syscall
- My method is call openat2 --> 
