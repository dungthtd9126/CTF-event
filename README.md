# nullcon-ctf
## atomizer
- This is a shellcode challenge, it let me write my own shellcode then the program will execute my shellcode
<img width="1664" height="604" alt="image" src="https://github.com/user-attachments/assets/518979a4-772e-4933-9024-d71bd20aa60f" />

## asan-bazar
- A fmt str challenge, it's only difficulty is the decompiled code is pretty hard to read

- So I'll combine debugging and ida reading to understand the program

- It has 2 bugs, fmt str and OOB

- The challenge also reads 5 inputs from user

- The first input is fmt str, I'll leak libc from there

- Then the next 2 inputs are offset chosen by user, idx and slot

<img width="912" height="96" alt="image" src="https://github.com/user-attachments/assets/0bfa97ce-6b99-402d-af1b-25afcb63965e" />

- After that, the challenge will calculate some math like above and use 'read_base_addr + math' as an address we will write, in the last read input

- When we choose idx: 23, slot, 8. our read address will be in exact saved rip of current function, greeting

- So we can overwrite saved rip with one gadget and done the challenge

- Note that the third input should be 8 to have the ability to write 8 bytes
