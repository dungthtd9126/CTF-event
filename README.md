# 0xlaugh-ctf-write-up
## new age
- This chall is pretty simple, the program will execute my shellcode
<img width="708" height="323" alt="image" src="https://github.com/user-attachments/assets/f4e71097-bd50-4119-836e-30266b5fbb3e" />
- What make it hard is the seccomp

<img width="817" height="676" alt="image" src="https://github.com/user-attachments/assets/533c79d9-d9dc-4fb3-9f71-9066e9e9cc3c" />

- We can see that the seccomp jailed high byte of our buf when using read / write
- Also, we cant call shell. So our only way is to read flag with some strange syscall
- My method is call openat2 --> readv --> writev

### openat 2
- openat2 also follows a structure named 'open_how' and the structure has 3 parts:
<img width="1038" height="332" alt="image" src="https://github.com/user-attachments/assets/ee10634a-cd93-4838-8326-b53ad9d09334" />
- And this is how to use it
<img width="845" height="314" alt="image" src="https://github.com/user-attachments/assets/aab6fc87-0b4e-45ef-91db-3b873186ffd2" />
- As you can see in my exploit, ill push 0 three times to create a structure with common value '0' and stores pointer to that section in rdx
- r10 is the size of the struct, rdi is set to -100 to search the current directory
- After call openat2, it will return fd to rax as usual
- Not only that, I used a new function to push long file name: 'shellcraft.pushstr(path)'
- This is a python function that will push a str based on my choice: push "flag_name_Should_Be_R@ndom_ahahahahahahahahah.txt", a very useful function for shellcode
### readv / writev
- readv and writev are alternative way of calling read / wrtie
- These syscalls use a structure called iovec instead of a simple buffer pointer.
```c=
struct iovec {
    void  *iov_base;    /* Starting address */
    size_t iov_len;     /* Number of bytes to transfer */
};
```
- first, ill set rdi = fd of the chosen file
- then ill choose buf addr to store flag of that file, which is rsp at that moment
- Ill save rsp to rsi
- Then create a structure by push it len first, then push rsi as chosen buf
- After that, ill set rsi to current rsp too because it need to be pointer to the iovec structure
- RDX is the number of struct so ill set 1 by default
- Almost done, syscall, the program will write flag to our chosen buf
- Finally, set rdi = 1 as stdout, then change syscall to writev and we'll get flag
- writev don't have to be set up so much because it will use the same atributes of readv, only fd need to be changed

## Zoro
- This challenge is pretty good because i learnt some trick after solved it
- This is a fmt str challenge
- First, it gives me a libc address, i can rely on it to calculate base libc
- Second, i can use fmt str twice. 
- My method is use the first input to fmt str: overwrite value of malloc / free hook to one gadget. I can input a lot bytes in first input so its good to fmt str in thiis step
- The reason is the libc version of binary is 2.23
<img width="785" height="337" alt="image" src="https://github.com/user-attachments/assets/184a55c3-a5bd-469e-b0a8-a85bcfb86181" />
- But the real challenge of this program is the prohibited words
- So i will need to use fmt str in full form like : "%p%p%p"
- With that way, i can easily bypass the probited func and fmt str like normal, i just need to change the method a bit to align the full form fmtstr
- The next input is only 10 bytes, but this is when we trigger malloc / free func to make it call one gadget
- To make printf do that, ill have to use '%10000c", we should padding more than 10.000 words
- The reason is when the padding is too big that overflow the size of allocated buf of program, printf will allocate another chunk / buf that is big enough to store the padding then print it
<img width="850" height="635" alt="image" src="https://github.com/user-attachments/assets/ca3e48f8-ca13-4176-a9b0-25ddddb6a713" />
- After that, The program frees the new chunk to give it back to the top chunk, this is when i get shell by one gadget
- Note that im using free hook so it wil call shell when call free, you can use malloc hook, its the same way too
