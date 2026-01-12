# CTF write up
## scarlet ctf
### 1. speedjournal
- This challenge is quite easy but also need some clever trick to solve
- At first, the only and most obvious bug in this chall is data racing
- When read the source code, we can easily see the flag is in index 0 of log
![image](https://hackmd.io/_uploads/rJYkgfMr-x.png)
- We also have read function to read data in log with index chosen by user
![image](https://hackmd.io/_uploads/rJpMxzGSZe.png)
- As we can see, if is_admin variable is 0 and the restricted section in that idx is != 0 ( which is set to 1 by default at index 0 ) , it will return as access denied
- But if one of requirement is false, we can bypass that and read log at idx 0
![image](https://hackmd.io/_uploads/HJ17WMfrWe.png)
- We can see that there is a function name as login_admin
- This function will change is_admin to 1
- It will call logout_thread and wait 1s to change is_admin to 0 
- So we will apply data racing in this case
- when we login successful, we will use read log as fast as possible
- Ill choose to login admin first, then send multiple steps in one payload to make the program read log as fast as possible.
![image](https://hackmd.io/_uploads/S1diKMfrZe.png)

### ruid_login
- This challenge is quite challenging for me as i need some help from mentor to download libc
- Otherwise, the challenge is quite simple
![image](https://hackmd.io/_uploads/rJo8jzMSbl.png)
- The bug is in the line 16 and 17 of program, it we can write full 64 bytes of read to make it no '\n' in input
- And in the official solve, the author use this way to leak stack as 6 bytes next of 64 bytes is stack address and scrcspn only set null byte to place that has '\n', which the input don't
- But in my own way, i solved a bit more complex because i didnt notice the read function too much
- I solve this challenge by first leak binary and get base binary
- To leak binary, i used dean function
![image](https://hackmd.io/_uploads/B1eF3zfHbg.png)
- It enable me to overwrite function ptr of 'dead' or 'prof'
- In this case, ill not overwrite the binary, ill send 32 bytes 
![image](https://hackmd.io/_uploads/S1wvpGMSWx.png)
- My aim is to leak binary when the main call staff name again in begining of the loop
- After that, ill overwrite prof ptr to 'puts plt'
![image](https://hackmd.io/_uploads/BJCATMMr-g.png)
- As we can see, when call rax - function ptr, rdi is pointing to an address storing stack address in it
- So when the program call rax, we will leak stack
- Then we just need to overwrite function ptr again with stack address that store our shellcode, which i sent before in input
![image](https://hackmd.io/_uploads/HySqAfGSWg.png)
![image](https://hackmd.io/_uploads/ryFsAzMr-l.png)
- I use this method because NX is off
