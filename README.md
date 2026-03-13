# Apoorv-CTF
## havok
- This challenge has 2 main bugs: bof and integer bug

<img width="1903" height="351" alt="image" src="https://github.com/user-attachments/assets/4baec6cd-ceba-407e-8d1f-462f9c958838" />


- We can see integer bug in calibrate_rings function if look carefully

<img width="1529" height="859" alt="image" src="https://github.com/user-attachments/assets/48d9a596-62c2-4149-9bfc-dd723429bd81" />

- It is pretty hard to see that bug in this challenge

- The bug is in this num check line: <b> "if ( (__int16)raw > 3 )" </b>

- If look carefully, you can see it check (_int16) type of raw. That means it check 2 least significant bytes of 'raw' number

- After that condition check, it also print frame.ring_data[(__int16)raw])

- We can easily control this to oob by enter some number like this: 0x50ffff

- It will bypass the first check 'raw >= 0'

- Then it will only check if '0xffff < 3'

- Because 0xffff = -1 in 2 byte term so it is supposed to less than 3

- And because it succesfully bypass 2 checks, we got oob data leak --> leak libc

<img width="1114" height="646" alt="image" src="https://github.com/user-attachments/assets/c451acff-f6ff-4ca8-9914-7a1f64a54db9" />

- This program also call 'calibrate_rings' 2 times --> leak both libc and binary

- The last bug is in the last function call too: bof

<img width="1155" height="687" alt="image" src="https://github.com/user-attachments/assets/7b746846-d89b-4587-9ee7-f3de2c54a696" />

- This function is pretty special, it has no canary check

- That means i can just overwrite rbp and saved rip to stack pivot to my rop chain

- I can write my rop chain + shellcode in bss area with the len 0x100

<img width="1490" height="430" alt="image" src="https://github.com/user-attachments/assets/59ca4303-d94d-47fb-83b0-bdfbdf16481b" />


- Now the challenge get trickier, it block shell call so i have to use mprotect + shellcode to leak flag

<img width="767" height="514" alt="image" src="https://github.com/user-attachments/assets/cc323c05-fb02-4d49-a3c7-44770e0bd4b1" />

- My method is pretty simple, i'll rop chain to call mprotect to change permission of my rop chain area to 'rwx'

<img width="1287" height="823" alt="image" src="https://github.com/user-attachments/assets/0d3074a6-267e-4dee-97ef-0616e380759a" />

- Then go back to my shellcode and execute it 

- The last problem is the challenge also block 'syscall' byte so i can't write 'syscall' shellcode directly

<img width="950" height="461" alt="image" src="https://github.com/user-attachments/assets/fb5e3d8d-e13a-4962-877d-880812604e57" />

- That's why I'll use other register to find and call syscall by 'jmp' or 'call' shellcode at the moment

- In this case, I uses rcx because if i add 0x1d to it, it become a syscall gadget

<img width="699" height="312" alt="image" src="https://github.com/user-attachments/assets/d79f9c7c-fc54-46d5-abd6-ee0137a497a3" />

- With that trick, the last block is bypassable now. Enjoy the flag!

<img width="1270" height="952" alt="image" src="https://github.com/user-attachments/assets/dd325d1c-beda-4c2e-ad00-b519e83d180a" />

## house_of_wade

- This is a basic heap challenge, 
