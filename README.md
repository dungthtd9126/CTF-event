# AOC2024
## help challenge
- In this program, my main idea is fsop to shell by overwrite on stderr

<img width="745" height="662" alt="image" src="https://github.com/user-attachments/assets/82ce280c-d5d7-406b-9296-1aa503a98333" />


- The main bug of this program is i have unlimited malloc choice
- So i can utilize this to malloc until the address is stored in my input section
- So that i can partial overwrite that address to get arbitrary read/write
- But i need to get heap base first
- To get that, ill use: malloc --> free --> malloc --> puts in the start of program
- the reason is when a chunk free, it will go to tcache cause size is 0x40 in this case
- And after i malloc again, the chunk will be reused

<img width="945" height="244" alt="image" src="https://github.com/user-attachments/assets/711f4fab-917b-422b-af9f-58d35ac97008" />

- As you can see, there will be a heap base that is changed a bit because of the mechanism of safe linking in libc 2.39
- When a chunk free, it will have a section 8 byte length named fd. This fd is encrypted to avoid some heap technique in old libc
- The math of encrypting will be: (pointer >> 12) ^ next_free_chunk
- In this case, there is only one chunk free with size 0x40 so next_free_chunk will be 0
- At this point, the result is (pointer >> 12) ^ 0 = pointer >> 12
- And if we look closely, that is also (heap_base + 0x{n}000) >> 12 with n is the relative offset that we can use to calculate heap base
- In this case, it is the heap base so n = 0

<img width="963" height="603" alt="image" src="https://github.com/user-attachments/assets/434b4dcd-aae6-4ff3-b39c-5832fc6d272b" />

- You can see that the value is '0x000000055555555b', i can just use '0x000000055555555b << 12' to make it back to it base after leak that value using 'puts'
- Next, ill spam malloc until malloc address stored in my input section

<img width="1073" height="583" alt="image" src="https://github.com/user-attachments/assets/11df78b8-a899-4bcd-af3a-c1452a82ca42" />

- In the picture above, my input is 'puts' and the address below is a chunk ptr that is overflow to my input section
- Since the program use strcmp so i can just padd b'\0' after puts then it will stop the comparation
- ill overwrite the ptr to aa heap address stores libc
- Then the program will leak libc for me
- At this point ill use fsop
- My main idea is using the same method as leak libc to overwrite stderr by using scanf
- My fsop techinque is set stderr_flag = '0x3b01010101010101' + b'sh'
- b'sh' will be below the flag section
- So that the program will call system('sh;11111...')
- The reason i set the flag '0x3b01010101010101' because when program exit, it will call _IO_flush_all

<img width="987" height="662" alt="image" src="https://github.com/user-attachments/assets/7e369a6c-0a60-4535-b832-1218adde457e" />

- _IO_flush_all is a function that will check each file structure and its sections to do check some conditions and do some function if those conditions are met. Then it will go to another file struct by looking at chain section storing another file struct
- In this exploit, ill try calling _IO_OVERFLOW, which is a macro for some special action 
- The func will call vtable + offset, in this case, it is [rax+0x18], rax is storing my fake vtable

<img width="1331" height="810" alt="image" src="https://github.com/user-attachments/assets/82247c52-b1f6-4ec8-8cf8-92af85c70af8" />

- And if we look closely enough, we can see that our rdi stores flag of file struct almost all the time
- This mean we can use a trick, overwrite fake vtable and set flag as 'sh'
- But before that, we need to make the program call _IO_OVERFLOW. There are 2 ways to make that func being called, but ill use way 1: mode <= 0 and write_ptr > write base

<img width="907" height="213" alt="image" src="https://github.com/user-attachments/assets/72c705aa-0871-434d-a510-874953350a19" />

- Ill set the mode = 0 and fp->_IO_write_ptr > fp->_IO_write_base to meet the condition 1 and trigger _IO_OVERFLOW
- From what i learnt, _IO_OVERFLOW is like a vtable jump of a file structure. So in this case, ill overwrite vtable of stdder for the purpose of jumping to IO_wfile_overflow --> which call doalloc if condition is meet --> Then call vtable of wdata with no vtable check if the condition is meet again
- After all of that progress, when program call vtable of wdata. RDI is storing flag of current file strucure, '0x3b01010101010101'.
- But because i send 'sh' continuously with the flag section, 'sh' will be placed right under that section
- So when it call system, it will be system('sh;111..')
- The reason is '0x3b' is a ';' char
- ';' act as a command separate operator, meaning it call system('sh') first then system('111...')
- Another reaon that '0x3b01010101010101' is because i have to bypass flag check in the program.
- If not, it may not behave like we want
- As we can see, there are 2 flag check in each func, IO_wfile_overflow and doalloc
- to bypass this, we need to set the flag at with value that part of it will joined in a compare math: 'and'


<img width="1403" height="623" alt="image" src="https://github.com/user-attachments/assets/186d62d8-b44d-42bc-90bf-195d261b5317" />
<img width="1379" height="139" alt="image" src="https://github.com/user-attachments/assets/2ba286c2-1252-4f3b-90e2-58f9ad763955" />

 - 'jne' is jump if not equal "or" jump if not zero
- And we dont want it to jump. So ill set each byte = 0x1 so both 'and' math will result in zero, leading program to trigger my final fake vtable in wide data-->vtable section
- As we can see before, rdi is likely storing flag section of IO file

<img width="1385" height="859" alt="image" src="https://github.com/user-attachments/assets/1b533f66-b3a9-4a6d-b222-8576e1b6dd8a" />

- So i will connect string sh with 0x3b01... so program will call system('sh;0101...')

<img width="1832" height="392" alt="image" src="https://github.com/user-attachments/assets/c1259a95-b74c-4bc3-a6e1-28398673ff90" />

- In conclusion, this challenge is the first time i actually use fsop to shell without one gadget, and it taught me alot from set up flag to how _IO_flush_all actually works

 
