# Lac-CTF

## Tcademy

- My main method of solving this challenge is using tcache poisblankingoning and heap overflow to leak libc, heap base then fsop to shell

### Heap overflow

- The first bug of this challenge is logic fault

- This results in heap overflow

<img width="1553" height="851" alt="image" src="https://github.com/user-attachments/assets/90a79401-73cd-4adb-a1c3-e7ecff592b63" />

- The bug is at the line 51, we can choose the size of our note

- The program will then malloc that size and trigger function 'read_data_into_note'

- This function will check if our size == 8 and stores 'size - 7 / 8' into 'resized_size'

- Here is when it got logic fault, if we choose the size to be < 8, it will results in a negative number

- But the type of 'resized_size' variable is unsigned short. So if i choose the size to be '0' then '0 - 8 = -8', it will store as '0xfff8'

- And the program will use that variable as our input amount, so a serious heap overflow happens here

### leak libc

- My first target is to leak libc, as you can see in the picture, I can choose note index to create / delete / read

- This program only allow me to use index 0 and 1

- I'll use index 1 as a victim, the overlapped chunk, Index 0 as a exploit chunk

<img width="679" height="754" alt="image" src="https://github.com/user-attachments/assets/a803d725-cda0-40de-a25a-d2d3ecbd33a5" />

- My aim is to resize the victim chunk to 0x521  then free it to make the chunk go to unsorted bin for the libc leak

- First, i need to make top chunk stay below my resized chunk. If not, the program will catch heap corruption when i malloc the overlapped chunk

- To avoid that, I'll spam malloc chunk with different size then free all of it. I'll call this method as padding chunks

<img width="447" height="407" alt="image" src="https://github.com/user-attachments/assets/518152da-1096-480c-9edb-17bc5410d9e7" />

- The program will then place top chunk at the bottom of my padding chunks

<img width="1195" height="1053" alt="image" src="https://github.com/user-attachments/assets/b423bc67-275d-4f61-a834-c980256f0545" />

##### heap leak

<img width="1240" height="927" alt="image" src="https://github.com/user-attachments/assets/aeb8d85c-86c8-4970-bb88-0a0237031ee3" />

- The picture above is heap layout of program after I padded chunks

- You can see that my idx 0 is in the top of heap layout because i created it first, the next chunk is idx 1

- Because i chose the size of both beflow 0x10 so the program allocate 0x21 size chunk as the smallest size

- If i choose to create another chunk with size of 0, ill get control all of chunks below because of heap overflow

- I'll first get heap leak by padding 'A' to address '0x55555555b2c0' then print note of idx 0

<img width="439" height="128" alt="image" src="https://github.com/user-attachments/assets/ab81274f-20fb-42cf-a47c-e4307dd27b01" />

- The program will print '0x000000055555555b', which is 'heap base >> 12'

<img width="981" height="184" alt="image" src="https://github.com/user-attachments/assets/75ffa482-83d6-4af7-a7e2-da9fde63230c" />

- At this stage, I got heap base leak

<img width="961" height="286" alt="image" src="https://github.com/user-attachments/assets/331454b3-6816-4d02-ac41-ec9afbed5332" />

- Go back to the main flow, I'll use that same method to resize the next chunk.

- From the picture above, we can easily see that method can resize my victim chunk too

- The next step is deleting idx 0 and malloc it with size 0 again to change the size

<img width="952" height="332" alt="image" src="https://github.com/user-attachments/assets/ae05a2ef-572e-4e61-b3b0-0ad8af8ad1f9" />

- Then create idx 1 with size '0' because it is known as a 0x21 size chunk and storing in the tcachebin bin at that moment

- So it doesnt matter if i overwrote its size when it is in freed state, the chunk will be reused whenever i malloc(size<=0x10)

- After reused that chunk, free it to make it go to unsorted bin because its size now is 0x521 

<img width="1215" height="288" alt="image" src="https://github.com/user-attachments/assets/4cb22355-92e6-49a7-bcd7-f42bdd51399d" />

- Then use the same heap leak method to leak libc and get libc base

### fsop

- After all of processes above, I got libc base and heap leak. In other words, I had full control of libc and heap layout

- Because this chall has heap overflow, I can tcache poison to overwrite stderr structre as my target

- The reason is when the program exit, it will call IO_flush_all

<img width="987" height="662" alt="image" src="https://github.com/user-attachments/assets/336f951e-bb73-4b27-9b81-646ce16e8e85" />

- This func will check each file structure in _IO_list_all array

<img width="1402" height="340" alt="image" src="https://github.com/user-attachments/assets/28e96164-9614-4f35-a3d4-66533a5c33d5" />

- It uses chain as the next file structure to check

- My target is triggering the if statement: calling _IO_OVERFLOW by set 'mode = 0 and write_ptr > write_base'

    - _IO_OVERFLOW is a macro, calling the vtable of that current IO file

- The next step is using the method showed in the picture below to bypass vtable check

<img width="1560" height="657" alt="image" src="https://github.com/user-attachments/assets/6764cd9b-9f9e-4925-b713-84473a38f59d" />

- file.vtable in this case is stderr.vtable, I'll overwrite it to make it call _IO_wfile_overflow --> calling do_allocbuf --> calling 'wide_data-->vtable' with no vtable check

- I'll overwrite stderr struct in the following steps:

    - Flags: 0x3b01010101010101
    - _IO_read_ptr: 'sh''
    - write_ptr: anyvalue
    - write_base: 0
    - lock: any address that has 8 byte null
    - mode: 0
    - vtable: _IO_wfile_overflow

 - After that, i just need to 
