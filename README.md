# Lac-CTF

## Tcademy

- My main method of solving this challenge is using tcache poisoning and heap overflow to leak libc, heap base then fsop to shell

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

- I'll use index 1 as a victim, the overlapped chunk, Index 0 as a expliting chunk

<img width="679" height="754" alt="image" src="https://github.com/user-attachments/assets/a803d725-cda0-40de-a25a-d2d3ecbd33a5" />
