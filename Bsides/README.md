# Bsidessf CTF
## read_me
### Analyze
This challenge has <b> arbitrary write / read and buffer overflow </b>

Security of challenge:
```
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

The program will read 3 inputs of user and stores it in <b> option, offset and v6 </b> value

```
while ( fgets(option, 32, stdin)
    && (option[0] == 'r' || option[0] == 'w' || option[0] == 'h')
    && fgets(offset, 32, stdin)
    && fgets(v6, 32, stdin) )
```
After that, it will change our <b> input string </b> in <b> offset </b> and <b> v6 </b> variable into that exact hex value in the program's internal data and stores inside 'buf' and 'num' variables
```
buf = (void *)strtoll(offset, 0, 16);
num = strtol(hex, 0, 16);
```
For example, if I input offset = 3636, it will stores 0x3636 into <b> buf </b>  variable after executing strtoll

So if I choose 'r', it will see 0x3636 as an address and try to see the value inside it. relating to it, num act as how many bytes I want the program to print
```
write(fd, buf, num); // fd = 1
```
'h' option works almost the same with 'r' one. The only different is it uses <b> 'memcpy' </b> function with src and num controlled by the user
```
memcpy(dest, buf, num);
```
because I can control num, I has ability to trigger bof by set num so big that it will overwrite saved rip, replacing it with win function in this challenge
### Exploit

My method is pretty simple, leak libc and stack by option 'r':
```
num = 8
1. buf = exe.got.gets --> leak libc
2. buf = libc.sym.environ --> leak stack
```
Although option 'h' copies my data from <b> buf </b> into 'dest' array, I still can overwrite 'saved rip' by copy large bytes (num) to fill the offset to <b> SAVED RIP </b> with padding bytes then successfully overwrite 'saved rip'
```
buf = fake_saved_rip_stack - padding_byte
num = can be very large, I use 0x312 in this case
```
Fake RIP can be written in 'option' variable at the same time I enter my choice
```
fake_rip = win_address
'h' * 8 + p64(fake_rip)
```
Then just input something to make it breaks the loop and enjoy the flag!!

## readwrite
This challenge has the same security with the one above and eventually a lot easier!!

The program now has option 'w', real arbitrary writing
```
case 'w':
        for ( j = 0; j < num; fprintf(stderr, "%d\n", j) )
        {
          v10 = fread((char *)buf + (int)j, 1u, num - j, stdin);
          if ( !v10 )
            exit(0);
          j += v10;
        }
        break;
```
With this, I'll just replace GOT of <b> fgets function </b> with address of <b> Win function </b>

Then the next time it calls fgets, it calls our Win function!!
## readwriteme
This is the same program like <b> readwrite </b> above. The only difference is the existence of Win function

### Method 1
Combining 2 methods from others, I'll leak libc, stack by method 1 (read_me) then arbitrary write with method 2 (readwrite). My target is rop chain to shell, so I'll focus on writing to 'saved_rip' and below it

### Method 2
There is another way to win, using only bof and arbitrary read like 'readme' program. This requires me to calculate some math to make 'memcpy' not overwrite my own rop chain

I'll first write system and ret gadget (stack alignment) at the bottom. Then write pop rdi and pointer to '/bin/sh' exactly before it (require correct num to not overwrite gadgets below)

## name-me
This is a pwn-reverse challenge so we have to reverse and rename all the function and variables before exploiting the binary
### The code after reversing
- main:
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *argument; // rax
  char *third_chunk; // rbx
  unsigned int fd; // eax
  u32 *v6; // r8
  u32 v7; // r9d
  signed __int64 num; // rbp
  char *buf; // rbx
  unsigned int fd_1; // eax
  unsigned __int8 get_opcode; // [rsp+1Fh] [rbp-69h]
  __int16 swap1; // [rsp+28h] [rbp-60h]
  __int16 swap2; // [rsp+2Ah] [rbp-5Eh]
  unsigned __int16 swap3; // [rsp+2Ch] [rbp-5Ch]
  unsigned int res; // [rsp+34h] [rbp-54h]
  signed __int64 offset; // [rsp+38h] [rbp-50h]
  unsigned __int64 chunk_4; // [rsp+40h] [rbp-48h]
  char **second_chunk; // [rsp+50h] [rbp-38h]
  __int16 v20; // [rsp+5Eh] [rbp-2Ah]
  unsigned __int64 v21; // [rsp+60h] [rbp-28h]
  __int64 i; // [rsp+68h] [rbp-20h]
  unsigned __int64 j; // [rsp+68h] [rbp-20h]

  set_vbuf(stdout, 0, 2, 0);
  set_vbuf(stderr, 0, 2, 0);
  putchar('\n');
  if ( argc <= 1 )
    argument = "host.list";
  else
    argument = argv[1];
  get_host_list(argument);
  second_chunk = (char **)malloc(0x20);
  *second_chunk = (char *)malloc(0x400);        // create third chunk and store in second_heap_ptr
  second_chunk[1] = *second_chunk;              // start 0x400 chunk
  second_chunk[2] = 0;
  second_chunk[3] = *second_chunk + 0x400;      // end of 0x400 chunk
  third_chunk = *second_chunk;                  // stores 0x400 chunk
  fd = get_fd(stdin);
  second_chunk[3] = &(*second_chunk)[read(fd, third_chunk, 0x400u)];
  swap1 = chunk_set_idx_1((__int64)second_chunk);// it takes and swaps the first 2 bytes of idx[1]
                                                // of input string
                                                // Then  gives the pointer of the third char
                                                //  of the string in chunk_idx[1]
                                                // Then return the swapped bytes
  swap2 = chunk_set_idx_1((__int64)second_chunk);
  if ( swap2 < 0 )
  {
    sub_410F20((__int64)"ERROR: Received a response!\n", 1u, 28, (__int64)stderr, v6, v7);
    exit(1);
  }
  get_opcode = ((unsigned __int16)swap2 >> 11) & 0xF;
  if ( get_opcode )
  {
    printf(stderr, "ERROR: Unexpected opcode: %d\n", get_opcode);
    exit(1);
  }
  if ( (swap2 & 0xF) != 0 )                     // rcode check
  {
    printf(stderr, "ERROR: Unexpected rcode: %d\n", swap2 & 0xF);
    exit(1);
  }
  swap3 = chunk_set_idx_1((__int64)second_chunk);
  chunk_set_idx_1((__int64)second_chunk);
  chunk_set_idx_1((__int64)second_chunk);
  chunk_set_idx_1((__int64)second_chunk);
  chunk_4 = malloc(12LL * swap3);
  v21 = 0;
  printf(stderr, "Questions: %d\n", swap3);
  v20 = 0;
  for ( i = 0; i < swap3; ++i )
  {
    printf(stderr, "\n** Question %ld\n", i);
    offset = second_chunk[1] - *second_chunk;
    res = answer(second_chunk);                 // bug function
    if ( second_chunk[1] >= second_chunk[3] )
      exit(1);
    if ( res )
    {
      *(_WORD *)(12 * v21 + chunk_4) = offset;
      *(_WORD *)(12 * v21 + chunk_4 + 2) = 1;
      *(_WORD *)(12 * v21 + chunk_4 + 4) = 1;
      *(_DWORD *)(12 * v21++ + chunk_4 + 8) = swap_4_byte(res);
    }
    else
    {
      v20 |= 3u;
    }
  }
  second_chunk[2] = second_chunk[1];
  second_chunk[1] = *second_chunk;
  swap_v2((unsigned __int64)second_chunk, swap1);
  swap_v2((unsigned __int64)second_chunk, v20 | 0x8000);
  swap_v2((unsigned __int64)second_chunk, swap3);
  swap_v2((unsigned __int64)second_chunk, v21);
  swap_v2((unsigned __int64)second_chunk, 0);
  swap_v2((unsigned __int64)second_chunk, 0);
  second_chunk[1] = second_chunk[2];
  for ( j = 0; j < v21; ++j )
  {
    swap_v2((unsigned __int64)second_chunk, *(_WORD *)(12 * j + chunk_4) | 0xC000);
    swap_v2((unsigned __int64)second_chunk, 1);
    swap_v2((unsigned __int64)second_chunk, 1);
    swap_4_byte_v2((unsigned __int64)second_chunk, 0x1000u);
    swap_v2((unsigned __int64)second_chunk, 4);
    swap_4_byte_v2((unsigned __int64)second_chunk, *(_DWORD *)(12 * j + chunk_4 + 8));
  }
  num = second_chunk[1] - *second_chunk;
  buf = *second_chunk;
  fd_1 = get_fd(stdout);
  write(fd_1, buf, num);
  free((__int64)second_chunk);
  return 0;
}
```
- Answer function:
```
__int64 __fastcall answer(_QWORD *second_chunk)
{
  __int64 idx; // rbp
  unsigned __int8 copy_num; // bl
  __int64 idx_end; // rax
  unsigned __int8 *ptr_idx_1; // rax MAPDST
  u32 *v8; // r8
  u32 v9; // r9d
  char buf[1030]; // [rsp+10h] [rbp-428h] BYREF
  unsigned __int16 math; // [rsp+416h] [rbp-22h]
  unsigned __int64 i; // [rsp+418h] [rbp-20h]

  memset((__int64)buf, 0, 1028);
  *(_WORD *)&buf[1026] = -1;
  *(_WORD *)&buf[1024] = -1;
  idx = 0;
  second_chunk[2] = 0;
  ptr_idx_1 = (unsigned __int8 *)second_chunk[1];// ptr[1] is ptr to the start of third chunk
  second_chunk[1] = ptr_idx_1 + 1;              // ptr[1] = ptr[1] + 1
  for ( copy_num = *ptr_idx_1; copy_num; copy_num = *ptr_idx_1 )// ptr is address of second chunk
                                                // 'i' is input from user
                                                // Each time it loops, it takes the next byte of input
  {
    if ( (copy_num & 0xC0) == 0xC0 )
    {
      ptr_idx_1 = (unsigned __int8 *)second_chunk[1];
      second_chunk[1] = ptr_idx_1 + 1;
      math = ((copy_num << 8) | *ptr_idx_1) & 0x3FFF;
      if ( !second_chunk[2] )
        second_chunk[2] = second_chunk[1];
      second_chunk[1] = math + *second_chunk;
    }
    else
    {
      if ( (copy_num & 0x80u) != 0 )
      {
        printf(stderr, "Illegal label: 0x%02x\n", copy_num);
        exit(1);
      }
      if ( (unsigned __int64)copy_num + second_chunk[1] >= second_chunk[3] )// check if our copy_num > size 
                                                // of the third chunk
        return 0;
      memcpy((__int64)&buf[idx], second_chunk[1], copy_num);
      second_chunk[1] += copy_num;              // add the pointer with copy num
      idx_end = copy_num + idx;
      idx = idx_end + 1;
      buf[idx_end] = '.';
      buf[idx_end + 1] = 0;
    }
    ptr_idx_1 = (unsigned __int8 *)second_chunk[1];
    second_chunk[1] = ptr_idx_1 + 1;
  }
  buf[idx - 1] = 0;
  if ( second_chunk[2] )
    second_chunk[1] = second_chunk[2];
  if ( (unsigned __int64)(second_chunk[1] + 4LL) >= second_chunk[3] )
    return 0;
  *(_WORD *)&buf[1024] = chunk_set_idx_1((__int64)second_chunk);
  *(_WORD *)&buf[1026] = chunk_set_idx_1((__int64)second_chunk);
  printf(stderr, "Question received: %s\n", buf);
  for ( i = 0; i < qword_4AC4E0; ++i )          // i < 0x68
  {
    if ( !(unsigned int)strcmp((char *)&host_list + 132 * i, buf) )
    {
      printf(stderr, "  Answer -> %08x!\n", dword_4A8360[33 * i]);
      return (unsigned int)dword_4A8360[33 * i];
    }
  }
  sub_410F20((__int64)"  Host not found!\n", 1u, 18, (__int64)stderr, v8, v9);
  return 0;
}
```
### Explaination

The reason I only show the code of <b> main </b> and <b> answer </b> function is they're exploitable and important

First of all, <b> main </b> go through some rocode and opcode checks. We can easily bypass this by send 4 NULL bytes. After that, send another 8 random bytes to makes chunk_set_idx_1 works like normal
- chunk_set_idx_1:
```
__int64 __fastcall chunk_set_idx_1(__int64 ptr)
{
  __int64 result; // rax

  if ( (unsigned __int64)(*(_QWORD *)(ptr + 8) + 2LL) >= *(_QWORD *)(ptr + 24) )
    return 0xFFFFFFFFLL;
  LOWORD(result) = swap(**(unsigned __int16 **)(ptr + 8));
  *(_QWORD *)(ptr + 8) += 2LL;
  return (unsigned __int16)result;
}
```
This function contains another one named swap. 'swap' works like its name, it swaps the position of 2 bytes value which is stored in a specifed poiner. After that, the pointer of our buf go forward by <b> 2 </b>

Because <b> answer </b> is the main bug function so I will go in details with it!!

our main exploit is in the for loop
```
...................................
for ( copy_num = *ptr_idx_1; copy_num; copy_num = *ptr_idx_1 )// ptr is address of second chunk
                                                // 'i' is input from user
                                                // Each time it loops, it takes the next byte of input
  {
    if ( (copy_num & 0xC0) == 0xC0 )
    {
      ptr_idx_1 = (unsigned __int8 *)second_chunk[1];
      second_chunk[1] = ptr_idx_1 + 1;
      math = ((copy_num << 8) | *ptr_idx_1) & 0x3FFF;
      if ( !second_chunk[2] )
        second_chunk[2] = second_chunk[1];
      second_chunk[1] = math + *second_chunk;
    }
...
      memcpy((__int64)&buf[idx], second_chunk[1], copy_num);
      second_chunk[1] += copy_num;              // add the pointer with copy num
      idx_end = copy_num + idx;
      idx = idx_end + 1;
      buf[idx_end] = '.';
      buf[idx_end + 1] = 0;
    }
    ptr_idx_1 = (unsigned __int8 *)second_chunk[1];
    second_chunk[1] = ptr_idx_1 + 1;
  }
...................................
```
This loop takes each bytes of our input from current buf pointer and compare it with some conditions

For example, 
``` if ( (copy_num & 0xC0) == 0xC0 ```
. If this condition satisfies, the program will let us control the pointer in idx 1 by our next input

<b> copy_num </b> is our input in 1 byte size

If the condition above not satisfied, it will check another 2 condition:
```
  if ( (copy_num & 0x80u) != 0 )
      {
        printf(stderr, "Illegal label: 0x%02x\n", copy_num);
        exit(1);
      }
      if ( copy_num + second_chunk[1] >= second_chunk[3] )// check if our copy_num > size 
                                                // of the third chunk
        return 0;
```
This check prohibited me to input <b> value > 0x7f </b>, it means <b> copy_num 
<= 0x7f </b>

The next check ensure that we don't copy bytes outside of the third chunk (our input area)

To ensure that I can copy largae bytes <= 0x7f, I use ```load.ljust``` with my payload to make second_chunk[3] as large as I want to avoid <b> the second check of else statement </b>
```
second_chunk[3] = &(*second_chunk)[read(fd, third_chunk, 0x400u)];
``` 
With the ability of control <b> second_chunk[1] </b> and <b> copy_num </b>, I can easily trigger bof because the program keeps trigger memcpy <b> &buf[idx] </b> as a destination. More of that, idx increases based on our copied bytes, respectively
```
idx_end = copy_num + idx;
idx = idx_end + 1;
```
Here is when it gets more complex. After it called memcpy, the ptr of third chunk += copy_num. So I have to adjust my input to write valid and helpful input at that exact place to continue my domination

After controlling the program to memcpy until overwriting saved rip, I will adjust may payload again so that it can overwrite the value I want at right place in stack

Because the program doesn't give libc nor dockerfiel, I'll use rop chain to call shell

This program only let me control saved rsi, rdx, rbx and rax, the only thing left is rdi

After debugging carefully, I realised that rdi will point to <b>the start of  destination  pointer </b>after executing memcpy. That means I can control my input to make it copies the exact string '/bin/sh\0' at the top combines with my rop chain, overwriting saved rip in one memcpy. Then let the program return by set 
``` 
copy_num + second_chunk[1] >= second_chunk[3] 
```
<img width="1202" height="967" alt="image" src="https://github.com/user-attachments/assets/c57992a9-9eff-47d3-80aa-2bd935c0713c" />

Finally, enjoy the flag!!
<img width="1920" height="464" alt="image" src="https://github.com/user-attachments/assets/0722c5ef-912b-4c76-8993-ac8f98004a23" />
