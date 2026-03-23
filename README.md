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
