# Dice CTF
## Byte crusher

<b> This challenge has OOB and bof </b>

In the beginning, the challenge calls <b> free_trial </b> function, which enables us to control 3 variables:

```
input_buf
rate
output_len
```

- Then it calls:
```
crush_string(input_buf, crushed, rate, output_len);
```

- Which does:
```
void crush_string(char *input, char *output, int rate, int output_max_len) {
    if (rate < 1) rate = 1;
    int out_idx = 0;
    for (int i = 0; input[i] != '\0' && out_idx < output_max_len - 1; i += rate) {
        output[out_idx++] = input[i];
    }
    output[out_idx] = '\0';
}
```
When looks at the loop carefully, you can see that it has OOB writing because you can control <b> 'rate' </b> and <b> 'output_max_len' </b>. So i just need to calculate the exact offset of canary and main address then choose right value of 'rate' variable.

Because this method only enables me to leak a byte in each loop, I'll use 16 loops of the <b> free trial function </b> to leak 16 bytes: canary and binary address

After that, the program calls:
```
void get_feedback() {
    char buf[16];
    printf("Enter some text:\n");
    gets(buf);
    printf("Your feedback has been recorded and totally not thrown away.\n");
}
```
This function has serious bof because of gets's existence so I can just overwrite it's saved rip to <b> Win function </b> 
```
void admin_portal() {
    puts("Welcome dicegang admin!");
    FILE *f = fopen("flag.txt", "r");
    if (f) {
        char read;
        while ((read = fgetc(f)) != EOF) {
            putchar(read);
        }
        fclose(f);
    } else {
        puts("flag file not found");
    }
}
```
## Message store

The decompiled code of this challenge is pretty hard to read as it is coded by <b> rust </b> language

So I'll guessing its bug by typing random input continuously:
```
-- MESSAGE STORER -- 
1) Set Message 
2) Set Message Color 
3) Print Message 
4) Exit 
> 1
New Message? aaaaaaaaaaaa
-- MESSAGE STORER -- 
1) Set Message 
2) Set Message Color 
3) Print Message 
4) Exit 
> 2
-- Message Colors -- 
0) Red 
1) Green 
2) Yellow 
3) Blue 
4) Magenta 
5) Cyan 
6) White 
> 10
-- MESSAGE STORER -- 
1) Set Message 
2) Set Message Color 
3) Print Message 
4) Exit 
> 3
[1]    37600 segmentation fault (core dumped)  ./challenge
```

From the input above, we can easily see that it got segmentation fault after i choose index 10 in option 2 and <b> print message </b>
So it may be got some OOB call. lets debug it:

- OOB call:
```
R14  0x2045cf ◂— '/home/jamie/.rustup/...

0x243a92 <challenge::print_message+66>     call   r14                         <0x2045cf>
```

- Normal call:

```

R14 = 0x246730 (<&str as colored::Colorize>::yellow) ◂— push rbx

0x243a92 <challenge::print_message+66>     call   r14                         <<&str as colored::Colorize>::yellow>

```

![alt text](image.png)

From what I've showed above, it has OOB call, meaning I can call to whatever offset I want

With the help of AI, I understood that the challenge only allows <b> each byte in my input <= 0x7f </b>

If not, it will do replace the prohibited byte with valid one, making my payload useless

Because of that, despite the ability to control all of registers, I can't pop address of /bin/sh into RDI as it's address is atleast '0x2f9e38'
```
0x9e > 0x7f --> useless  
```
<h2> After this stage, I'm currently waiting for write up from others to solve it :(( </h2>