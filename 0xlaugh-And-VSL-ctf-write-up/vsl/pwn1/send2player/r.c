#include <stdio.h>
#include <unistd.h>


void init(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(){
    init();
    char a[0x500];
    
    puts("Welcome to blind pwn");
    for (int i =0; i < 2; i++){
        printf("> ");
        read(0, a, 0x500-1);
        printf(a);  
    }
    

    return 0;
}