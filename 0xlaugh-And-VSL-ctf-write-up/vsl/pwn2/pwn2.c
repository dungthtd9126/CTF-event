#include <stdio.h>
#include <unistd.h>

void get(){
    puts("Welcome to blind pwn v2");
    printf("> ");
    char a[0x400];
    read(0, a, 0x400-1);
    printf(a);  
}

void show(){
    get();
}

void init(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(){
    init();
    
    show();
    return 0;
}