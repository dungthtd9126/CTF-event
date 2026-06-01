#include <stdio.h>
#include <stdlib.h> // Required for system()
#include <unistd.h> // Required for read()

void win() {
    system("/bin/sh");
}

int main() {
    char a[19] = {0};
    puts("Enter string (max 19 chars):");
    
    // The vulnerability: reading 0x10000 (65536) bytes into a 19-byte buffer
    fgets(a, 0x10000, stdin);; 
    a[19] =0; 
    
    puts(a);
    return 0;
}