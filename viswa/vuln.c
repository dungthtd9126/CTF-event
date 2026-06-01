#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

// Ép cấu trúc Stack: dummy1(6), dummy2(7), buffer(8)
struct vuln_frame {
    long dummy1;      // Offset 6 (Sẽ chứa địa chỉ Stack)
    long dummy2;      // Offset 7 (Sẽ chứa địa chỉ Libc)
    char buffer[160]; // Offset 8 -> Kết thúc ở 34. 35 là RIP.
};

void log_a_note() {
    struct vuln_frame f;
    f.dummy1 = (long)&f;      // Mồi địa chỉ Stack vào Offset 6
    f.dummy2 = (long)&printf; // Mồi địa chỉ Libc vào Offset 7

    printf("note:\n");
    read(0, f.buffer, 159);

    // Xóa register để Offset 1, 2, 3 là nil. Offset 4 là 0x1. 
    // Offset 5 mồi Libc.
    asm(
        "xor %%rsi, %%rsi;"
        "xor %%rdx, %%rdx;"
        "xor %%rcx, %%rcx;"
        "mov $0x1, %%r8;"
        "mov %0, %%r9;"
        : : "r"(&init) : "rsi", "rdx", "rcx", "r8", "r9"
    );

    printf(f.buffer); // LỖI FORMAT STRING
    printf("\n");
}

int main() {
    init();
    
    // Padding 32 bytes để đẩy Saved RIP của main (39) cách RIP log_a_note (35) đúng 4 ô
    long p1 = 0, p2 = 0, p3 = 0; 

    while(1) {
        printf("=== Admin Console ===\n1. Log a note\n2. Enter secret info\n3. Exit\n$ ");
        int choice;
        if (scanf("%d", &choice) <= 0) break;
        getchar();
        if (choice == 1) log_a_note();
        else if (choice == 3) exit(0);
    }
    return 0;
}