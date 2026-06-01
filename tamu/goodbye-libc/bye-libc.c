// Custom strlen
int strlen(char* str) {
  int i = 0;
  while (str[i]) i++;
  return i;
}

// Exit syscall
int __attribute__((naked)) exit(int) {
  asm ("push rbp\n\t"
      "mov rbp, rsp\n\t"
      "mov rax, 60\n\t"
      "syscall\n\t"
      "pop rbp\n\t"
      "push rdx\n\t"
      "push rsi\n\t"
      "push rdi\n\t"
      "pop rdi\n\t"
      "pop rsi\n\t"
      "pop rdx\n\t"
      "ret\n\t"
  );
}

// Write syscall
int __attribute__((naked)) write(int, char*, int) {
  asm ("push rbp\n\t"
      "mov rbp, rsp\n\t"
      "mov rax, 0x1\n\t"
      "syscall\n\t"
      "pop rbp\n\t"
      "ret\n\t"
  );
}

// Read syscall
int __attribute__((naked)) read(int, char*, int) {
  asm ("push rbp\n\t"
      "mov rbp, rsp\n\t"
      "mov rax, 0x0\n\t"
      "syscall\n\t"
      "pop rbp\n\t"
      "ret\n\t"
  );
}

