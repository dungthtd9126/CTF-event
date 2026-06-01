// gcc -o prob prob.c -lseccomp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <seccomp.h>
#include <linux/seccomp.h>

volatile char flag_mem[0x50] = {0};

void sandbox(){
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);

	if (seccomp_load(ctx) < 0){
		seccomp_release(ctx);
		printf("seccomp error\n");
		exit(0);
	}
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";

int main(int argc, char* argv[]){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	int fd = open("./flag", O_RDONLY);
	if (fd == -1) {
		perror("open");
		return 1;
	}
	read(fd, (char*)flag_mem, 0x50);
	close(fd);

	char* sh = (char*)mmap((void*)0x40400000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
	memset(sh, 0x90, 0x1000);
	memcpy(sh, stub, strlen(stub));

	int offset = sizeof(stub);
	printf("Enter your shellcode: ");
	int n = read(0, sh + offset, 0x900);

	for (int i = 0; i < n; i++) {
		if ((unsigned char)(sh[offset + i]) & 1) {
			printf("No odd bytes allowed!\n");
			return 1;
		}
	}

	mprotect(sh, 0x1000, PROT_READ | PROT_EXEC);

	ualarm(500, 0);
	sandbox();
	((void (*)(void))sh)();
	return 0;
}
