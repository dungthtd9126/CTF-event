#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
int main(void){ long rc = syscall(SYS_nfssys, 19, (void*)0); printf("rc=%ld errno=%d\n", rc, errno); return 0; }
