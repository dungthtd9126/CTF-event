#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/processor.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void bind_cpu0(void) {
    processorid_t old;
    if (processor_bind(P_PID, P_MYID, 0, &old) != 0)
        warn("processor_bind");
}
int main(void) {
    pid_t pid=fork();
    if(pid==0){
        bind_cpu0();
        int fd=open("/dev/cope", O_RDWR);
        if(fd<0) err(1,"open");
        printf("child open ok %d\n", fd);
        fflush(stdout);
        sleep(1);
        _exit(0);
    }
    waitpid(pid,NULL,0);
    return 0;
}
