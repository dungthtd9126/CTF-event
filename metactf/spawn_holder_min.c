#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/processor.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void bind_cpu0(void){ processorid_t old; if (processor_bind(P_PID, P_MYID, 0, &old) != 0) warn("processor_bind"); }
static void write_status(int fd, char c){ if(write(fd,&c,1)!=1) _exit(120); }
static void childfn(int status_fd, int cmd_fd){ (void)cmd_fd; bind_cpu0(); int fd=open("/dev/cope", O_RDWR); if(fd<0) err(1,"open(/dev/cope)"); write_status(status_fd,'H'); for(;;) pause(); }
int main(void){ int sp[2], cp[2]; if(pipe(sp)||pipe(cp)) err(1,"pipe"); pid_t pid=fork(); if(pid<0) err(1,"fork"); if(pid==0){ close(sp[0]); close(cp[1]); childfn(sp[1], cp[0]); }
close(sp[1]); close(cp[0]); char c; if(read(sp[0],&c,1)!=1) errx(1,"child failed before status H"); printf("status=%c\n", c); fflush(stdout); kill(pid,SIGKILL); waitpid(pid,NULL,0); return 0; }
