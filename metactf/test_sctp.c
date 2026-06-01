#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
int main(void){ int fd=socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP); if(fd<0){perror("socket"); return 1;} struct sockaddr_in sa={0}; sa.sin_family=AF_INET; sa.sin_port=0; sa.sin_addr.s_addr=htonl(INADDR_LOOPBACK); if(bind(fd,(void*)&sa,sizeof(sa))<0){perror("bind"); return 2;} if(listen(fd,1)<0){perror("listen"); return 3;} close(fd); puts("ok"); return 0; }
