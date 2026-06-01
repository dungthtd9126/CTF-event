#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/cope.h>
int main() {
    int fd = open("/dev/cope", O_RDWR);
    printf("fd=%d\n", fd);
    if (fd >= 0) {
        cope_t copes[2];
        cope_ioc_t ioc;
        memset(copes, 0, sizeof(copes));
        ioc.ci_copes = copes;
        ioc.ci_ncope = 2;
        int rc = ioctl(fd, COPEIOC_COPE, &ioc);
        printf("ioctl rc=%d\n", rc);
        close(fd);
    }
    return 0;
}
