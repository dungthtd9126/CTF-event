#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cope.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void
die(const char *msg)
{
	perror(msg);
	exit(1);
}

static void
do_cope(int fd, cope_t *buf, uint32_t ncope)
{
	cope_ioc_t ioc;

	ioc.ci_copes = buf;
	ioc.ci_ncope = ncope;
	if (ioctl(fd, COPEIOC_COPE, &ioc) != 0)
		die("COPEIOC_COPE");
}

int
main(void)
{
	unsigned char raw[2 * sizeof (cope_t)];
	int fd;
	uint32_t latest = 0;

	memset(raw, 0, sizeof (raw));

	fd = open("/dev/cope", O_RDWR);
	if (fd < 0)
		die("open(/dev/cope)");

	do_cope(fd, (cope_t *)raw, 2);
	if (ioctl(fd, COPEIOC_MALD, &latest) != 0)
		die("COPEIOC_MALD");

	printf("latest=%u\n", latest);
	return (0);
}
