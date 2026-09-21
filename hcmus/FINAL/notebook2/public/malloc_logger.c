#define _GNU_SOURCE

#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void (*real_free)(void *);

static __thread int in_hook;

static long tid(void) {
    return syscall(SYS_gettid);
}

static void init_hooks(void) {
    if (real_malloc) {
        return;
    }
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_free = dlsym(RTLD_NEXT, "free");
}

static void log_line(const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        if ((size_t)n > sizeof(buf)) {
            n = sizeof(buf);
        }
        write(2, buf, (size_t)n);
    }
}

static int want_size(size_t size) {
    return size == 0x49 || size == 0x58 || size == 0x40 || size == 0xa0 || size == 1;
}

void *malloc(size_t size) {
    init_hooks();
    void *ret = real_malloc(size);
    if (!in_hook && want_size(size)) {
        in_hook = 1;
        log_line("[mlog] tid=%ld malloc(%#zx) = %p ra=%p\n",
                 tid(), size, ret, __builtin_return_address(0));
        in_hook = 0;
    }
    return ret;
}

void *calloc(size_t nmemb, size_t size) {
    init_hooks();
    void *ret = real_calloc(nmemb, size);
    size_t total = nmemb * size;
    if (!in_hook && want_size(total)) {
        in_hook = 1;
        log_line("[mlog] tid=%ld calloc(%#zx,%#zx) = %p ra=%p\n",
                 tid(), nmemb, size, ret, __builtin_return_address(0));
        in_hook = 0;
    }
    return ret;
}

void free(void *ptr) {
    init_hooks();
    if (!in_hook && ptr) {
        in_hook = 1;
        log_line("[mlog] tid=%ld free(%p) ra=%p\n",
                 tid(), ptr, __builtin_return_address(0));
        in_hook = 0;
    }
    real_free(ptr);
    if (!in_hook && ptr) {
        unsigned char *p = ptr;
        in_hook = 1;
        log_line("[mlog] tid=%ld postfree(%p) bytes=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                 tid(),
                 ptr,
                 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                 p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
        in_hook = 0;
    }
}
