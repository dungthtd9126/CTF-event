#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

static void *(*real_malloc)(size_t);
static void *(*real_realloc)(void*, size_t);
static void (*real_free)(void*);
static FILE *(*real_fopen)(const char*, const char*);
static size_t (*real_fread)(void*, size_t, size_t, FILE*);
static int (*real_fclose)(FILE*);
static int inited = 0;
static __thread int guard = 0;

static void init(void) {
    if (inited) return;
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_fread = dlsym(RTLD_NEXT, "fread");
    real_fclose = dlsym(RTLD_NEXT, "fclose");
    inited = 1;
}

static void logmsg(const char *fmt, ...) {
    if (guard) return;
    guard = 1;
    init();
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    guard = 0;
}

void *malloc(size_t n) {
    init();
    void *ret = real_malloc(n);
    logmsg("[trace] malloc(%#zx)=%p ra=%p\n", n, ret, __builtin_return_address(0));
    return ret;
}

void *realloc(void *p, size_t n) {
    init();
    void *ret = real_realloc(p, n);
    logmsg("[trace] realloc(%p,%#zx)=%p ra=%p\n", p, n, ret, __builtin_return_address(0));
    return ret;
}

void free(void *p) {
    init();
    logmsg("[trace] free(%p) ra=%p\n", p, __builtin_return_address(0));
    real_free(p);
}

FILE *fopen(const char *path, const char *mode) {
    init();
    FILE *ret = real_fopen(path, mode);
    logmsg("[trace] fopen(%s,%s)=%p ra=%p\n", path ? path : "<null>", mode ? mode : "<null>", ret, __builtin_return_address(0));
    return ret;
}

size_t fread(void *ptr, size_t sz, size_t nmemb, FILE *f) {
    init();
    size_t ret = real_fread(ptr, sz, nmemb, f);
    logmsg("[trace] fread(%p,%#zx,%#zx,%p)=%#zx ra=%p\n", ptr, sz, nmemb, f, ret, __builtin_return_address(0));
    return ret;
}

int fclose(FILE *f) {
    init();
    logmsg("[trace] fclose(%p) ra=%p\n", f, __builtin_return_address(0));
    return real_fclose(f);
}
