#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void *(*real_malloc)(size_t);
static void (*real_free)(void *);
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uintptr_t libc_base;

static uintptr_t find_libc_base(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        return 0;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libc.so.6") && strstr(line, "r-xp")) {
            uintptr_t lo = 0;
            uintptr_t off = 0;
            if (sscanf(line, "%lx-%*lx %*s %lx", &lo, &off) == 2) {
                fclose(fp);
                return lo - off;
            }
        }
    }
    fclose(fp);
    return 0;
}

static void init_real(void) {
    if (!real_malloc) {
        real_malloc = dlsym(RTLD_NEXT, "malloc");
    }
    if (!real_free) {
        real_free = dlsym(RTLD_NEXT, "free");
    }
}

void *malloc(size_t size) {
    init_real();
    void *ptr = real_malloc(size);
    if (size >= 0x10000) {
        pthread_mutex_lock(&lock);
        if (!libc_base) {
            libc_base = find_libc_base();
        }
        fprintf(stderr, "[malloc] size=%#zx ptr=%p libc_base=%#lx delta=%#lx\n",
                size,
                ptr,
                (unsigned long) libc_base,
                libc_base ? (unsigned long) ((uintptr_t) ptr - libc_base) : 0UL);
        fflush(stderr);
        pthread_mutex_unlock(&lock);
    }
    return ptr;
}

void free(void *ptr) {
    init_real();
    real_free(ptr);
}
