// wine_shim.c — LD_PRELOAD yol yeniden yönlendirici
// /usr/share/wine ve /usr/lib/wine cagrilarini /tmp/winedl/root altina yonlendirir
// (rootsuz ortamda Wine 10 calistirmak icin)
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <limits.h>

static const char* cevir(const char* p, char* buf, size_t n) {
    if (!p) return p;
    if (strncmp(p, "/usr/share/wine", 15) == 0) {
        snprintf(buf, n, "/tmp/winedl/root/usr/share/wine%s", p + 15);
        return buf;
    }
    if (strncmp(p, "/usr/lib/wine", 13) == 0) {
        snprintf(buf, n, "/tmp/winedl/root/usr/lib/wine%s", p + 13);
        return buf;
    }
    return p;
}

int open(const char* path, int flags, ...) {
    static int (*gercek)(const char*, int, ...) = NULL;
    if (!gercek) gercek = dlsym(RTLD_NEXT, "open");
    char buf[PATH_MAX];
    mode_t m = 0;
    if (flags & (O_CREAT)) {
        va_list ap; va_start(ap, flags);
        m = va_arg(ap, mode_t); va_end(ap);
    }
    return gercek(cevir(path, buf, sizeof buf), flags, m);
}

int openat(int dirfd, const char* path, int flags, ...) {
    static int (*gercek)(int, const char*, int, ...) = NULL;
    if (!gercek) gercek = dlsym(RTLD_NEXT, "openat");
    char buf[PATH_MAX];
    mode_t m = 0;
    if (flags & (O_CREAT)) {
        va_list ap; va_start(ap, flags);
        m = va_arg(ap, mode_t); va_end(ap);
    }
    return gercek(dirfd, cevir(path, buf, sizeof buf), flags, m);
}

int stat(const char* path, struct stat* st) {
    static int (*gercek)(const char*, struct stat*) = NULL;
    if (!gercek) gercek = dlsym(RTLD_NEXT, "stat");
    char buf[PATH_MAX];
    return gercek(cevir(path, buf, sizeof buf), st);
}

int __xstat(int ver, const char* path, struct stat* st) {
    static int (*gercek)(int, const char*, struct stat*) = NULL;
    if (!gercek) gercek = dlsym(RTLD_NEXT, "__xstat");
    char buf[PATH_MAX];
    return gercek(ver, cevir(path, buf, sizeof buf), st);
}

FILE* fopen(const char* path, const char* mod) {
    static FILE* (*gercek)(const char*, const char*) = NULL;
    if (!gercek) gercek = dlsym(RTLD_NEXT, "fopen");
    char buf[PATH_MAX];
    return gercek(cevir(path, buf, sizeof buf), mod);
}
