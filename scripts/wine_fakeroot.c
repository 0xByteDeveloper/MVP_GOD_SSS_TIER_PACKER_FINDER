// wine_fakeroot.c — LD_PRELOAD ile /usr/share/wine ve /usr/lib/wine yollarını
// çıkarılmış wine ağacına yönlendiren shim (rootless relocation).
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>

#define NEW_ROOT "/home/z/my-project/work/tools/wine_root"

static __thread char rbuf[PATH_MAX];

static const char *rewrite(const char *path)
{
    if (!path)
        return path;
    size_t n = strlen(path);
    if ((n >= 15 && strncmp(path, "/usr/lib/wine/", 14) == 0) ||
        (n >= 17 && strncmp(path, "/usr/share/wine/", 16) == 0) ||
        (n >= 32 && strncmp(path, "/usr/lib/x86_64-linux-gnu/wine/", 31) == 0)) {
        snprintf(rbuf, sizeof(rbuf), "%s%s", NEW_ROOT, path);
        return rbuf;
    }
    return path;
}

int open(const char *path, int flags, ...)
{
    static int (*real)(const char *, int, ...);
    if (!real) real = dlsym(RTLD_NEXT, "open");
    mode_t mode = 0;
    va_list ap; va_start(ap, flags);
    mode = (flags & (O_CREAT|O_TMPFILE)) ? va_arg(ap, int) : 0;
    va_end(ap);
    return real(rewrite(path), flags, mode);
}

int open64(const char *path, int flags, ...)
{
    static int (*real)(const char *, int, ...);
    if (!real) real = dlsym(RTLD_NEXT, "open64");
    mode_t mode = 0;
    va_list ap; va_start(ap, flags);
    mode = (flags & (O_CREAT|O_TMPFILE)) ? va_arg(ap, int) : 0;
    va_end(ap);
    return real(rewrite(path), flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    static int (*real)(int, const char *, int, ...);
    if (!real) real = dlsym(RTLD_NEXT, "openat");
    mode_t mode = 0;
    va_list ap; va_start(ap, flags);
    mode = (flags & (O_CREAT|O_TMPFILE)) ? va_arg(ap, int) : 0;
    va_end(ap);
    return real(dirfd, rewrite(path), flags, mode);
}

FILE *fopen(const char *path, const char *mode)
{
    static FILE *(*real)(const char *, const char *);
    if (!real) real = dlsym(RTLD_NEXT, "fopen");
    return real(rewrite(path), mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    static FILE *(*real)(const char *, const char *);
    if (!real) real = dlsym(RTLD_NEXT, "fopen64");
    return real(rewrite(path), mode);
}

int stat(const char *path, struct stat *st)
{
    static int (*real)(const char *, struct stat *);
    if (!real) real = dlsym(RTLD_NEXT, "stat");
    return real(rewrite(path), st);
}

int lstat(const char *path, struct stat *st)
{
    static int (*real)(const char *, struct stat *);
    if (!real) real = dlsym(RTLD_NEXT, "lstat");
    return real(rewrite(path), st);
}

int access(const char *path, int mode)
{
    static int (*real)(const char *, int);
    if (!real) real = dlsym(RTLD_NEXT, "access");
    return real(rewrite(path), mode);
}

DIR *opendir(const char *path)
{
    static DIR *(*real)(const char *);
    if (!real) real = dlsym(RTLD_NEXT, "opendir");
    return real(rewrite(path));
}
