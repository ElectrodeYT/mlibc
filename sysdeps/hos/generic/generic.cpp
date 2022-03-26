#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/thread-entry.hpp>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <hos/syscalls.h>

namespace mlibc  {

// Syscall stuff

void sys_debug_write(const char* msg, size_t size) {
    syscall_2arg_0ret(SYSCALL_DEBUGWRITE, (uint64_t)msg, (uint64_t)size);
}

void sys_exit(int ret) {
    while(true) {
        syscall_1arg_0ret(SYSCALL_EXIT, ret);
    }
}

pid_t sys_fork() {
    return (pid_t)syscall_0arg_1ret(SYSCALL_FORK);
}

uint64_t sys_mmap(uint64_t pointer, size_t size, int flags) {
    return syscall_3arg_1ret(SYSCALL_MMAP, (uint64_t)size, pointer, (uint64_t)flags);
} 

int sys_munmap(uint64_t pointer, size_t size) {
    return (int)syscall_2arg_1ret(SYSCALL_MUNMAP, pointer, (uint64_t)size);
}

// mlibc sys functions

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
    __ensure(flags & MAP_ANONYMOUS);
    // TODO: fd
    // TODO: offset
    // TODO: prot
    // TODO: flags
    (void)fd; (void)offset;
    uint64_t addr = sys_mmap((uint64_t)hint, size, prot & PROT_WRITE);
    if((int)(addr) < 0) { return (int)addr; }
    *window = (void*)addr;
    return 0;
}

int sys_vm_unmap(void* pointer, size_t size) {
    return sys_munmap((uint64_t)pointer, size);
}

int sys_anon_allocate(size_t size, void **pointer) {
    uint64_t tmp = sys_mmap(0, size, 0b11);
    if((int)(tmp) < 0) { return (int)tmp; }
    *pointer = (void*)tmp;
    return 0;
}

int sys_anon_free(void *pointer, size_t size) {
    return sys_munmap((uint64_t)pointer, size);
}

int sys_open(const char *path, int flags, int *fd) {
    int64_t ret = (int64_t)syscall_3arg_1ret(SYSCALL_OPEN, (uint64_t)path, strlen(path), flags);
    if(ret < 0) { return -ret; }
    *fd = ret;
    return 0;
}

int sys_close(int fd) {
    int64_t ret = (int64_t)syscall_1arg_1ret(SYSCALL_CLOSE, (uint64_t)fd);
    return -ret;
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
    int64_t ret = (int64_t)syscall_3arg_1ret(SYSCALL_WRITE, (uint64_t)buf, count, fd);
    if(ret < 0) { return -ret; }
    *bytes_written = ret;
    return 0;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
    int64_t ret = (int64_t)syscall_3arg_1ret(SYSCALL_READ, (uint64_t)buf, count, fd);
    if(ret < 0) { return -ret; }
    *bytes_read = ret;
    return 0;
}

void sys_libc_log(const char* msg) {
    sys_debug_write(msg, strlen(msg));
}

void sys_libc_panic() {
    mlibc::infoLogger() << "\e[31mmlibc: panic!" << frg::endlog;
    sys_exit(-1);
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
    int64_t tmp = (int64_t)syscall_3arg_1ret(SYSCALL_SEEK, fd, offset, whence);
    if(tmp < 0) { return -tmp; }
    *new_offset = tmp;
    return 0;
}

int sys_futex_wake(int *pointer) {
    return 0;
    (void)pointer;
}

int sys_futex_wait(int *pointer, int expected) {
    return 0;
    (void)pointer; (void)expected;
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
    return ENOSYS;
    (void)pointer; (void)expected; (void)time;
}

int sys_clone(void *entry, void *user_arg, void *tcb, pid_t *tid_out) {
    return ENOSYS;
    (void)entry; (void)user_arg; (void)tcb; (void)tid_out;
}

int sys_tcb_set(void *pointer) {
    syscall_1arg_0ret(SYSCALL_SET_TCB, (uint64_t)pointer);
    return 0;
}
/*
int sys_isatty(int fd) {
    infoLogger() << "haha sys_isatty go brrr" << frg::endlog;
    return ENOTTY;
    (void)fd;
}
*/
int sys_clock_get(int clock, time_t* secs, long* nanos) {
    return 0;
}

}