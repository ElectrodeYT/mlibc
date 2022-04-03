#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

namespace mlibc {


#define SYSCALL_DEBUGWRITE 1
#define SYSCALL_MMAP 2
#define SYSCALL_MUNMAP 3
#define SYSCALL_EXIT 4
#define SYSCALL_FORK 5
#define SYSCALL_OPEN 6
#define SYSCALL_CLOSE 7
#define SYSCALL_READ 8
#define SYSCALL_WRITE 9
#define SYSCALL_SEEK 10
#define SYSCALL_SET_TCB 11
#define SYSCALL_ISATTY 12
#define SYSCALL_EXEC 13
#define SYSCALL_WAIT 14



__attribute__((always_inline)) static inline void syscall_1arg_0ret(uint64_t syscall, uint64_t arg1) {
    asm volatile("      \
        mov %0, %%rax;  \
        mov %1, %%rbx;  \
        int $0x80;      \
    " : : "r" ((uint64_t)syscall), "r" ((uint64_t)arg1) : "rax", "rbx", "memory");
    asm volatile("": : :"memory");
}

__attribute__((always_inline)) static inline void syscall_2arg_0ret(uint64_t syscall, uint64_t arg1, uint64_t arg2) {
    asm volatile("      \
        mov %0, %%rax;  \
        mov %1, %%rbx;  \
        mov %2, %%rcx;  \
        int $0x80;      \
    " : : "r" ((uint64_t)syscall), "r" ((uint64_t)arg1), "r" ((uint64_t)arg2) : "rax", "rbx", "rcx", "memory");
    asm volatile("": : :"memory");
}

__attribute__((always_inline)) static inline void syscall_4arg_0ret(uint64_t syscall, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    uint64_t ret;
    asm volatile("      \
        mov %0, %%rax;  \
        mov %1, %%rbx;  \
        mov %2, %%rcx;  \
        mov %3, %%rdx;  \
        mov %4, %%rdi;  \
        int $0x80;      \
    " : : "r" ((uint64_t)syscall), "r" ((uint64_t)arg1), "r" ((uint64_t)arg2), "r" ((uint64_t)arg3), "r" ((uint64_t)arg4) : "rax", "rbx", "rcx", "rdx", "memory");
    asm volatile("": : :"memory");
}

__attribute__((always_inline)) static inline uint64_t syscall_0arg_1ret(uint64_t syscall) {
    uint64_t ret;
    asm volatile("      \
        mov %1, %%rax;  \
        int $0x80;      \
        mov %%rax, %0   \
    " : "=r" (ret) : "r" ((uint64_t)syscall) : "rax", "memory");
    asm volatile("": : :"memory");
    return ret;
}

__attribute__((always_inline)) static inline uint64_t syscall_1arg_1ret(uint64_t syscall, uint64_t arg1) {
    uint64_t ret;
    asm volatile("      \
        mov %1, %%rax;  \
        mov %2, %%rbx;  \
        int $0x80;      \
        mov %%rax, %0   \
    " : "=r" (ret) : "r" ((uint64_t)syscall), "r" ((uint64_t)arg1) : "rax", "rbx", "memory");
    asm volatile("": : :"memory");
    return ret;
}

__attribute__((always_inline)) static inline uint64_t syscall_2arg_1ret(uint64_t syscall, uint64_t arg1, uint64_t arg2) {
    uint64_t ret;
    asm volatile("      \
        mov %1, %%rax;  \
        mov %2, %%rbx;  \
        mov %3, %%rcx;  \
        int $0x80;      \
        mov %%rax, %0   \
    " : "=r" (ret) : "r" ((uint64_t)syscall), "r" ((uint64_t)arg1), "r" ((uint64_t)arg2) : "rax", "rbx", "rcx", "memory");
    asm volatile("": : :"memory");
    return ret;
}

__attribute__((always_inline)) static inline uint64_t syscall_3arg_1ret(uint64_t syscall, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    uint64_t ret;
    asm volatile("      \
        mov %1, %%rax;  \
        mov %2, %%rbx;  \
        mov %3, %%rcx;  \
        mov %4, %%rdx;  \
        int $0x80;      \
        mov %%rax, %0   \
    " : "=r" (ret) : "r" ((uint64_t)syscall), "r" ((uint64_t)arg1), "r" ((uint64_t)arg2), "r" ((uint64_t)arg3) : "rax", "rbx", "rcx", "rdx", "memory");
    asm volatile("": : :"memory");
    return ret;
}

__attribute__((always_inline)) static inline uint64_t syscall_4arg_1ret(uint64_t syscall, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    uint64_t ret;
    asm volatile("      \
        mov %1, %%rax;  \
        mov %2, %%rbx;  \
        mov %3, %%rcx;  \
        mov %4, %%rdx;  \
        mov %5, %%rdi;  \
        int $0x80;      \
        mov %%rax, %0   \
    " : "=r" (ret) : "r" ((uint64_t)syscall), "r" ((uint64_t)arg1), "r" ((uint64_t)arg2), "r" ((uint64_t)arg3), "r" ((uint64_t)arg4) : "rax", "rbx", "rcx", "rdx", "memory");
    asm volatile("": : :"memory");
    return ret;
}


// Syscalls
void sys_debug_write(const char* msg, size_t size);
void sys_exit(int ret);
pid_t sys_fork();
uint64_t sys_mmap(uint64_t pointer, size_t size, int flags);
int sys_munmap(uint64_t pointer, size_t size);
int sys_open(const char *path, int flags, int *fd);
int sys_close(int fd);
int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written);
int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read);

// mlibc functions
int sys_seek(int fd, off_t offset, int whence, off_t *new_offset);
int sys_futex_wake(int *pointer);
int sys_futex_wait(int *pointer, int expected);
int sys_clone(void *entry, void *user_arg, void *tcb, pid_t *tid_out);
int sys_anon_allocate(size_t size, void **pointer);
int sys_anon_free(void *pointer, size_t size);
int sys_tcb_set(void *pointer);
// int sys_isatty(int fd);

}

#endif