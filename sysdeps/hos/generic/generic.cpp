#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/thread-entry.hpp>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

namespace mlibc  {


#define SYSCALL_DEBUGWRITE 1
#define SYSCALL_MMAP 2
#define SYSCALL_MUNMAP 3
#define SYSCALL_EXIT 4
#define SYSCALL_FORK 5
#define SYSCALL_IPCHINT 6
#define SYSCALL_IPCSENDPID 7
#define SYSCALL_IPCSENDPIPE 8
#define SYSCALL_IPCRECV 9

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

void sys_debug_write(char* msg, size_t size) {
    syscall_2arg_0ret(SYSCALL_DEBUGWRITE, (uint64_t)msg, (uint64_t)size);
}

void sys_exit(int ret) {
    syscall_1arg_0ret(SYSCALL_EXIT, ret);
}

pid_t sys_fork() {
    return (pid_t)syscall_0arg_1ret(SYSCALL_FORK);
}

uint64_t sys_mmap(uint64_t pointer, size_t size, int flags) {
    return syscall_3arg_1ret(SYSCALL_MMAP, pointer, (uint64_t)size, (uint64_t)flags);
}

int sys_munmap(uint64_t pointer, size_t size) {
    return (int)syscall_2arg_1ret(SYSCALL_MUNMAP, pointer, (uint64_t)size);
}

int sys_ipc_hint(size_t max_msg_size, char* pipe_name, size_t pipe_name_len) {
    return (int)syscall_3arg_1ret(SYSCALL_IPCHINT, (uint64_t)max_msg_size, (uint64_t)pipe_name, (uint64_t)pipe_name_len);
}

int sys_ipc_send_pid(const void* data, size_t size, pid_t pid) {
    return (int)syscall_3arg_1ret(SYSCALL_IPCSENDPID, (uint64_t)data, (uint64_t)size, (uint64_t)pid);
}

int sys_ipc_send_pipe(const void* data, size_t size, char* pipe_name, size_t pipe_name_len) {
    return (int)syscall_4arg_1ret(SYSCALL_IPCSENDPIPE, (uint64_t)data, (uint64_t)size, (uint64_t)pipe_name, (uint64_t)pipe_name_len);
}

int64_t sys_ipc_recv(void* data, size_t size, bool block) {
    return (int64_t)syscall_3arg_1ret(SYSCALL_IPCRECV, (uint64_t)data, (uint64_t)size, (uint64_t)block);
}

}