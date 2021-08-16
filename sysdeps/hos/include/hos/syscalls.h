#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

namespace mlibc {

void sys_debug_write(char* msg, size_t size);
void sys_exit(int ret);
pid_t sys_fork();
uint64_t sys_mmap(uint64_t pointer, size_t size, int flags);
int sys_munmap(uint64_t pointer, size_t size);
int sys_ipc_hint(size_t max_msg_size, char* pipe_name, size_t pipe_name_len);
int sys_ipc_send_pid(const void* data, size_t size, pid_t pid);
int sys_ipc_send_pipe(const void* data, size_t size, char* pipe_name, size_t pipe_name_len);
int64_t sys_ipc_recv(void* data, size_t size, bool block);



}

#endif