#include <hos/syscalls.h>
#include <hos/ipc.h>
#include <string.h>
#include <errno.h>

int64_t ipchint(uint64_t msg_len, char* named_pipe) {
    int len = strlen(named_pipe);
    if(!len) { errno = EINVAL; return -EINVAL; }
    errno = -mlibc::sys_ipc_hint(msg_len, named_pipe, len);
}

int64_t ipcrecv(void* buffer, size_t buffer_size, int should_block) {
    int64_t ret = mlibc::sys_ipc_recv(buffer, buffer_size, should_block != 0);
    if(ret < 0) { errno = -ret; }
    return ret;
}

int64_t ipcsendpipe(const void* msg, size_t msg_size, char* pipe) {
    int len = strlen(pipe);
    if(!len) { errno = EINVAL; return -EINVAL; }
    int64_t ret = mlibc::sys_ipc_send_pipe(msg, msg_size, pipe, len);
    if(ret < 0) { errno = -ret; }
    return ret;
}