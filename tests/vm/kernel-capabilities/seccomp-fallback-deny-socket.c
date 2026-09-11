// SPDX-License-Identifier: Apache-2.0
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#define SENTRY_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define SENTRY_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#error "unsupported architecture for the seccomp fallback probe"
#endif

int main(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SENTRY_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    int socket_fd;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) {
        perror("install seccomp fallback");
        return 1;
    }
    errno = 0;
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd != -1 || errno != EPERM) {
        fprintf(stderr, "expected socket to fail with EPERM, got fd=%d errno=%d\n", socket_fd, errno);
        if (socket_fd >= 0)
            close(socket_fd);
        return 1;
    }
    puts("seccomp fallback socket denial succeeded");
    return 0;
}
