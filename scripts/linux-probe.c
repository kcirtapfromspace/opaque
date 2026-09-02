/*
 * Kernel capability probe for the trust-domain hardening work.
 *
 * Answers, empirically, whether this kernel can enforce what the opaqued
 * sandbox is about to promise: Landlock filesystem rules and seccomp-bpf
 * syscall filters. CI asserts this exits 0 so the Linux-only sandbox tests
 * can never be skipped silently on a kernel that cannot run them.
 *
 * Exit codes: 0 = landlock + seccomp both available
 *             3 = landlock unavailable
 *             4 = seccomp unavailable
 *             7 = both unavailable
 */
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_seccomp
#ifdef __aarch64__
#define __NR_seccomp 277
#else
#define __NR_seccomp 317
#endif
#endif

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_RET_KILL_PROCESS 0x80000000U

int main(void) {
    int rc = 0;

    long abi = syscall(__NR_landlock_create_ruleset, NULL, 0,
                       LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        printf("landlock: UNAVAILABLE (errno=%d%s)\n", errno,
               errno == EOPNOTSUPP ? " — LSM built but not enabled at boot"
               : errno == ENOSYS   ? " — kernel too old or syscall filtered"
                                   : "");
        rc |= 3;
    } else {
        printf("landlock: ok (ABI v%ld)\n", abi);
    }

    unsigned int action = SECCOMP_RET_KILL_PROCESS;
    if (syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) != 0) {
        printf("seccomp:  UNAVAILABLE (errno=%d)\n", errno);
        rc |= 4;
    } else {
        printf("seccomp:  ok (filters supported)\n");
    }

    return rc;
}
