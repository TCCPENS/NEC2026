#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/* The challenge intentionally exposes a CSU-shaped sequence, rather than
 * convenient argument-pop gadgets in the main executable. */
__attribute__((naked, noinline, used))
static void csu_pop(void) {
    __asm__(
        "pop %rbx\n"
        "pop %rbp\n"
        "pop %r12\n"
        "pop %r13\n"
        "pop %r14\n"
        "pop %r15\n"
        "nop\n"
        "ret\n"
    );
}

__attribute__((naked, noinline, used))
static void csu_call(void) {
    __asm__(
        "mov %r13, %rdx\n"
        "mov %r14, %rsi\n"
        "mov %r15, %rdi\n"
        "call *(%r12,%rbx,8)\n"
        "add $8, %rsp\n"
        "pop %rbx\n"
        "pop %rbp\n"
        "pop %r12\n"
        "pop %r13\n"
        "pop %r14\n"
        "pop %r15\n"
        "nop\n"
        "ret\n"
    );
}

__attribute__((naked, noinline, used))
static void pop_rbp_ret(void) {
    __asm__("pop %rbp\nret\n");
}

/* There is no useful pop-rdi sequence in the main binary. This primitive is
 * intentionally needed to carry openat()'s return value onward. */
__attribute__((naked, noinline, used))
static void move_rax_to_rdi(void) {
    __asm__("mov %rax, %rdi\nret\n");
}

__attribute__((naked, noinline, used))
static void zero_rcx(void) {
    __asm__("xor %ecx, %ecx\nret\n");
}

__attribute__((naked, noinline, used))
static void pivot_r12(void) {
    __asm__("mov %r12, %rsp\nret\n");
}

__attribute__((used)) static const char stage2_ready[] = "stage2-ready\n";

static void install_sandbox(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
        _exit(1);
    }
}

/* Fill the requested size so TCP fragmentation cannot turn a ROP stage into
 * an accidental short read. The destination remains the caller's stack
 * buffer, which preserves the vulnerability while making the challenge
 * reproducible. */
static void fill_profile(char *destination, size_t length) {
    size_t received = 0;
    while (received < length) {
        ssize_t count = read(STDIN_FILENO, destination + received,
                             length - received);
        if (count <= 0)
            _exit(0);
        received += (size_t)count;
    }
}

__attribute__((noinline))
static void receive_profile(void) {
    char profile[64];
    static const char prompt[] = "Profile input: ";
    static const char stored[] = "profile stored\n";

    write(STDOUT_FILENO, prompt, sizeof(prompt) - 1);
    /* Deliberately larger than profile. The saved return address is reachable. */
    fill_profile(profile, 0x200);
    write(STDOUT_FILENO, stored, sizeof(stored) - 1);
}

extern void _start(void);

int main(void) {
    char line[128];
    int length;

    /* This leak gives the solver the PIE base without making libc static. */
    length = snprintf(line, sizeof(line),
                      "Shelless relay online\nPIE anchor: %p\n",
                      (void *)&_start);
    if (length > 0)
        write(STDOUT_FILENO, line, (size_t)length);

    /* All PLT entries are resolved at startup by -z now. */
    install_sandbox();
    receive_profile();
    return 0;
}
