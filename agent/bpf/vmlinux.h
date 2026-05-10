// vmlinux.h - Minimal kernel type definitions for eBPF programs
// In production, generate this with: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;

typedef _Bool bool;
enum { false = 0, true = 1 };
#define NULL ((void *)0)

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_IP(x) ((x)->ip)

struct pt_regs {
    unsigned long r15, r14, r13, r12;
    unsigned long bp, bx;
    unsigned long r11, r10, r9, r8;
    unsigned long ax, cx, dx, si, di;
    unsigned long orig_ax, ip, cs, flags, sp, ss;
};

typedef struct { int counter; } atomic_t;
typedef struct { long counter; } atomic64_t;

typedef unsigned long __kernel_size_t;
typedef long __kernel_ssize_t;
typedef long __kernel_off_t;
typedef long __kernel_loff_t;
typedef long __kernel_time_t;
typedef long __kernel_clock_t;
typedef int __kernel_pid_t;
typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;

typedef __kernel_uid32_t uid_t;
typedef __kernel_gid32_t gid_t;
typedef __kernel_off_t off_t;
typedef __kernel_loff_t loff_t;
typedef __kernel_size_t size_t;
typedef __kernel_ssize_t ssize_t;
typedef __kernel_pid_t pid_t;
typedef __kernel_time_t time_t;
typedef __kernel_clock_t clock_t;
typedef unsigned short umode_t;
typedef u64 phys_addr_t;

struct list_head {
    struct list_head *next, *prev;
};

struct hlist_head { struct hlist_node *first; };
struct hlist_node { struct hlist_node *next, **pprev; };

struct callback_head {
    struct callback_head *next;
    void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));

struct task_struct {
    volatile long state;
    void *stack;
    atomic_t usage;
    unsigned int flags;
    unsigned int ptrace;
    int on_cpu;
    int prio;
    int static_prio;
    int normal_prio;
    unsigned int rt_priority;
    unsigned int policy;
    int nr_cpus_allowed;
    struct list_head tasks;
    struct mm_struct *mm;
    struct mm_struct *active_mm;
    int exit_state;
    int exit_code;
    int exit_signal;
    int pdeath_signal;
    unsigned long personality;
    pid_t pid;
    pid_t tgid;
    struct task_struct *real_parent;
    struct task_struct *parent;
    struct list_head children;
    struct list_head sibling;
    struct task_struct *group_leader;
    struct list_head ptraced;
    struct list_head ptrace_entry;
    struct list_head thread_group;
    struct list_head thread_node;
    cputime_t utime, stime;
    unsigned long nvcsw, nivcsw;
    u64 start_time;
    u64 real_start_time;
    char comm[16];
    struct fs_struct *fs;
    struct files_struct *files;
    struct nsproxy *nsproxy;
    struct signal_struct *signal;
    struct sighand_struct *sighand;
    sigset_t blocked, real_blocked, saved_sigmask;
    struct sigpending pending;
    void *security;
    unsigned long stack_refcount;
};

#endif /* __VMLINUX_H__ */
