// SPDX-License-Identifier: GPL-2.0
// process_monitor.bpf.c - Process lifecycle and privilege escalation monitoring

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 512

#define EVENT_PROCESS_CREATE   1
#define EVENT_PROCESS_EXIT     2
#define EVENT_PROCESS_PRIV_ESC 3

struct process_event {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 exit_code;
    __u32 cgroup_id;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} process_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct process_event));
    __uint(max_entries, 1);
} process_event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 10240);
} exec_uid_map SEC(".maps");

static __always_inline __u32 get_cgroup_id(void) {
    return (__u32)(bpf_get_current_cgroup_id() & 0xFFFFFFFF);
}

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 key = 0;
    struct process_event *evt = bpf_map_lookup_elem(&process_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp = bpf_ktime_get_ns();
    evt->event_type = EVENT_PROCESS_CREATE;
    evt->pid = ctx->child_pid;
    evt->ppid = ctx->parent_pid;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt->gid = bpf_get_current_uid_gid() >> 32;
    evt->cgroup_id = get_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(&evt->filename, sizeof(evt->filename), task->comm);

    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

    __u32 pid = ctx->child_pid;
    __u32 uid = evt->uid;
    bpf_map_update_elem(&exec_uid_map, &pid, &uid, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u32 key = 0;
    struct process_event *evt = bpf_map_lookup_elem(&process_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    __u64 uid_gid = bpf_get_current_uid_gid();

    evt->timestamp = bpf_ktime_get_ns();
    evt->event_type = EVENT_PROCESS_CREATE;
    evt->pid = pid;
    evt->uid = uid_gid & 0xFFFFFFFF;
    evt->gid = uid_gid >> 32;
    evt->cgroup_id = get_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        unsigned long fname_off = ctx->filename;
        bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), (void *)fname_off);
    }

    struct task_struct *real_parent;
    bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);
    if (real_parent) {
        bpf_probe_read_kernel(&evt->ppid, sizeof(evt->ppid), &real_parent->pid);
    }

    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

    __u32 uid = evt->uid;
    __u32 *old_uid = bpf_map_lookup_elem(&exec_uid_map, &tid);
    if (old_uid && *old_uid != uid) {
        __builtin_memset(evt, 0, sizeof(*evt));
        evt->timestamp = bpf_ktime_get_ns();
        evt->event_type = EVENT_PROCESS_PRIV_ESC;
        evt->pid = pid;
        evt->ppid = *old_uid;
        evt->uid = uid;
        evt->cgroup_id = get_cgroup_id();
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), (void *)ctx->filename);
        bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    }

    bpf_map_update_elem(&exec_uid_map, &pid, &uid, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    if (pid != tid) return 0;

    __u32 key = 0;
    struct process_event *evt = bpf_map_lookup_elem(&process_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    evt->timestamp = bpf_ktime_get_ns();
    evt->event_type = EVENT_PROCESS_EXIT;
    evt->pid = pid;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt->cgroup_id = get_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    int exit_code;
    bpf_probe_read_kernel(&exit_code, sizeof(exit_code), &task->exit_code);
    evt->exit_code = (__u32)(exit_code >> 8);

    struct task_struct *real_parent;
    bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);
    if (real_parent) {
        bpf_probe_read_kernel(&evt->ppid, sizeof(evt->ppid), &real_parent->pid);
    }

    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    bpf_map_delete_elem(&exec_uid_map, &pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
