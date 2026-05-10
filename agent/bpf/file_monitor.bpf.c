// SPDX-License-Identifier: GPL-2.0
// file_monitor.bpf.c - File system event monitoring

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

#define EVENT_FILE_CREATE  30
#define EVENT_FILE_MODIFY  31
#define EVENT_FILE_DELETE  32
#define EVENT_FILE_RENAME  33
#define EVENT_FILE_CHMOD   34
#define EVENT_FILE_CHOWN   35

struct file_event {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 cgroup_id;
    __u32 mode;
    __u32 flags;
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
    char  old_filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} file_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct file_event));
    __uint(max_entries, 1);
} file_event_heap SEC(".maps");

static __always_inline __u32 get_cgroup_id(void) {
    return (__u32)(bpf_get_current_cgroup_id() & 0xFFFFFFFF);
}

static __always_inline void fill_file_event(struct file_event *evt, __u32 event_type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->timestamp = bpf_ktime_get_ns();
    evt->event_type = event_type;
    evt->pid = pid_tgid >> 32;
    evt->uid = uid_gid & 0xFFFFFFFF;
    evt->gid = uid_gid >> 32;
    evt->cgroup_id = get_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    int flags = (int)ctx->args[2];
    int mode = (int)ctx->args[3];
    if (!(flags & O_CREAT)) return 0;

    __u32 key = 0;
    struct file_event *evt = bpf_map_lookup_elem(&file_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_file_event(evt, EVENT_FILE_CREATE);
    evt->flags = flags;
    evt->mode = mode;

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), filename);

    if (evt->filename[0] == '/')
        bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct file_event *evt = bpf_map_lookup_elem(&file_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_file_event(evt, EVENT_FILE_DELETE);

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), filename);

    if (evt->filename[0] == '/')
        bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    return 0;
}

SEC("kprobe/vfs_rename")
int BPF_KPROBE(kprobe__vfs_rename, struct inode *old_dir, struct dentry *old_dentry,
               struct inode *new_dir, struct dentry *new_dentry) {
    __u32 key = 0;
    struct file_event *evt = bpf_map_lookup_elem(&file_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_file_event(evt, EVENT_FILE_RENAME);

    struct dentry *parent;
    struct qstr old_name, new_name;
    bpf_probe_read_kernel(&old_name, sizeof(old_name), &old_dentry->d_name);
    bpf_probe_read_kernel(&new_name, sizeof(new_name), &new_dentry->d_name);

    bpf_probe_read_kernel(&parent, sizeof(parent), &old_dentry->d_parent);
    if (parent) {
        struct qstr parent_name;
        bpf_probe_read_kernel(&parent_name, sizeof(parent_name), &parent->d_name);
        int plen = parent_name.len;
        if (plen > 0 && plen < MAX_FILENAME_LEN - 2) {
            bpf_probe_read_kernel_str(evt->old_filename, MAX_FILENAME_LEN, parent_name.name);
            int offset = plen;
            if (offset < MAX_FILENAME_LEN - 1) {
                evt->old_filename[offset] = '/';
                offset++;
                bpf_probe_read_kernel_str(evt->old_filename + offset,
                                          MAX_FILENAME_LEN - offset, old_name.name);
            }
        }
    }

    bpf_probe_read_kernel(&parent, sizeof(parent), &new_dentry->d_parent);
    if (parent) {
        struct qstr parent_name;
        bpf_probe_read_kernel(&parent_name, sizeof(parent_name), &parent->d_name);
        int plen = parent_name.len;
        if (plen > 0 && plen < MAX_FILENAME_LEN - 2) {
            bpf_probe_read_kernel_str(evt->filename, MAX_FILENAME_LEN, parent_name.name);
            int offset = plen;
            if (offset < MAX_FILENAME_LEN - 1) {
                evt->filename[offset] = '/';
                offset++;
                bpf_probe_read_kernel_str(evt->filename + offset,
                                          MAX_FILENAME_LEN - offset, new_name.name);
            }
        }
    }

    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    return 0;
}

SEC("kprobe/security_inode_setattr")
int BPF_KPROBE(kprobe__security_inode_setattr, struct dentry *dentry, struct iattr *attr) {
    if (!dentry || !attr) return 0;

    int attr_valid;
    bpf_probe_read_kernel(&attr_valid, sizeof(attr_valid), &attr->ia_valid);

    __u32 event_type = 0;
    if (attr_valid & ATTR_MODE)
        event_type = EVENT_FILE_CHMOD;
    else if (attr_valid & (ATTR_UID | ATTR_GID))
        event_type = EVENT_FILE_CHOWN;
    else
        return 0;

    __u32 key = 0;
    struct file_event *evt = bpf_map_lookup_elem(&file_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_file_event(evt, event_type);

    struct qstr d_name;
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
    bpf_probe_read_kernel_str(&evt->filename, sizeof(evt->filename), d_name.name);

    if (event_type == EVENT_FILE_CHMOD) {
        umode_t mode;
        bpf_probe_read_kernel(&mode, sizeof(mode), &attr->ia_mode);
        evt->mode = mode;
    }

    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe__vfs_write, struct file *file, const char *buf,
               size_t count, loff_t *pos) {
    if (count < 16) return 0;

    struct inode *inode;
    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);

    umode_t mode;
    bpf_probe_read_kernel(&mode, sizeof(mode), &inode->i_mode);
    if (!S_ISREG(mode)) return 0;

    __u32 key = 0;
    struct file_event *evt = bpf_map_lookup_elem(&file_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_file_event(evt, EVENT_FILE_MODIFY);

    struct dentry *dentry;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
    if (dentry) {
        struct qstr d_name;
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
        bpf_probe_read_kernel_str(&evt->filename, sizeof(evt->filename), d_name.name);
    }

    evt->flags = count;
    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    return 0;
}

char _license[] SEC("license") = "GPL";
