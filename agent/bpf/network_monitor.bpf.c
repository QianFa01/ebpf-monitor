// SPDX-License-Identifier: GPL-2.0
// network_monitor.bpf.c - TCP and UDP connection monitoring

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

#define EVENT_TCP_CONNECT  10
#define EVENT_TCP_ACCEPT   11
#define EVENT_TCP_CLOSE    12
#define EVENT_UDP_SEND     20
#define EVENT_UDP_RECV     21

struct network_event {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    __u32 cgroup_id;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} network_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct network_event));
    __uint(max_entries, 1);
} network_event_heap SEC(".maps");

struct sock_info {
    __u32 pid;
    __u32 saddr;
    __u16 sport;
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct sock_info));
    __uint(max_entries, 10240);
} sock_info_map SEC(".maps");

static __always_inline __u32 get_cgroup_id(void) {
    return (__u32)(bpf_get_current_cgroup_id() & 0xFFFFFFFF);
}

static __always_inline void fill_network_event(struct network_event *evt,
                                                __u32 event_type,
                                                __u32 saddr, __u32 daddr,
                                                __u16 sport, __u16 dport,
                                                __u8 proto) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->timestamp = bpf_ktime_get_ns();
    evt->event_type = event_type;
    evt->pid = pid_tgid >> 32;
    evt->uid = uid_gid & 0xFFFFFFFF;
    evt->cgroup_id = get_cgroup_id();
    evt->saddr = saddr;
    evt->daddr = daddr;
    evt->sport = sport;
    evt->dport = dport;
    evt->proto = proto;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe__tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct sock_info info = {};
    info.pid = tid >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    __u32 saddr = 0;
    __u16 sport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    info.saddr = saddr;
    info.sport = sport;

    bpf_map_update_elem(&sock_info_map, &tid, &info, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe__tcp_v4_connect, int ret) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct sock_info *info = bpf_map_lookup_elem(&sock_info_map, &tid);
    if (!info) return 0;

    __u32 key = 0;
    struct network_event *evt = bpf_map_lookup_elem(&network_event_heap, &key);
    if (!evt) goto cleanup;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_network_event(evt, EVENT_TCP_CONNECT, info->saddr, 0, info->sport, 0, 6);
    bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

cleanup:
    bpf_map_delete_elem(&sock_info_map, &tid);
    return 0;
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(kprobe__tcp_set_state, struct sock *sk, int new_state) {
    if (new_state != TCP_ESTABLISHED) return 0;

    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = __builtin_bswap16(dport);

    __u32 key = 0;
    struct network_event *evt = bpf_map_lookup_elem(&network_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_network_event(evt, EVENT_TCP_CONNECT, saddr, daddr, sport, dport, 6);
    bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe__inet_csk_accept, struct sock *sk) {
    if (!sk) return 0;

    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    sport = __builtin_bswap16(sport);
    dport = __builtin_bswap16(dport);

    __u32 key = 0;
    struct network_event *evt = bpf_map_lookup_elem(&network_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_network_event(evt, EVENT_TCP_ACCEPT, daddr, saddr, dport, sport, 6);
    bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe__tcp_close, struct sock *sk, long timeout) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    sport = __builtin_bswap16(sport);
    dport = __builtin_bswap16(dport);

    if (saddr == 0 && daddr == 0) return 0;

    __u32 key = 0;
    struct network_event *evt = bpf_map_lookup_elem(&network_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_network_event(evt, EVENT_TCP_CLOSE, saddr, daddr, sport, dport, 6);
    bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe__udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = __builtin_bswap16(dport);

    __u32 key = 0;
    struct network_event *evt = bpf_map_lookup_elem(&network_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_network_event(evt, EVENT_UDP_SEND, saddr, daddr, sport, dport, 17);
    bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(kretprobe__udp_recvmsg, int ret) {
    if (ret <= 0) return 0;

    struct sock *sk = (struct sock *)ctx->di;
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = __builtin_bswap16(dport);

    __u32 key = 0;
    struct network_event *evt = bpf_map_lookup_elem(&network_event_heap, &key);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_network_event(evt, EVENT_UDP_RECV, daddr, saddr, dport, sport, 17);
    bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
    return 0;
}

char _license[] SEC("license") = "GPL";
