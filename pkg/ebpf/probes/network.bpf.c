/* network.bpf.c — Network connection monitoring eBPF probes
 *
 * Monitors outbound TCP/UDP connections, detects C2 callbacks, mining pool
 * connections, and cloud metadata service access.
 *
 * Probes:
 *   - kprobe/tcp_v4_connect          (outbound IPv4 TCP connect)
 *   - kprobe/tcp_v6_connect          (outbound IPv6 TCP connect)
 *   - kprobe/ip4_datagram_connect    (outbound IPv4 UDP connect)
 *   - tracepoint/sock/inet_sock_set_state (TCP state changes)
 *   - tracepoint/syscalls/sys_enter_listen (listen for rogue listeners)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "security_scarlet_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ── Maps ──────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u32);
} container_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);
    __type(value, __u8);
} monitored_syscalls SEC(".maps");

/* Known mining pool ports — kernel-side early filter */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);    /* port number */
    __type(value, __u8);   /* 1 = known mining pool */
} miner_pool_ports SEC(".maps");

/* Known C2 ports */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u8);
} c2_ports SEC(".maps");

/* Cloud metadata IPs — AWS/GCP/Azure (for SSRF detection) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);    /* IPv4 addr as u32, network byte order */
    __type(value, __u8);  /* 1 = metadata service */
} cloud_metadata_ips SEC(".maps");

/* ── Helper functions ───────────────────────────────────────────────── */

static __always_inline int is_container_process(__u64 cgroup_id)
{
    return bpf_map_lookup_elem(&container_cgroups, &cgroup_id) != NULL;
}

static __always_inline void fill_event_header(struct scarlet_event *e,
                                                __u8 category,
                                                __u8 event_type,
                                                __u16 syscall_nr)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;
    e->tgid = pid_tgid & 0xFFFFFFFF;
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = uid_gid >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->category = category;
    e->event_type = event_type;
    e->syscall_nr = syscall_nr;

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    struct pid *pid_struct = BPF_CORE_READ(task, thread_pid);
    if (pid_struct) {
        struct pid_namespace *pid_ns = BPF_CORE_READ(pid_struct, numbers[0].ns);
        if (pid_ns) {
            e->pid_ns_level = BPF_CORE_READ(pid_ns, level);
        } else {
            e->pid_ns_level = 0;
        }
    } else {
        e->pid_ns_level = 0;
    }

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void fill_network_payload(struct scarlet_event *e,
                                                   struct sock *sk,
                                                   __u8 protocol)
{
    struct inet_sock *inet = (struct inet_sock *)sk;

    /* Read source address */
    __u32 saddr = BPF_CORE_READ(inet, inet_saddr);
    __builtin_memcpy(e->payload.network.local_addr, &saddr, 4);

    /* Read destination address */
    __u32 daddr = BPF_CORE_READ(inet, inet_daddr);
    __builtin_memcpy(e->payload.network.remote_addr, &daddr, 4);

    /* Read ports */
    e->payload.network.local_port = BPF_CORE_READ(inet, inet_sport);
    e->payload.network.remote_port = __bpf_ntohs(BPF_CORE_READ(inet, inet_dport));

    e->payload.network.protocol = protocol;
    e->payload.network.family = BPF_CORE_READ(sk, sk_family);
    e->payload.network._net_pad = 0;
}

/* ── kprobe: tcp_v4_connect ────────────────────────────────────────── */

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    /* Early filter: check if destination port or IP is interesting */
    struct inet_sock *inet = (struct inet_sock *)sk;
    __u16 dport = __bpf_ntohs(BPF_CORE_READ(inet, inet_dport));
    __u32 daddr = BPF_CORE_READ(inet, inet_daddr);

    /* Only emit if: mining pool port, C2 port, or cloud metadata IP,
       or if all connections are being monitored */
    int interesting = 0;
    if (bpf_map_lookup_elem(&miner_pool_ports, &dport))
        interesting = 1;
    if (bpf_map_lookup_elem(&c2_ports, &dport))
        interesting = 1;
    if (bpf_map_lookup_elem(&cloud_metadata_ips, &daddr))
        interesting = 1;

    if (!interesting) {
        __u32 syscall_nr = 42; /* __NR_connect */
        if (!bpf_map_lookup_elem(&monitored_syscalls, &syscall_nr))
            return 0;
    }

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_event_header(e, SCARLET_CAT_NETWORK, SCARLET_EVT_NET_CONNECT, 42);
    fill_network_payload(e, sk, IPPROTO_TCP);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── kprobe: tcp_v6_connect ────────────────────────────────────────── */

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(trace_tcp_v6_connect, struct sock *sk)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_event_header(e, SCARLET_CAT_NETWORK, SCARLET_EVT_NET_CONNECT, 42);

    /* For IPv6, store the first 4 bytes of address */
    struct inet_sock *inet = (struct inet_sock *)sk;
    BPF_CORE_READ_INTO(e->payload.network.remote_addr, inet, pinet6->saddr.in6_u.u6_addr8);
    e->payload.network.remote_port = __bpf_ntohs(BPF_CORE_READ(inet, inet_dport));
    e->payload.network.local_port = BPF_CORE_READ(inet, inet_sport);
    e->payload.network.protocol = IPPROTO_TCP;
    e->payload.network.family = AF_INET6;
    e->payload.network._net_pad = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── kprobe: ip4_datagram_connect ───────────────────────────────────── */

SEC("kprobe/ip4_datagram_connect")
int BPF_KPROBE(trace_ip4_datagram_connect, struct sock *sk)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_event_header(e, SCARLET_CAT_NETWORK, SCARLET_EVT_NET_UDP, 42);
    fill_network_payload(e, sk, IPPROTO_UDP);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_listen (rogue listener detection) ──────── */

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_event_header(e, SCARLET_CAT_NETWORK, SCARLET_EVT_NET_LISTEN, 50);

    /* listen(fd, backlog) — we don't have socket details easily here,
       userspace enrichment will resolve from /proc/net/tcp */
    e->payload.network.local_port = 0;
    e->payload.network.remote_port = 0;
    e->payload.network.protocol = IPPROTO_TCP;
    e->payload.network.family = AF_INET;
    e->payload.network._net_pad = 0;
    __builtin_memset(e->payload.network.local_addr, 0, 4);
    __builtin_memset(e->payload.network.remote_addr, 0, 4);

    bpf_ringbuf_submit(e, 0);
    return 0;
}