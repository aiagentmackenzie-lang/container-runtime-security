// +build linux

// eBPF TC (Traffic Control) classifier program for network policy enforcement.
// Attaches to network interfaces at TC ingress/egress to block connections
// by destination IP, destination port, and protocol.
//
// Per SRD Section 6.1.3 and Deliverable 5:
//   - IP/port blocklist as BPF hash map, updated from userspace
//   - Block by: destination IP, destination port, protocol (TCP/UDP)
//   - Integrates with rule engine: R009/R027 match → add IP/port to blocklist
//   - Blocklist TTL (default 5 min) managed from userspace
//   - Metrics: scarlet_network_blocks_total{rule,reason}
//
// Build note: Requires Linux kernel headers (BPF TC support, kernel 5.8+).
// Will not compile on macOS. Use build tags for cross-platform compatibility.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ── Network Block Constants ────────────────────────────────────────────

#define SCARLET_NET_BLOCK_IPV4   1
#define SCARLET_NET_BLOCK_IPV6   2
#define SCARLET_NET_BLOCK_PORT   3
#define SCARLET_NET_BLOCK_COMBINED 4

#define SCARLET_PROTO_TCP  6
#define SCARLET_PROTO_UDP  17

#define SCARLET_TC_VERDICT_ALLOW 0
#define SCARLET_TC_VERDICT_DROP  2  // TC_ACT_SHOT

// ── Network Block Entry ────────────────────────────────────────────────

// network_block_key identifies an IP+port+protocol combination to block.
struct network_block_key {
    __u32 dest_ip;      // Network byte order IPv4 address
    __u16 dest_port;    // Network byte order destination port
    __u8  protocol;    // IPPROTO_TCP=6, IPPROTO_UDP=17, 0=any
    __u8  _pad;
};

// network_block_value holds metadata about why a block was placed.
struct network_block_value {
    __u64 block_time_ns;  // When the block was added (bpf_ktime_get_ns)
    __u32 ttl_seconds;    // Block duration in seconds
    __u32 rule_id;        // Rule that triggered the block (e.g., R009)
    __u8  block_type;     // SCARLET_NET_BLOCK_*
    __u8  reason;         // Reason code
    __u16 _pad;
};

// ── BPF Maps ───────────────────────────────────────────────────────────

// network_blocklist: IP/port/protocol → block metadata
// Updated from userspace when rule enforcement dictates a network block.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct network_block_key);
    __type(value, struct network_block_value);
} network_blocklist SEC(".maps");

// network_block_stats: per-rule block counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);   // rule_id
    __type(value, __u64); // packet count
} network_block_stats SEC(".maps");

// network_block_events: ring buffer for block event notifications
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1MB ring buffer for block events
} network_block_events SEC(".maps");

// ── Network Block Event ────────────────────────────────────────────────

struct network_block_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u8  protocol;
    __u8  block_type;
    __u32 rule_id;
    __u64 cgroup_id;
};

// ── Packet Parsing Helpers ──────────────────────────────────────────────

// parse_eth_hdr validates Ethernet header and returns next protocol.
static __always_inline int parse_eth_hdr(struct __sk_buff *skb, __u16 *eth_proto) {
    if (bpf_skb_pull_data(skb, 14) < 0)
        return -1;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    *eth_proto = bpf_ntohs(eth->h_proto);
    return 0;
}

// parse_ipv4_hdr extracts IPv4 header fields.
static __always_inline int parse_ipv4_hdr(struct __sk_buff *skb,
    __u32 *src_ip, __u32 *dest_ip, __u8 *protocol) {
    if (bpf_skb_pull_data(skb, 34) < 0)
        return -1;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data + 14;  // Skip Ethernet header
    if ((void *)(iph + 1) > data_end)
        return -1;

    *src_ip = bpf_ntohl(iph->saddr);
    *dest_ip = bpf_ntohl(iph->daddr);
    *protocol = iph->protocol;
    return 0;
}

// parse_tcp_hdr extracts TCP destination port.
static __always_inline int parse_tcp_hdr(struct __sk_buff *skb,
    __u16 *dest_port, __u8 ihl) {
    if (bpf_skb_pull_data(skb, 54) < 0)
        return -1;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct tcphdr *tcp = data + 14 + ihl;  // Ethernet + IP header
    if ((void *)(tcp + 1) > data_end)
        return -1;

    *dest_port = bpf_ntohs(tcp->dest);
    return 0;
}

// parse_udp_hdr extracts UDP destination port.
static __always_inline int parse_udp_hdr(struct __sk_buff *skb,
    __u16 *dest_port, __u8 ihl) {
    if (bpf_skb_pull_data(skb, 42) < 0)
        return -1;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct udphdr *udp = data + 14 + ihl;  // Ethernet + IP header
    if ((void *)(udp + 1) > data_end)
        return -1;

    *dest_port = bpf_ntohs(udp->dest);
    return 0;
}

// ── Block Check ────────────────────────────────────────────────────────

// check_network_blocklist checks if a packet should be blocked.
// Returns TC_ACT_SHOT (drop) if the destination matches the blocklist,
// or TC_ACT_OK (allow) if no match.
static __always_inline int check_blocklist(__u32 dest_ip, __u16 dest_port, __u8 protocol) {
    struct network_block_key key = {};
    struct network_block_value *val;

    // Check 1: exact match (IP + port + protocol)
    key.dest_ip = dest_ip;
    key.dest_port = dest_port;
    key.protocol = protocol;

    val = bpf_map_lookup_elem(&network_blocklist, &key);
    if (val) {
        return SCARLET_TC_VERDICT_DROP;
    }

    // Check 2: IP + port, any protocol
    key.protocol = 0;
    val = bpf_map_lookup_elem(&network_blocklist, &key);
    if (val) {
        return SCARLET_TC_VERDICT_DROP;
    }

    // Check 3: IP only, any port, any protocol
    key.dest_port = 0;
    key.protocol = 0;
    val = bpf_map_lookup_elem(&network_blocklist, &key);
    if (val) {
        return SCARLET_TC_VERDICT_DROP;
    }

    // Check 4: port only, any IP (e.g., block all traffic to port 4444)
    key.dest_ip = 0;
    key.dest_port = dest_port;
    key.protocol = 0;
    val = bpf_map_lookup_elem(&network_blocklist, &key);
    if (val) {
        return SCARLET_TC_VERDICT_DROP;
    }

    // Check 5: port + protocol, any IP
    key.dest_ip = 0;
    key.dest_port = dest_port;
    key.protocol = protocol;
    val = bpf_map_lookup_elem(&network_blocklist, &key);
    if (val) {
        return SCARLET_TC_VERDICT_DROP;
    }

    return SCARLET_TC_VERDICT_ALLOW;
}

// emit_block_event sends a notification that a packet was blocked.
static __always_inline void emit_block_event(struct __sk_buff *skb,
    __u32 src_ip, __u32 dest_ip, __u16 src_port, __u16 dest_port,
    __u8 protocol, __u32 rule_id) {
    struct network_block_event *e;
    e = bpf_ringbuf_reserve(&network_block_events, sizeof(*e), 0);
    if (!e)
        return;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->src_ip = src_ip;
    e->dest_ip = dest_ip;
    e->src_port = src_port;
    e->dest_port = dest_port;
    e->protocol = protocol;
    e->block_type = SCARLET_NET_BLOCK_COMBINED;
    e->rule_id = rule_id;
    e->cgroup_id = bpf_get_cgroup_id();

    bpf_ringbuf_submit(e, 0);
}

// ── TC Classifier Programs ─────────────────────────────────────────────

// tc_ingress filters incoming packets at the TC ingress hook.
SEC("tc")
int tc_ingress_filter(struct __sk_buff *skb) {
    __u16 eth_proto;

    if (parse_eth_hdr(skb, &eth_proto) < 0)
        return SCARLET_TC_VERDICT_ALLOW;

    // Only handle IPv4 (0x0800)
    if (eth_proto != 0x0800)
        return SCARLET_TC_VERDICT_ALLOW;

    __u32 src_ip, dest_ip;
    __u8 protocol;

    if (parse_ipv4_hdr(skb, &src_ip, &dest_ip, &protocol) < 0)
        return SCARLET_TC_VERDICT_ALLOW;

    __u16 dest_port = 0;

    if (protocol == SCARLET_PROTO_TCP) {
        if (parse_tcp_hdr(skb, &dest_port, 0) < 0)
            return SCARLET_TC_VERDICT_ALLOW;
    } else if (protocol == SCARLET_PROTO_UDP) {
        if (parse_udp_hdr(skb, &dest_port, 0) < 0)
            return SCARLET_TC_VERDICT_ALLOW;
    }

    // Check if this packet should be blocked
    int verdict = check_blocklist(dest_ip, dest_port, protocol);
    if (verdict == SCARLET_TC_VERDICT_DROP) {
        // Increment block stats (find the matching rule)
        // For port-only blocks, use rule_id 0 as counter
        __u32 stats_key = 0;
        __u64 *count = bpf_map_lookup_elem(&network_block_stats, &stats_key);
        if (count) {
            (*count)++;
        }

        return SCARLET_TC_VERDICT_DROP;
    }

    return SCARLET_TC_VERDICT_ALLOW;
}

// tc_egress filters outgoing packets at the TC egress hook.
SEC("tc")
int tc_egress_filter(struct __sk_buff *skb) {
    __u16 eth_proto;

    if (parse_eth_hdr(skb, &eth_proto) < 0)
        return SCARLET_TC_VERDICT_ALLOW;

    // Only handle IPv4 (0x0800)
    if (eth_proto != 0x0800)
        return SCARLET_TC_VERDICT_ALLOW;

    __u32 src_ip, dest_ip;
    __u8 protocol;

    if (parse_ipv4_hdr(skb, &src_ip, &dest_ip, &protocol) < 0)
        return SCARLET_TC_VERDICT_ALLOW;

    __u16 dest_port = 0;

    if (protocol == SCARLET_PROTO_TCP) {
        if (parse_tcp_hdr(skb, &dest_port, 0) < 0)
            return SCARLET_TC_VERDICT_ALLOW;
    } else if (protocol == SCARLET_PROTO_UDP) {
        if (parse_udp_hdr(skb, &dest_port, 0) < 0)
            return SCARLET_TC_VERDICT_ALLOW;
    }

    // Check if this outgoing packet should be blocked
    int verdict = check_blocklist(dest_ip, dest_port, protocol);
    if (verdict == SCARLET_TC_VERDICT_DROP) {
        __u32 stats_key = 0;
        __u64 *count = bpf_map_lookup_elem(&network_block_stats, &stats_key);
        if (count) {
            (*count)++;
        }

        return SCARLET_TC_VERDICT_DROP;
    }

    return SCARLET_TC_VERDICT_ALLOW;
}