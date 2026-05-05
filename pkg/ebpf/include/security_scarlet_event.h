/* security_scarlet_event.h — Shared event structure between eBPF kernel probes and Go userspace
 *
 * This header defines the fixed-size event struct written to the BPF ring buffer
 * by eBPF probes and read by the Go agent. Both sides must agree on layout.
 *
 * Design principles:
 *   - Fixed-size struct (no variable-length fields) for ring buffer efficiency
 *   - Union-based payload keeps total size constant regardless of event category
 *   - Inspired by Juliet's 304-byte approach, extended for our 6 categories
 *
 * Total struct size: ~432 bytes (fixed, union-based)
 */

#ifndef __SECURITY_SCARLET_EVENT_H__
#define __SECURITY_SCARLET_EVENT_H__

#ifndef __BPF__
#pragma pack(push, 1)
#endif

#define SCARLET_MAX_COMM_LEN    16
#define SCARLET_MAX_PATH_LEN    256
#define SCARLET_MAX_ARGS_LEN    128
#define SCARLET_MAX_IPv6_ADDR   16
#define SCARLET_MAX_IPv4_ADDR   4
#define SCARLET_NS_COUNT        8

/* Event categories — determines which union member is active */
enum scarlet_event_category {
    SCARLET_CAT_PROCESS    = 1,
    SCARLET_CAT_FILE       = 2,
    SCARLET_CAT_NETWORK    = 3,
    SCARLET_CAT_ESCAPE     = 4,
    SCARLET_CAT_PRIVILEGE  = 5,
    SCARLET_CAT_CREDENTIAL = 6,
};

/* Event types within categories */
enum scarlet_event_type {
    /* Process events (1-9) */
    SCARLET_EVT_EXEC        = 1,
    SCARLET_EVT_FORK        = 2,
    SCARLET_EVT_EXIT        = 3,

    /* File events (10-19) */
    SCARLET_EVT_FILE_OPEN   = 10,
    SCARLET_EVT_FILE_UNLINK = 11,
    SCARLET_EVT_FILE_MEMFD  = 12,
    SCARLET_EVT_FILE_RENAME = 13,

    /* Network events (20-29) */
    SCARLET_EVT_NET_CONNECT = 20,
    SCARLET_EVT_NET_LISTEN  = 21,
    SCARLET_EVT_NET_STATE   = 22,
    SCARLET_EVT_NET_UDP     = 23,

    /* Escape events (30-39) */
    SCARLET_EVT_SETNS       = 30,
    SCARLET_EVT_UNSHARE     = 31,
    SCARLET_EVT_MOUNT       = 32,
    SCARLET_EVT_PTRACE      = 33,
    SCARLET_EVT_MODULE_LOAD = 34,
    SCARLET_EVT_BPF_LOAD    = 35,

    /* Privilege events (40-49) */
    SCARLET_EVT_SETUID      = 40,
    SCARLET_EVT_SETRESUID   = 41,
    SCARLET_EVT_CAPSET      = 42,
    SCARLET_EVT_CHMOD       = 43,

    /* Credential events (50-59) — composite, uses file/network payloads */
    SCARLET_EVT_CRED_ACCESS = 50,
};

/* Process event payload */
struct scarlet_process_payload {
    char filename[SCARLET_MAX_PATH_LEN];    /* executed binary path */
    char args[SCARLET_MAX_ARGS_LEN];        /* first 128 bytes of args */
};

/* File event payload */
struct scarlet_file_payload {
    char path[SCARLET_MAX_PATH_LEN];        /* file path */
    __u32 flags;                             /* open flags (O_RDONLY, O_WRONLY, etc.) */
    __u32 mode;                              /* file mode (for chmod) */
};

/* Network event payload */
struct scarlet_network_payload {
    __u8  local_addr[SCARLET_MAX_IPv4_ADDR];  /* source IP */
    __u8  remote_addr[SCARLET_MAX_IPv4_ADDR]; /* dest IP */
    __u16 local_port;                          /* source port */
    __u16 remote_port;                         /* dest port */
    __u8  protocol;                            /* IPPROTO_TCP/UDP */
    __u8  family;                              /* AF_INET/AF_INET6 */
    __u16 _net_pad;
};

/* Escape event payload */
struct scarlet_escape_payload {
    __u32 ns_type;                              /* namespace type (CLONE_NEW*) */
    __u32 target_ns[SCARLET_NS_COUNT];         /* namespace inode numbers */
    __u8  ns_count;                            /* number of namespaces */
    __u8  _esc_pad[3];
};

/* Privilege event payload */
struct scarlet_privilege_payload {
    __u32 old_uid;
    __u32 new_uid;
    __u32 capability;                          /* capability number */
    __u32 mode_flags;                          /* chmod mode flags */
};

/* Main event structure — fixed size, union-based */
struct scarlet_event {
    __u64 timestamp_ns;           /* bpf_ktime_get_ns() */
    __u32 pid;                    /* process ID */
    __u32 tgid;                   /* thread group ID (main PID) */
    __u32 ppid;                   /* parent PID */
    __u32 uid;                    /* user ID */
    __u32 gid;                    /* group ID */
    __u64 cgroup_id;              /* cgroup inode number (container ID) */
    __u32 pid_ns_level;           /* PID namespace depth (0=host, >0=container) */
    __u8  category;               /* scarlet_event_category */
    __u8  event_type;             /* scarlet_event_type */
    __u16 syscall_nr;             /* syscall number */
    __u8  _pad[2];
    char  comm[SCARLET_MAX_COMM_LEN];     /* process command name */

    /* Category-specific payload — fixed total size via union */
    union {
        struct scarlet_process_payload process;
        struct scarlet_file_payload    file;
        struct scarlet_network_payload  network;
        struct scarlet_escape_payload   escape;
        struct scarlet_privilege_payload privilege;
    } payload;
};

#ifndef __BPF__
#pragma pack(pop)
#endif

#endif /* __SECURITY_SCARLET_EVENT_H__ */