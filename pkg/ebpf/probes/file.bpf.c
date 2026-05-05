/* file.bpf.c — File access monitoring eBPF probes
 *
 * Monitors file operations: openat, unlinkat, memfd_create.
 * Detects sensitive file access, file deletion, and fileless malware.
 *
 * Tracepoints:
 *   - syscalls/sys_enter_openat     (openat)
 *   - syscalls/sys_enter_unlinkat   (unlinkat)
 *   - syscalls/sys_enter_memfd_create (memfd_create)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "security_scarlet_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ── Maps (shared with other probes — same section names) ─────────── */

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

/* Sensitive paths prefix match — kernel-side fast reject */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);   /* hash of first 8 chars of path */
    __type(value, __u8);  /* 1 = sensitive */
} sensitive_path_prefixes SEC(".maps");

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

/* Simple hash for path prefix matching */
static __always_inline __u64 path_prefix_hash(const char *path)
{
    __u64 hash = 0;
    /* Use first 8 bytes as a simple hash for prefix matching */
    bpf_probe_read_user(&hash, 8, path);
    return hash;
}

/* ── Tracepoint: sys_enter_openat ───────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    /* Read the filename pointer from syscall args */
    const char *filename_ptr = (const char *)ctx->args[1];
    __s32 flags = (__s32)ctx->args[2];

    /* Early filter: check if this path might be sensitive */
    __u64 path_hash = path_prefix_hash(filename_ptr);
    __u8 *is_sensitive = bpf_map_lookup_elem(&sensitive_path_prefixes, &path_hash);

    /* Only emit events for sensitive paths or all file opens if enabled */
    if (!is_sensitive) {
        /* Check if we're monitoring all file opens (wide mode) */
        __u32 syscall_nr = 257; /* __NR_openat */
        if (!bpf_map_lookup_elem(&monitored_syscalls, &syscall_nr))
            return 0;
    }

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_event_header(e, SCARLET_CAT_FILE, SCARLET_EVT_FILE_OPEN, 257);

    /* Read file path from userspace */
    bpf_probe_read_user_str(&e->payload.file.path,
                             sizeof(e->payload.file.path),
                             filename_ptr);

    e->payload.file.flags = flags;
    e->payload.file.mode = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_unlinkat ─────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_event_header(e, SCARLET_CAT_FILE, SCARLET_EVT_FILE_UNLINK, 263);

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->payload.file.path,
                             sizeof(e->payload.file.path),
                             pathname);

    e->payload.file.flags = 0;
    e->payload.file.mode = (__u32)ctx->args[2]; /* flags for unlinkat */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_memfd_create ────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_event_header(e, SCARLET_CAT_FILE, SCARLET_EVT_FILE_MEMFD, 319);

    const char *name_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->payload.file.path,
                             sizeof(e->payload.file.path),
                             name_ptr);

    e->payload.file.flags = (__u32)ctx->args[1]; /* MFD_* flags */
    e->payload.file.mode = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}