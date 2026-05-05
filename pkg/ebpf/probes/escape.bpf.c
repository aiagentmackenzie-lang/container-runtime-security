/* escape.bpf.c — Container escape and namespace monitoring eBPF probes
 *
 * Monitors namespace operations, mounts, ptrace, kernel module loads,
 * and eBPF program loading from containers.
 *
 * Tracepoints:
 *   - syscalls/sys_enter_setns        (namespace join)
 *   - syscalls/sys_enter_unshare      (namespace creation)
 *   - syscalls/sys_enter_mount        (filesystem mount)
 *   - syscalls/sys_enter_ptrace      (process injection)
 *   - syscalls/sys_enter_init_module  (kernel module loading)
 *   - syscalls/sys_enter_bpf         (eBPF program loading)
 *   - syscalls/sys_enter_chmod       (chmod for SUID detection)
 *   - syscalls/sys_enter_setuid      (UID transitions)
 *   - syscalls/sys_enter_capset      (capability changes)
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

/* ── Tracepoint: sys_enter_setns ────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_setns = 308 on x86_64 */
    fill_event_header(e, SCARLET_CAT_ESCAPE, SCARLET_EVT_SETNS, 308);

    /* setns(fd, nstype) */
    e->payload.escape.ns_type = (__u32)ctx->args[1]; /* CLONE_NEW* flags */
    e->payload.escape.ns_count = 0;
    __builtin_memset(e->payload.escape.target_ns, 0,
                     sizeof(e->payload.escape.target_ns));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_unshare ──────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_unshare = 272 on x86_64 */
    fill_event_header(e, SCARLET_CAT_ESCAPE, SCARLET_EVT_UNSHARE, 272);

    e->payload.escape.ns_type = (__u32)ctx->args[0]; /* CLONE_NEW* flags */
    e->payload.escape.ns_count = 0;
    __builtin_memset(e->payload.escape.target_ns, 0,
                     sizeof(e->payload.escape.target_ns));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_mount ────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_mount(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_mount = 165 on x86_64 */
    fill_event_header(e, SCARLET_CAT_ESCAPE, SCARLET_EVT_MOUNT, 165);

    /* mount(source, target, filesystemtype, mountflags, data) */
    /* Store source as ns_type field for mount events */
    e->payload.escape.ns_type = (__u32)ctx->args[3]; /* mount flags */
    e->payload.escape.ns_count = 0;

    /* Try to read the filesystem type to help identify cgroup mounts */
    const char *type = (const char *)ctx->args[2];
    bpf_probe_read_user_str((char *)e->payload.escape.target_ns,
                             sizeof(e->payload.escape.target_ns),
                             type);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_ptrace ────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_ptrace = 101 on x86_64 */
    fill_event_header(e, SCARLET_CAT_ESCAPE, SCARLET_EVT_PTRACE, 101);

    /* ptrace(request, pid, addr, data) */
    e->payload.escape.ns_type = (__u32)ctx->args[0]; /* PTRACE_* request */
    e->payload.escape.ns_count = 0;
    __builtin_memset(e->payload.escape.target_ns, 0,
                     sizeof(e->payload.escape.target_ns));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_init_module ──────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_init_module = 175 on x86_64 */
    fill_event_header(e, SCARLET_CAT_ESCAPE, SCARLET_EVT_MODULE_LOAD, 175);

    e->payload.escape.ns_type = 0;
    e->payload.escape.ns_count = 0;
    __builtin_memset(e->payload.escape.target_ns, 0,
                     sizeof(e->payload.escape.target_ns));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_bpf (eBPF attack detection) ─────────────── */

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_bpf = 321 on x86_64 */
    fill_event_header(e, SCARLET_CAT_ESCAPE, SCARLET_EVT_BPF_LOAD, 321);

    /* bpf(cmd, attr, size) */
    e->payload.escape.ns_type = (__u32)ctx->args[0]; /* BPF_* cmd */
    e->payload.escape.ns_count = 0;
    __builtin_memset(e->payload.escape.target_ns, 0,
                     sizeof(e->payload.escape.target_ns));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_setuid ───────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_setuid = 105 on x86_64 */
    fill_event_header(e, SCARLET_CAT_PRIVILEGE, SCARLET_EVT_SETUID, 105);

    e->payload.privilege.old_uid = e->uid;
    e->payload.privilege.new_uid = (__u32)ctx->args[0];
    e->payload.privilege.capability = 0;
    e->payload.privilege.mode_flags = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_capset ───────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_capset = 126 on x86_64 */
    fill_event_header(e, SCARLET_CAT_PRIVILEGE, SCARLET_EVT_CAPSET, 126);

    e->payload.privilege.old_uid = e->uid;
    e->payload.privilege.new_uid = 0;
    e->payload.privilege.capability = 0;
    e->payload.privilege.mode_flags = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_chmod (SUID/SGID detection) ─────────────── */

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    /* Only care if SUID/SGID bits are being set */
    __u32 mode = (__u32)ctx->args[1];
    if (!(mode & 04000) && !(mode & 02000))  /* No S_ISUID or S_ISGID */
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_chmod = 90 on x86_64 */
    fill_event_header(e, SCARLET_CAT_PRIVILEGE, SCARLET_EVT_CHMOD, 90);

    const char *pathname = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->payload.file.path,
                             sizeof(e->payload.file.path),
                             pathname);

    e->payload.privilege.mode_flags = mode;
    e->payload.privilege.old_uid = e->uid;
    e->payload.privilege.new_uid = 0;
    e->payload.privilege.capability = 0;

    /* For chmod events, we repurpose the file path in the privilege union.
       Note: the privilege union doesn't have a path field, so we store
       mode_flags and let userspace read the pathname from ctx if needed.
       For CO-RE, we store the chmod-specific mode in mode_flags. */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sys_enter_fchmodat (SUID/SGID detection) ──────────── */

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    __u32 mode = (__u32)ctx->args[2];
    if (!(mode & 04000) && !(mode & 02000))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_fchmodat = 268 on x86_64 */
    fill_event_header(e, SCARLET_CAT_PRIVILEGE, SCARLET_EVT_CHMOD, 268);

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->payload.file.path,
                             sizeof(e->payload.file.path),
                             pathname);

    e->payload.privilege.mode_flags = mode;
    e->payload.privilege.old_uid = e->uid;
    e->payload.privilege.new_uid = 0;
    e->payload.privilege.capability = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}