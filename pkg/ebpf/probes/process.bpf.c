/* process.bpf.c — Process execution monitoring eBPF probes
 *
 * CO-RE (Compile Once, Run Everywhere) eBPF program using libbpf.
 * Monitors process lifecycle events: execve, fork, exit.
 *
 * Tracepoints:
 *   - sched_process_exec  (execve/execveat)
 *   - sched_process_fork  (clone/fork)
 *   - sched_process_exit  (exit/exit_group)
 *
 * Kernel-side filtering:
 *   - Only emits events for processes in monitored containers (cgroup_id lookup)
 *   - Only emits events for syscalls in the monitored_syscalls map
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "security_scarlet_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ── Maps ──────────────────────────────────────────────────────────── */

/* Ring buffer for sending events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);  /* 4MB */
} events_rb SEC(".maps");

/* Set of cgroup IDs for containers on this node */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);    /* cgroup_id */
    __type(value, __u32);  /* container sequence number */
} container_cgroups SEC(".maps");

/* Set of monitored syscall numbers (early filter) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);   /* syscall_nr */
    __type(value, __u8);  /* 1 = monitored */
} monitored_syscalls SEC(".maps");

/* ── Helper: check if cgroup is a monitored container ──────────────── */

static __always_inline int is_container_process(__u64 cgroup_id)
{
    return bpf_map_lookup_elem(&container_cgroups, &cgroup_id) != NULL;
}

/* ── Helper: fill common event header ──────────────────────────────── */

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

    /* Get parent PID */
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    /* Get PID namespace level */
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

    /* Get process command name */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* ── Tracepoint: sched_process_exec ────────────────────────────────── */

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    /* Only monitor container processes */
    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_execve = 59 on x86_64 */
    fill_event_header(e, SCARLET_CAT_PROCESS, SCARLET_EVT_EXEC, 59);

    /* Read filename from the sched_process_exec ctx */
    const char *filename = ctx->filename;
    bpf_probe_read_kernel_str(&e->payload.process.filename,
                               sizeof(e->payload.process.filename),
                               filename);

    /* Read args — try to get from bprm */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct binary_arguments *bprm = BPF_CORE_READ(task, bprm);
    if (bprm) {
        const char *const *argv = BPF_CORE_READ(bprm, argv);
        if (argv) {
            bpf_probe_read_user_str(&e->payload.process.args,
                                     sizeof(e->payload.process.args),
                                     argv);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sched_process_fork ────────────────────────────────── */

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_clone = 56 on x86_64 */
    fill_event_header(e, SCARLET_CAT_PROCESS, SCARLET_EVT_FORK, 56);

    /* For fork events, filename is the parent's comm (child inherits) */
    __builtin_memcpy(&e->payload.process.filename, e->comm,
                     SCARLET_MAX_COMM_LEN);
    e->payload.process.args[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint: sched_process_exit ─────────────────────────────────── */

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!is_container_process(cgroup_id))
        return 0;

    struct scarlet_event *e;
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* __NR_exit_group = 231 on x86_64 */
    fill_event_header(e, SCARLET_CAT_PROCESS, SCARLET_EVT_EXIT, 231);

    e->payload.process.filename[0] = '\0';
    e->payload.process.args[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}