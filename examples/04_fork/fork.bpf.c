#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "event.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->parent_pid = ctx->parent_pid;
    e->child_pid  = ctx->child_pid;

    /* 直接從 tracepoint 拿 comm（最穩） */
    __builtin_memcpy(e->parent_comm, ctx->parent_comm, TASK_COMM_LEN);
    __builtin_memcpy(e->child_comm,  ctx->child_comm,  TASK_COMM_LEN);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
