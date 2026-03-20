#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// tracepoint: sched:sched_switch
SEC("tracepoint/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
    char prev[TASK_COMM_LEN];
    char next[TASK_COMM_LEN];

    __builtin_memcpy(prev, ctx->prev_comm, TASK_COMM_LEN);
    __builtin_memcpy(next, ctx->next_comm, TASK_COMM_LEN);

    bpf_printk("switch: %s -> %s\n", prev, next);

    return 0;
}
