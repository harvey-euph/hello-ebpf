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
    
    bpf_probe_read_kernel(prev, sizeof(prev), ctx->prev_comm);
    bpf_probe_read_kernel(next, sizeof(next), ctx->next_comm);

    bpf_printk("switch: %s -> %s\n", prev, next);

    return 0;
}
