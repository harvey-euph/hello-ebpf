#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    char prev[TASK_COMM_LEN];
    char next[TASK_COMM_LEN];
};

struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) 
        return 0;

    bpf_probe_read_kernel(e->prev, sizeof(e->prev), ctx->prev_comm);
    bpf_probe_read_kernel(e->next, sizeof(e->next), ctx->next_comm);

    bpf_ringbuf_submit(e, 0);

    return 0;
}
