#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <scx/common.bpf.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 1024);
    __type(value, u32);
} queue SEC(".maps");

SEC("struct_ops/enqueue")
void enqueue(struct task_struct *p, u64 enq_flags)
{
    if (!p)
        return;

    scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, 0, 0);
}

SEC("struct_ops/dispatch")
void dispatch(s32 cpu, struct task_struct *prev)
{
    /* nothing needed for simple global DSQ */
}

// struct_ops registration
SEC(".struct_ops")
struct sched_ext_ops simple_ops = {
    .enqueue = enqueue,
    .dispatch = dispatch,
    .name = "minimal_scx",
};
