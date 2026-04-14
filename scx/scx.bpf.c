// scx.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <scx/common.bpf.h>

char LICENSE[] SEC("license") = "GPL";

/*
 * 最簡單：直接用 kernel default DSQ
 */

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    return prev_cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    scx_bpf_enqueue(p, SCX_DSQ_GLOBAL, enq_flags);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_dispatch(SCX_DSQ_GLOBAL, cpu);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
    // no-op
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
    // no-op
}

SEC(".struct_ops")
struct sched_ext_ops simple_ops = {
    .select_cpu = (void *)simple_select_cpu,
    .enqueue    = (void *)simple_enqueue,
    .dispatch   = (void *)simple_dispatch,
    .running    = (void *)simple_running,
    .stopping   = (void *)simple_stopping,
    .name       = "scx_simple",
};
