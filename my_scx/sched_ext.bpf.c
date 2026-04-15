#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <scx/common.bpf.h>

char LICENSE[] SEC("license") = "GPL";

// FIFO queue
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 1024);
    __type(value, u32);
} queue SEC(".maps");

// ✅ struct_ops enqueue
BPF_STRUCT_OPS(enqueue, struct task_struct *p, u64 enq_flags)
{
    u32 pid = p->pid;
    bpf_map_push_elem(&queue, &pid, 0);
}

// ✅ struct_ops dispatch
BPF_STRUCT_OPS(dispatch, s32 cpu, struct task_struct *prev)
{
    u32 pid;

    if (bpf_map_pop_elem(&queue, &pid) == 0) {
        struct task_struct *p = bpf_task_from_pid(pid);
        if (p) {
            scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, 0, 0);
        }
    }
}

// ✅ scheduler 註冊
SEC(".struct_ops")
struct sched_ext_ops simple_ops = {
    .enqueue = (void *)enqueue,
    .dispatch = (void *)dispatch,
    .name = "minimal_scx",
};
