// sched_ext.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ⚠️ 這個是關鍵
#include <scx/common.bpf.h>

char LICENSE[] SEC("license") = "GPL";

// 簡單 FIFO queue (用 BPF queue map)
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 1024);
    __type(value, u32); // pid
} queue SEC(".maps");

// enqueue task
SEC("sched_ext")
int BPF_PROG(enqueue, struct task_struct *p, u64 enq_flags)
{
    u32 pid = p->pid;

    bpf_map_push_elem(&queue, &pid, 0);
    return 0;
}

// dispatch task to CPU
SEC("sched_ext")
int BPF_PROG(dispatch, s32 cpu, struct task_struct *prev)
{
    u32 pid;

    if (bpf_map_pop_elem(&queue, &pid) == 0) {
        struct task_struct *p = bpf_task_from_pid(pid);
        if (p) {
            scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, 0);
        }
    }

    return 0;
}
