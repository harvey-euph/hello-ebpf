// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"           // 最重要的 header，解決大部分 struct fail
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// scx_bpf_ 系列 helper 來自 kernel/sched/ext.h，透過 vmlinux.h + bpf_helpers 可用
#define SHARED_DSQ 0

char _license[] SEC("license") = "GPL";

SEC("struct_ops")
void BPF_STRUCT_OPS(minimal_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    // 簡單：盡量留在原本 CPU
    bpf_scx_bpf_select_cpu(p, prev_cpu, wake_flags);
}

SEC("struct_ops")
void BPF_STRUCT_OPS(minimal_enqueue, struct task_struct *p, u64 enq_flags)
{
    // 全部丟到共享 DSQ (global FIFO)
    scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

SEC("struct_ops")
void BPF_STRUCT_OPS(minimal_dispatch, s32 cpu, struct task_struct *prev)
{
    // 從共享 DSQ 拿出來執行
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

SEC("struct_ops")
int BPF_STRUCT_OPS(minimal_init)
{
    // 可以加一些初始化，現在留空
    return 0;
}

SEC(".struct_ops.link")
struct sched_ext_ops minimal_ops = {
    .select_cpu = (void *)minimal_select_cpu,
    .enqueue    = (void *)minimal_enqueue,
    .dispatch   = (void *)minimal_dispatch,
    .init       = (void *)minimal_init,
    .name       = "minimal_scx",
    .flags      = SCX_OPS_ENQ_LAST,   // 簡單範例常用
};
