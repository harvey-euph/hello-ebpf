// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name) \
	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name) \
	BPF_PROG(name, ##args)

#define SHARED_DSQ 0ULL

char _license[] SEC("license") = "GPL";

/* 最簡單的 select_cpu：盡量留在原本 CPU 上 */
s32 BPF_STRUCT_OPS(minimal_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return prev_cpu;        // 直接回傳 prev_cpu，最不會出 BTF 問題
}

void BPF_STRUCT_OPS(minimal_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* 把任務放入共享 DSQ（FIFO） */
	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(minimal_dispatch, s32 cpu, struct task_struct *prev)
{
	/* 從共享 DSQ 拿出任務執行 */
	scx_bpf_consume(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(minimal_init)
{
	/* 建立共享 DSQ */
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

SEC(".struct_ops.link")
struct sched_ext_ops minimal_ops = {
	.select_cpu = (void *)minimal_select_cpu,
	.enqueue    = (void *)minimal_enqueue,
	.dispatch   = (void *)minimal_dispatch,
	.init       = (void *)minimal_init,

	.name       = "minimal_scx",
	.flags      = SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE,   // 保留 built-in idle
};
