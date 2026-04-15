// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 正確的 BPF_STRUCT_OPS 定義（6.12+ 標準）
#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name) \
	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name) \
	BPF_PROG(name, ##args)

#define SHARED_DSQ 0ULL

char _license[] SEC("license") = "GPL";

s32 BPF_STRUCT_OPS(minimal_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	// 最簡單且最安全的寫法：留在原本 CPU（避免呼叫 scx_bpf_select_cpu_dfl 導致 BTF 問題）
	return prev_cpu;
}

void BPF_STRUCT_OPS(minimal_enqueue, struct task_struct *p, u64 enq_flags)
{
	// 6.17 推薦寫法：使用 scx_bpf_dsq_insert
	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(minimal_dispatch, s32 cpu, struct task_struct *prev)
{
	// 6.17 已把 scx_bpf_consume 改名為 scx_bpf_dsq_move_to_local
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(minimal_init)
{
	// 建立共享 DSQ（所有 CPU 可用）
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

SEC(".struct_ops.link")
struct sched_ext_ops minimal_ops = {
	.select_cpu = (void *)minimal_select_cpu,
	.enqueue    = (void *)minimal_enqueue,
	.dispatch   = (void *)minimal_dispatch,
	.init       = (void *)minimal_init,

	.name       = "minimal_scx",
	.flags      = SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE,
};
