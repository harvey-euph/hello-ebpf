// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ==================== 重要：定義新版 BPF_STRUCT_OPS 宏 ====================
#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name) \
	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name) \
	BPF_PROG(name, ##args)

// ==================== 共享 DSQ ====================
#define SHARED_DSQ 0

char _license[] SEC("license") = "GPL";

BPF_STRUCT_OPS(minimal_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	// 使用 kernel 內建的預設 idle CPU 選擇（最安全、最簡單）
	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, NULL);
	return cpu;
}

BPF_STRUCT_OPS(minimal_enqueue, struct task_struct *p, u64 enq_flags)
{
	// 把任務丟到全局共享 DSQ（簡單 FIFO）
	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

BPF_STRUCT_OPS(minimal_dispatch, s32 cpu, struct task_struct *prev)
{
	// 從共享 DSQ 拿出任務到本地執行
	scx_bpf_consume(SHARED_DSQ);
}

BPF_STRUCT_OPS_SLEEPABLE(minimal_init)
{
	// 建立共享 DSQ（-1 表示所有 CPU 都可使用）
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
