// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 正確定義 macro（這是目前 kernel 6.12+ / 6.17 標準寫法）
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
	bool is_idle = false;
	s32 cpu;

	// 使用 kernel 預設 idle CPU 選擇邏輯（最安全）
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	// 如果找到 idle CPU，可以直接 dispatch 到 local DSQ（可選）
	// if (is_idle)
	//     scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

	return cpu;
}

void BPF_STRUCT_OPS(minimal_enqueue, struct task_struct *p, u64 enq_flags)
{
	// 把任務放入共享全局 DSQ（簡單 FIFO）
	scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(minimal_dispatch, s32 cpu, struct task_struct *prev)
{
	// 從共享 DSQ 拿任務出來執行
	scx_bpf_consume(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(minimal_init)
{
	// 建立共享 DSQ，讓所有 CPU (-1) 都可以存取
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
