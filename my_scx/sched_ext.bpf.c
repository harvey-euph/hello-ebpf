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

s32 BPF_STRUCT_OPS(minimal_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return prev_cpu;                  // 最簡單寫法，避免任何 scx_*_dfl helper
}

void BPF_STRUCT_OPS(minimal_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(minimal_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);   // 這是你 kernel 已確認存在的 helper
}

s32 BPF_STRUCT_OPS_SLEEPABLE(minimal_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

SEC(".struct_ops.link")
struct sched_ext_ops minimal_ops = {
	.select_cpu = (void *)minimal_select_cpu,
	.enqueue    = (void *)minimal_enqueue,
	.dispatch   = (void *)minimal_dispatch,
	.init       = (void *)minimal_init,

	.name       = "minimal_scx",
	.flags      = SCX_OPS_ENQ_LAST,        // 拿掉 SCX_OPS_KEEP_BUILTIN_IDLE，避免 BTF 問題
};
