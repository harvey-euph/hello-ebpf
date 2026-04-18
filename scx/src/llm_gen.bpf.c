#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_CPUS 256
#define CPU_DSQ_BASE 1000

char _license[] SEC("license") = "GPL";

/* ===================== */
/* helpers */
/* ===================== */

static __always_inline u32 get_cpu_dsq(u32 cpu)
{
    return CPU_DSQ_BASE + cpu;
}

/* ===================== */
/* init */
/* ===================== */

s32 BPF_STRUCT_OPS_SLEEPABLE(adv_init)
{
    u32 nr = scx_bpf_nr_cpu_ids();

    bpf_printk("SCX adv_init: nr_cpu=%u", nr);

    for (u32 i = 0; i < nr && i < MAX_CPUS; i++) {
        if (scx_bpf_create_dsq(get_cpu_dsq(i), -1)) {
            bpf_printk("DSQ create failed cpu=%u", i);
            return -1;
        }
    }

    return 0;
}

/* ===================== */
/* select_cpu */
/* ===================== */

s32 BPF_STRUCT_OPS(adv_select_cpu,
    struct task_struct *p,
    s32 prev_cpu,
    u64 wake_flags)
{
    bool idle = false;

    /* 強 affinity：如果 prev_cpu idle 就回去 */
    if (prev_cpu >= 0 &&
        scx_bpf_test_and_clear_cpu_idle(prev_cpu))
        return prev_cpu;

    /* fallback default policy */
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &idle);
}

/* ===================== */
/* enqueue */
/* ===================== */

int BPF_STRUCT_OPS(adv_enqueue,
    struct task_struct *p,
    u64 enq_flags)
{
    u32 target = scx_bpf_task_cpu(p);
    u32 curr   = bpf_get_smp_processor_id();

    /* 🔥 保護 kernel thread */
    if (p->flags & PF_KTHREAD) {
        scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
        return 0;
    }

    /* 🔥 正確使用 LOCAL（只有同 CPU 才能用） */
    if (target == curr) {
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
    } else {
        scx_bpf_dsq_insert(p, get_cpu_dsq(target),
                           SCX_SLICE_DFL, enq_flags);
    }

    return 0;
}

/* ===================== */
/* dispatch */
/* ===================== */

int BPF_STRUCT_OPS(adv_dispatch,
    s32 cpu,
    struct task_struct *prev)
{
    u32 nr = scx_bpf_nr_cpu_ids();
    u32 my_dsq = get_cpu_dsq(cpu);

    /* 1️⃣ 自己的 queue（affinity） */
    if (scx_bpf_dsq_move_to_local(my_dsq))
        return 0;

    /* 2️⃣ bounded work stealing（比你原本強） */
#pragma unroll
    for (int i = 1; i <= 4; i++) {
        u32 victim = (cpu + i) % nr;

        if (scx_bpf_dsq_move_to_local(get_cpu_dsq(victim))) {
            bpf_printk("CPU %d stole from %d", cpu, victim);
            return 0;
        }
    }

    /* 3️⃣ global fallback（避免 starvation） */
    if (scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL))
        return 0;

    return 0;
}

/* ===================== */
/* running */
/* ===================== */

void BPF_STRUCT_OPS(adv_running,
    struct task_struct *p)
{
    /* debug 用（平常關掉） */
    // bpf_printk("Running %s on cpu %d",
    //            p->comm, bpf_get_smp_processor_id());
}

/* ===================== */
/* exit */
/* ===================== */

void BPF_STRUCT_OPS(adv_exit,
    struct scx_exit_info *info)
{
    bpf_printk("SCX EXIT reason=%d", info->reason);
}

/* ===================== */
/* ops */
/* ===================== */

SEC(".struct_ops.link")
struct sched_ext_ops adv_ops = {
    .select_cpu = (void *)adv_select_cpu,
    .enqueue    = (void *)adv_enqueue,
    .dispatch   = (void *)adv_dispatch,
    .running    = (void *)adv_running,
    .init       = (void *)adv_init,
    .exit       = (void *)adv_exit,
    .name       = "adv_scx",
    .flags      = SCX_OPS_KEEP_BUILTIN_IDLE,
};
