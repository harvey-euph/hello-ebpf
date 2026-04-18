#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_CPUS 256

#define DSQ_FAST_BASE  1000
#define DSQ_SLOW_BASE  2000

#define BPF_STRUCT_OPS(name, args...) \
    SEC("struct_ops/"#name) BPF_PROG(name, ##args) 

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
    SEC("struct_ops.s/"#name) BPF_PROG(name, ##args)
char _license[] SEC("license") = "GPL";

/* ===================== */
/* task state map */
/* ===================== */

struct task_ctx {
    u64 last_enq_ts;
    u32 wake_cnt;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, struct task_struct *);
    __type(value, struct task_ctx);
} task_ctx_map SEC(".maps");

/* ===================== */
/* helpers */
/* ===================== */

static __always_inline u32 fast_dsq(u32 cpu)
{
    return DSQ_FAST_BASE + cpu;
}

static __always_inline u32 slow_dsq(u32 cpu)
{
    return DSQ_SLOW_BASE + cpu;
}

/* ===================== */
/* init */
/* ===================== */

s32 BPF_STRUCT_OPS_SLEEPABLE(policy_init)
{
    u32 nr = scx_bpf_nr_cpu_ids();

    for (u32 i = 0; i < nr && i < MAX_CPUS; i++) {
        if (scx_bpf_create_dsq(fast_dsq(i), -1))
            return -1;
        if (scx_bpf_create_dsq(slow_dsq(i), -1))
            return -1;
    }
    return 0;
}

/* ===================== */
/* classification */
/* ===================== */

static __always_inline int is_interactive(struct task_struct *p)
{
    struct task_ctx *ctx;
    u64 now = bpf_ktime_get_ns();

    ctx = bpf_task_storage_get(&task_ctx_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ctx)
        return 0;

    u64 delta = now - ctx->last_enq_ts;

    ctx->last_enq_ts = now;
    ctx->wake_cnt++;

    /* heuristic：
     * frequent wakeup + short interval = interactive
     */
    if (delta < 5 * 1000 * 1000 && ctx->wake_cnt > 5)
        return 1;

    return 0;
}

/* ===================== */
/* select_cpu */
/* ===================== */

s32 BPF_STRUCT_OPS(policy_select_cpu,
    struct task_struct *p,
    s32 prev_cpu,
    u64 wake_flags)
{
    if (prev_cpu >= 0 &&
        scx_bpf_test_and_clear_cpu_idle(prev_cpu))
        return prev_cpu;

    bool idle;
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &idle);
}

/* ===================== */
/* enqueue */
/* ===================== */

int BPF_STRUCT_OPS(policy_enqueue,
    struct task_struct *p,
    u64 enq_flags)
{
    u32 target = scx_bpf_task_cpu(p);
    u32 curr   = bpf_get_smp_processor_id();

    int interactive = is_interactive(p);

    u32 dsq;

    if (interactive)
        dsq = fast_dsq(target);
    else
        dsq = slow_dsq(target);

    if (target == curr)
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
    else
        scx_bpf_dsq_insert(p, dsq, SCX_SLICE_DFL, enq_flags);

    return 0;
}

/* ===================== */
/* dispatch */
/* ===================== */

int BPF_STRUCT_OPS(policy_dispatch,
    s32 cpu,
    struct task_struct *prev)
{
    u32 nr = scx_bpf_nr_cpu_ids();

    /* 1. fast path（低 latency） */
    if (scx_bpf_dsq_move_to_local(fast_dsq(cpu)))
        return 0;

    /* 2. slow path */
    if (scx_bpf_dsq_move_to_local(slow_dsq(cpu)))
        return 0;

    /* 3. steal（先偷 fast） */
#pragma unroll
    for (int i = 1; i <= 4; i++) {
        u32 v = (cpu + i) % nr;

        if (scx_bpf_dsq_move_to_local(fast_dsq(v)))
            return 0;

        if (scx_bpf_dsq_move_to_local(slow_dsq(v)))
            return 0;
    }

    /* 4. global fallback */
    if (scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL))
        return 0;

    return 0;
}

/* ===================== */
/* exit */
/* ===================== */

void BPF_STRUCT_OPS(policy_exit,
    struct scx_exit_info *info)
{
    bpf_printk("policy exit reason=%d", info->reason);
}

/* ===================== */
/* ops */
/* ===================== */

SEC(".struct_ops.link")
struct sched_ext_ops policy_ops = {
    .select_cpu = (void *)policy_select_cpu,
    .enqueue    = (void *)policy_enqueue,
    .dispatch   = (void *)policy_dispatch,
    .init       = (void *)policy_init,
    .exit       = (void *)policy_exit,
    .name       = "policy_sched",
    .flags      = SCX_OPS_KEEP_BUILTIN_IDLE,
};
