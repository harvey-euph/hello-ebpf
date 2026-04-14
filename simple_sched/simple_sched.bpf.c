/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 最簡單的 sched_ext BPF 排程器 — FIFO 語意
 * 所有 task 丟進同一個 global DSQ，依序執行
 */
#include <scx/common.bpf.h>
#include "simple_sched.h"

/* 告訴 sched_ext framework 這個排程器的旗標 */
char _license[] SEC("license") = "GPL";

/* 全域 DSQ (Dispatch Queue) ID，自定義值 0 */
#define SHARED_DSQ 0

/* 整個系統共用的 weight sum，用於統計 (可選) */
static u64 nr_enqueued, nr_dispatched;

/*
 * ops.enqueue — 當一個 task 變成 runnable 時呼叫
 * 我們直接把它丟進 SHARED_DSQ，slice = 默認值
 */
void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    __sync_fetch_and_add(&nr_enqueued, 1);

    /*
     * scx_bpf_dispatch() 把 task 放入指定 DSQ
     * SCX_SLICE_DFL = 使用系統默認 time slice
     */
    scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

/*
 * ops.dispatch — 當某顆 CPU 需要下一個 task 時呼叫
 * 從 SHARED_DSQ consume 一個 task 給這顆 CPU 執行
 */
void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
    __sync_fetch_and_add(&nr_dispatched, 1);
    scx_bpf_consume(SHARED_DSQ);
}

/*
 * ops.init — 排程器啟動時初始化
 * 建立我們的 SHARED_DSQ
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
    /* scx_bpf_create_dsq(dsq_id, node)，node=-1 表示 NUMA-agnostic */
    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

/*
 * ops.exit — 排程器卸載時呼叫（印出統計）
 */
void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
    bpf_printk("simple_sched exit: enqueued=%llu dispatched=%llu\n",
               nr_enqueued, nr_dispatched);
}

/*
 * 向 sched_ext 框架註冊這個排程器的 ops 結構
 * 只需要實作你需要的 callback，其餘保持 NULL
 */
SEC(".struct_ops.link")
struct sched_ext_ops simple_ops = {
    .enqueue   = (void *)simple_enqueue,
    .dispatch  = (void *)simple_dispatch,
    .init      = (void *)simple_init,
    .exit      = (void *)simple_exit,
    .name      = "simple_sched",
};
