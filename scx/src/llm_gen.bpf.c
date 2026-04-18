#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define CPU_DSQ_OFFSET 100
#define MAX_CPUS 512

#define BPF_STRUCT_OPS(name, args...)	\
    SEC("struct_ops/"#name)	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...)	\
    SEC("struct_ops.s/"#name)				    \
    BPF_PROG(name, ##args)

// 初始化：加 Log 確認 DSQ 是否創建成功
s32 BPF_STRUCT_OPS_SLEEPABLE(study_init) {
    u32 nr_cpus = scx_bpf_nr_cpu_ids();
    bpf_printk("SCX Init: Starting to create %u DSQs", nr_cpus);

    for (int i = 0; i < nr_cpus && i < MAX_CPUS; i++) {
        s32 ret = scx_bpf_create_dsq(CPU_DSQ_OFFSET + i, -1);
        if (ret) {
            bpf_printk("SCX Init Error: Failed to create DSQ %d", i);
            return ret;
        }
    }
    bpf_printk("SCX Init: Success");
    return 0;
}

// 導航階段：Log 出決策過程
s32 BPF_STRUCT_OPS(study_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
    bool is_idle;
    
    if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
        // bpf_printk("Select: Task %s back to prev_cpu %d (Idle)", p->comm, prev_cpu);
        return prev_cpu;
    }
    
    s32 target = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    // bpf_printk("Select: Task %s -> target %d", p->comm, target);
    return target;
}

// 入庫階段：Log 任務被丟進哪個倉庫
int BPF_STRUCT_OPS(study_enqueue, struct task_struct *p, u64 enq_flags) {
    // 獲取該任務被分配到的目標 CPU (不是當前執行 enqueue 的 CPU)
    u32 target_cpu = scx_bpf_task_cpu(p);
    u32 dsq_id = CPU_DSQ_OFFSET + target_cpu;

    if (enq_flags & SCX_ENQ_WAKEUP) {
        bpf_printk("Enqueue: %s (Wakeup) -> Local CPU %d", p->comm, target_cpu);
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
    } else {
        bpf_printk("Enqueue: %s -> User DSQ %u", p->comm, dsq_id);
        scx_bpf_dsq_insert(p, dsq_id, SCX_SLICE_DFL, enq_flags);
    }
    return 0;
}

// 提貨階段：這是最需要 Log 的地方
int BPF_STRUCT_OPS(study_dispatch, s32 cpu, struct task_struct *prev) {
    u32 dsq_id = CPU_DSQ_OFFSET + cpu;

    // 1. 試著從自己的倉庫拿
    if (scx_bpf_dsq_move_to_local(dsq_id)) {
        bpf_printk("Dispatch: CPU %d consumed from own DSQ %u", cpu, dsq_id);
        return 0;
    }

    // 2. 試著偷別人的
    u32 neighbor_cpu = (cpu + 1) % scx_bpf_nr_cpu_ids();
    if (scx_bpf_dsq_move_to_local(CPU_DSQ_OFFSET + neighbor_cpu)) {
        bpf_printk("Dispatch: CPU %d STOLE from CPU %d", cpu, neighbor_cpu);
        return 0;
    }

    // 3. 全局保底
    if (scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL)) {
        bpf_printk("Dispatch: CPU %d picked from Global", cpu);
        return 0;
    }
    
    return 0;
}

void BPF_STRUCT_OPS(study_running, struct task_struct *p) {
    // 這裡頻率太高，平時建議註解掉，只在抓不到任務跑時開啟
    // bpf_printk("Running: %s on CPU %d", p->comm, bpf_get_smp_processor_id());
}

SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {
    .select_cpu = (void *)study_select_cpu,
    .enqueue    = (void *)study_enqueue,
    .dispatch   = (void *)study_dispatch,
    .running    = (void *)study_running,
    .init       = (void *)study_init,
    .name       = "study_advanced_scheduler",
    .flags      = SCX_OPS_KEEP_BUILTIN_IDLE, 
};

char _license[] SEC("license") = "GPL";
