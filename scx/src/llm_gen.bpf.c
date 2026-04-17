#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 使用 User DSQ ID，對應每個 CPU
// 我們預留一個範圍，例如 0 ~ 511 給 CPU 私有 DSQ
#define CPU_DSQ_OFFSET 100

// 靜態定義最大支援的 CPU 數量
#define MAX_CPUS 512

#define BPF_STRUCT_OPS(name, args...)	\
    SEC("struct_ops/"#name)	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...)	\
    SEC("struct_ops.s/"#name)				    \
    BPF_PROG(name, ##args)

// 用於追蹤每個 CPU 佇列長度的 Map (幫助做負載決策)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} cpu_queue_count SEC(".maps");

// 初始化：為每個 CPU 創建一個私有的 User DSQ
s32 BPF_STRUCT_OPS_SLEEPABLE(study_init) {
    // 這裡我們假設系統 CPU 不超過 MAX_CPUS
    for (int i = 0; i < MAX_CPUS; i++) {
        s32 ret = scx_bpf_create_dsq(CPU_DSQ_OFFSET + i, -1);
        if (ret) return ret;
    }
    return 0;
}

// 1. 導航階段：盡量選上次跑過的 CPU
s32 BPF_STRUCT_OPS(study_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
    bool is_idle; // 定義一個變數來接收閒置狀態
    
    if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
        return prev_cpu;
    }
    
    // 傳入第 4 個參數 &is_idle
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

// 2. 入庫階段：根據目標 CPU 狀態決定去向
int BPF_STRUCT_OPS(study_enqueue, struct task_struct *p, u64 enq_flags) {
    u32 cpu = bpf_get_smp_processor_id();
    u32 dsq_id = CPU_DSQ_OFFSET + cpu;

    if (enq_flags & SCX_ENQ_WAKEUP) {
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
    } else {
        scx_bpf_dsq_insert(p, dsq_id, SCX_SLICE_DFL, enq_flags);
    }
    return 0;
}

// 3. 提貨階段：當 Local DSQ 空了
int BPF_STRUCT_OPS(study_dispatch, s32 cpu, struct task_struct *prev) {
    u32 dsq_id = CPU_DSQ_OFFSET + cpu;

    // 1. 從自己的 User DSQ 搬貨到 Local DSQ
    // 如果成功搬運，回傳值會是 true (非零)
    if (scx_bpf_dsq_move_to_local(dsq_id)) {
        return 0;
    }

    // 2. 嘗試從鄰居 CPU 的 DSQ 偷貨
    u32 neighbor_cpu = (cpu + 1) % scx_bpf_nr_cpu_ids(); // 使用你 list 中的 scx_bpf_nr_cpu_ids() 更精準
    if (scx_bpf_dsq_move_to_local(CPU_DSQ_OFFSET + neighbor_cpu)) {
        return 0;
    }

    // 3. 從全局隊列搬貨
    scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL);
    
    return 0;
}
// 紀錄任務開始跑的瞬間
void BPF_STRUCT_OPS(study_running, struct task_struct *p) {
    // 可以在這裡紀錄時間戳，或是增加該 CPU 的計數器
}

SEC(".struct_ops.link")
struct sched_ext_ops study_ops = {
    .select_cpu = (void *)study_select_cpu,
    .enqueue    = (void *)study_enqueue,
    .dispatch   = (void *)study_dispatch,
    .running    = (void *)study_running,
    .init       = (void *)study_init,
    .name       = "study_advanced_scheduler",
    // 這裡我們不加 SCX_OPS_ENQ_LAST，讓我們能完全控制 enqueue 
    .flags      = SCX_OPS_KEEP_BUILTIN_IDLE, 
};

char _license[] SEC("license") = "GPL";
