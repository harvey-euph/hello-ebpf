#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

char LICENSE[] SEC("license") = "GPL";

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event {
    u32 pid;
    u32 syscall_id;
    u64 arg0;
    u64 arg1;
    char comm[TASK_COMM_LEN];
};

// tracepoint: sys_enter
SEC("tracepoint/syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    e->pid = pid;
    e->syscall_id = ctx->id;

    // 取前兩個 syscall 參數
    e->arg0 = ctx->args[0];
    e->arg1 = ctx->args[1];

    // task comm
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
