// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "minimal.skel.h"   // 之後 clang + bpftool 會產生

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct minimal_bpf *skel;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = minimal_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skeleton\n");
        return 1;
    }

    err = minimal_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    err = minimal_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach scheduler\n");
        goto cleanup;
    }

    printf("minimal_scx scheduler 已經啟動！按 Ctrl+C 停止。\n");
    printf("可以用 `cat /sys/kernel/debug/tracing/trace_pipe` 看 log\n");

    while (!exiting)
        pause();

cleanup:
    minimal_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
