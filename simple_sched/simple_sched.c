/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace loader：載入 BPF skeleton，啟動排程器，等待 Ctrl+C
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>

/* libbpf 產生的 skeleton header（由 bpftool 自動生成） */
#include "simple_sched.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(void)
{
    struct simple_sched_bpf *skel;
    struct bpf_link *link;
    int err;

    /* 1. 開啟並載入 BPF 程式 */
    skel = simple_sched_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* 2. 啟動排程器（attach struct_ops） */
    link = bpf_map__attach_struct_ops(skel->maps.simple_ops);
    if (!link) {
        fprintf(stderr, "Failed to attach struct_ops\n");
        err = 1;
        goto cleanup;
    }

    printf("simple_sched running. Press Ctrl+C to stop.\n");

    /* 3. 註冊 Ctrl+C 處理 */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* 4. 等待直到使用者中斷 */
    while (!exiting)
        sleep(1);

    printf("Exiting...\n");
    bpf_link__destroy(link);
    err = 0;

cleanup:
    simple_sched_bpf__destroy(skel);
    return err;
}
