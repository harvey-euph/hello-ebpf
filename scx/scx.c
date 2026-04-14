// scx.c
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "scx.skel.h"

int main(void)
{
    struct scx_bpf *skel;

    skel = scx_bpf__open_and_load();
    if (!skel) {
        printf("Failed to open/load BPF\n");
        return 1;
    }

    if (scx_bpf__attach(skel)) {
        printf("Failed to attach\n");
        return 1;
    }

    printf("sched_ext running...\n");
    printf("Press Ctrl+C to exit\n");

    while (1) sleep(1);

    scx_bpf__destroy(skel);
    return 0;
}
