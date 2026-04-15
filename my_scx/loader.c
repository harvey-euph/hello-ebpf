#include <stdio.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include "sched_ext.skel.h"

int main()
{
    struct sched_ext_bpf *skel;

    skel = sched_ext_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF\n");
        return 1;
    }

    if (sched_ext_bpf__attach(skel)) {
        fprintf(stderr, "failed to attach\n");
        return 1;
    }

    printf("SCX scheduler loaded\n");

    while (1)
        sleep(1);

    sched_ext_bpf__destroy(skel);
    return 0;
}
