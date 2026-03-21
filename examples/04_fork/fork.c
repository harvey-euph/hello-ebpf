#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "event.h"

static volatile sig_atomic_t running = 1;

static void handle_sig(int sig)
{
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;

    printf("PARENT[%u:%s] -> CHILD[%u:%s]\n",
           e->parent_pid, e->parent_comm,
           e->child_pid,  e->child_comm);

    return 0;
}

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_sig);

    obj = bpf_object__open_file("fork.bpf.o", NULL);
    if (!obj) {
        printf("open failed\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        printf("load failed\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_fork");
    if (!prog) {
        printf("prog not found\n");
        return 1;
    }

    link = bpf_program__attach_tracepoint(prog, "sched", "sched_process_fork");
    if (!link) {
        printf("attach failed\n");
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);

    if (!rb) {
        printf("ringbuf failed\n");
        return 1;
    }

    printf("Running... Ctrl+C to stop\n");

    while (running) {
        err = ring_buffer__poll(rb, 50);
        if (err == -EINTR)
            break;
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
