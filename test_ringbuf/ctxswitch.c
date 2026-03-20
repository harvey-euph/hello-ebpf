#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>

static volatile int running = 1;

struct event {
    char prev[16];
    char next[16];
};

static void handle_sig(int sig)
{
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;
    printf("switch: %s -> %s\n", e->prev, e->next);
    return 0;
}

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *rb = NULL;
    int map_fd;

    signal(SIGINT, handle_sig);

    obj = bpf_object__open_file("ctxswitch.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "open failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_switch");
    if (!prog) {
        fprintf(stderr, "prog not found\n");
        return 1;
    }

    link = bpf_program__attach_tracepoint(prog, "sched", "sched_switch");
    if (!link) {
        fprintf(stderr, "attach failed\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
    	return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
    	return 1;
    }

    printf("Running (ringbuf)... Press Ctrl+C\n");

    while (running) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
