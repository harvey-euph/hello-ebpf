#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <string.h>

static volatile int running = 1;

struct event {
    unsigned int pid;
    unsigned int syscall_id;
    unsigned long long arg0;
    unsigned long long arg1;
    char comm[16];
};

static void handle_sig(int sig) {
    running = 0;
    exit(0);
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;

    printf("PID=%u COMM=%s SYSCALL_ID=%u ARG0=0x%llx ARG1=0x%llx\n",
        e->pid,
        e->comm,
        e->syscall_id,
        e->arg0,
        e->arg1
    );

    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *rb;
    int map_fd;

    signal(SIGINT, handle_sig);

    obj = bpf_object__open_file("ctxsyscall.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "trace_sys_enter");
    link = bpf_program__attach_tracepoint(prog, "raw_syscalls", "sys_enter");
    if (!link) {
        fprintf(stderr, "Failed to attach tracepoint\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Tracing syscalls... Ctrl-C to exit.\n");

    while (running) {
        ring_buffer__poll(rb, 100 /* ms */);
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
