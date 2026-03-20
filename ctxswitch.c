#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level,
                          const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;

    libbpf_set_print(libbpf_print_fn);

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

    printf("Running... Press Ctrl+C\n");

    while (1) {
        sleep(1);
    }

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
