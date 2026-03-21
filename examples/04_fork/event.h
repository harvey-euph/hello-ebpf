#ifndef __EVENT_H
#define __EVENT_H

#define TASK_COMM_LEN 16

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <stdint.h>
typedef uint32_t __u32;
#endif

struct event {
    __u32 parent_pid;
    __u32 child_pid;
    char parent_comm[TASK_COMM_LEN];
    char child_comm[TASK_COMM_LEN];
};

#endif
