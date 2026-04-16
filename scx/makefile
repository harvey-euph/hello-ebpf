CLANG ?= clang
BPF_CFLAGS := -target bpf -g -O2

BPF_SRCS := $(wildcard *.bpf.c)
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

VMLINUX := vmlinux.h

all: $(VMLINUX) $(BPF_OBJS)

$(VMLINUX):
	@echo "[BTF] Generating vmlinux.h"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

%.bpf.o: %.bpf.c $(VMLINUX)
	@echo "[BPF] Compiling $< → $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@ -I.

clean:
	rm -f *.bpf.o

distclean: clean
	rm -f $(VMLINUX)

list:
	@echo "Available schedulers:"
	@ls -1 *.bpf.c

# ===== Register scheduler =====
# 用法: make load FILE=sched_ext.bpf.c
load: all
ifndef FILE
	$(error Please specify FILE=xxx.bpf.c)
endif
	@echo "[LOAD] Loading $(FILE)"
	sudo ./stop.sh || true
	sudo bpftool struct_ops register $(FILE:.c=.o) /sys/fs/bpf/sched_ext
	cat /sys/kernel/sched_ext/root/ops

unload:
	sudo ./stop.sh
