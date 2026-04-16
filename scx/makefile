CLANG ?= clang
BPF_CFLAGS := -target bpf -g -O2

SRC_DIR := src
BUILD_DIR := build

BPF_SRCS := $(wildcard $(SRC_DIR)/*.bpf.c)
BPF_OBJS := $(patsubst $(SRC_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SRCS))

VMLINUX := vmlinux.h

all: $(VMLINUX) $(BPF_OBJS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(VMLINUX):
	@echo "[BTF] Generating vmlinux.h"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(BUILD_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c $(VMLINUX) | $(BUILD_DIR)
	@echo "[BPF] Compiling $< → $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@ -I.

clean:
	rm -rf $(BUILD_DIR)

distclean: clean
	rm -f $(VMLINUX)

list:
	@echo "Available schedulers:"
	@ls -1 $(SRC_DIR)/*.bpf.c | xargs -n1 basename

# ===== Register scheduler =====
# 用法: make load FILE=sched_ext.bpf.c
load: all
ifndef FILE
	$(error Please specify FILE=xxx.bpf.c)
endif
	@echo "[LOAD] Loading $(FILE)"
	sudo rm /sys/fs/bpf/sched_ext/sched_ops || true
	sudo bpftool struct_ops register $(FILE:.c=.o) /sys/fs/bpf/sched_ext
	cat /sys/kernel/sched_ext/root/ops

unload:
	sudo rm /sys/fs/bpf/sched_ext/sched_ops
