# ===================================================
# simple_sched Makefile
# 需求：clang, llvm, libbpf-dev, bpftool, linux headers
# ===================================================

CLANG       ?= clang
BPFTOOL     ?= bpftool
CC          ?= gcc

# 你的 kernel source / vmlinux BTF 路徑
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

INCLUDES    := -I/usr/include/bpf \
               -I/usr/local/include

BPF_CFLAGS  := -g -O2 -target bpf \
                -D__TARGET_ARCH_x86 \
                $(INCLUDES)

CFLAGS      := -g -O2 -Wall $(INCLUDES)
LDFLAGS     := -lbpf -lz -lelf

TARGET      := simple_sched
BPF_OBJ     := $(TARGET).bpf.o
SKEL_H      := $(TARGET).skel.h

.PHONY: all clean

all: $(TARGET)

# Step 1: 用 clang 把 .bpf.c 編譯成 BPF object
$(BPF_OBJ): $(TARGET).bpf.c $(TARGET).h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Step 2: 用 bpftool 產生 skeleton header
$(SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Step 3: 編譯 userspace loader（依賴 skeleton）
$(TARGET): $(TARGET).c $(SKEL_H)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(TARGET)
