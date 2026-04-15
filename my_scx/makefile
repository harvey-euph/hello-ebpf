# ========================
# SCX CLEAN BUILD SYSTEM
# ========================

KDIR := /home/andy16384/linux

LIBBPF := $(KDIR)/tools/lib
BPFOOL := $(KDIR)/tools/bpf/bpftool/bpftool

CLANG ?= clang
CC ?= gcc

BPF_CFLAGS := -O2 -g -target bpf

INCLUDES := \
	-I./ \
	-I$(LIBBPF) \
	-I$(KDIR)/tools/include \
	-I$(KDIR)/tools/include/uapi \
	-I$(KDIR)/tools/sched_ext/include

LDFLAGS := \
	$(LIBBPF)/libbpf.a \
	-lelf -lz

# ------------------------
# default
# ------------------------
all: loader

# ------------------------
# vmlinux.h (BTF)
# ------------------------
vmlinux.h:
	$(BPFOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# ------------------------
# BPF object
# ------------------------
sched_ext.bpf.o: sched_ext.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

# ------------------------
# skeleton (IMPORTANT: same bpftool)
# ------------------------
sched_ext.skel.h: sched_ext.bpf.o
	$(BPFOOL) gen skeleton $< > $@

# ------------------------
# userspace loader
# ------------------------
loader: loader.c sched_ext.skel.h
	gcc loader.c \
    -I$(KDIR)/tools/lib \
    -I$(KDIR)/tools/include \
    -I$(KDIR)/tools/include/uapi \
    -o loader \
    $(LIBBPF)/libbpf.a \
    -lelf -lz

clean:
	rm -f *.o *.skel.h loader vmlinux.h
