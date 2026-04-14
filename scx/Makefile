CLANG ?= clang
BPFTOOL ?= bpftool

LINUX_SRC ?= ~/linux

CFLAGS = -O2 -g -Wall
BPF_CFLAGS = -target bpf -D__BPF_TRACING__ \
	-I$(LINUX_SRC)/tools/sched_ext/include \
	-I$(LINUX_SRC)/tools/lib \
	-I$(LINUX_SRC)/tools/include \
	-I$(LINUX_SRC)/tools/include/uapi

all: scx

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

scx.bpf.o: scx.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

scx.skel.h: scx.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

scx: scx.c scx.skel.h
	$(CLANG) $(CFLAGS) scx.c -lbpf -o scx

clean:
	rm -f *.o *.skel.h scx
