CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS := -O2 -g -Wall
BPF_CFLAGS := -O2 -g -target bpf

KDIR := /home/$(USER)/linux

INCLUDES := \
	-I$(KDIR)/tools/lib/bpf \
	-I$(KDIR)/tools/include \
	-I$(KDIR)/tools/include/uapi \
	-I$(KDIR)/tools/sched_ext/include

all: loader

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

sched_ext.bpf.o: sched_ext.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

sched_ext.skel.h: sched_ext.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

loader: loader.c sched_ext.skel.h
	gcc $(CFLAGS) $< -lbpf -lelf -o $@

clean:
	rm -f *.o *.skel.h loader vmlinux.h
