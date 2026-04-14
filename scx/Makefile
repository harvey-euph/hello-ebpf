CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

CFLAGS = -O2 -g -Wall
BPF_CFLAGS = -target bpf -D__BPF_TRACING__

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
