KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)

CLANG ?= clang
BPFTOOL ?= bpftool
LIBBPF ?= -lbpf

all: vmlinux.h minimal.bpf.o minimal.skel.h loader

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

minimal.bpf.o: sched_ext.bpf.c vmlinux.h
	$(CLANG) -target bpf -g -O2 -Wall \
		-I. \
		-I$(KERNEL_HEADERS) \
		-I$(KERNEL_HEADERS)/tools/include \
		-I$(KERNEL_HEADERS)/tools/lib \
		-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/armv.*/arm/') \
		-c $< -o $@

minimal.skel.h: minimal.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

loader: loader.c minimal.skel.h
	gcc -Wall -O2 -g \
		-I. \
		-I$(KERNEL_HEADERS)/tools/lib \
		loader.c \
		$(LIBBPF) -lelf -lz \
		-o $@

clean:
	rm -f *.o *.skel.h vmlinux.h loader

.PHONY: all clean
