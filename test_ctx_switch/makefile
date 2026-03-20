CLANG ?= clang
CC ?= gcc

CFLAGS = -O2 -g
BPF_CFLAGS = -O2 -g -target bpf

LIBS = -lbpf -lelf

BPF_OBJ = ctxswitch.bpf.o
VMLINUX = vmlinux.h

all: ctxswitch

$(VMLINUX): /sys/kernel/btf/vmlinux
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(BPF_OBJ): ctxswitch.bpf.c $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ctxswitch: ctxswitch.c $(BPF_OBJ)
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f *.o ctxswitch $(VMLINUX)

