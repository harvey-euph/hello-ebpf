CLANG ?= clang
CC ?= gcc

CFLAGS = -O2 -g
BPF_CFLAGS = -O2 -g -target bpf

LIBS = -lbpf -lelf

TARGET ?= fork

BPF_SRC := $(TARGET).bpf.c
USER_SRC := $(TARGET).c

BPF_OBJ := $(TARGET).bpf.o
USER_BIN := $(TARGET)

VMLINUX = vmlinux.h

all: $(USER_BIN)

$(VMLINUX): /sys/kernel/btf/vmlinux
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) event.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): $(USER_SRC) $(BPF_OBJ) event.h
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@ $(LIBS)

clean:
	rm -f *.o $(USER_BIN) $(VMLINUX)

run: all
	sudo ./$(USER_BIN)
