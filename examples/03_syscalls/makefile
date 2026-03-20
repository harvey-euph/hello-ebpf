BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf

all: ctxsyscall ctxsyscall.bpf.o

ctxsyscall.bpf.o: ctxsyscall.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

ctxsyscall: ctxsyscall.c
	cc -O2 -g $< -o $@ -lbpf -lelf

clean:
    rm -f ctxsyscall ctxsyscall.bpf.o
