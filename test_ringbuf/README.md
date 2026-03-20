# Enviroment

Ubuntu 24.04.4 LTS
Linux 6.17.0-1009-gcp

```sh
sudo apt install -y \
    clang llvm libbpf-dev libelf-dev \
    gcc make linux-tools-common linux-tools-generic
```

# Build

```sh
make
```

# Execution
```sh
sudo ./ctxswitch
```

# Observation

```sh
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

