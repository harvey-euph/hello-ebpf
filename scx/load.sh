OPS=$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || echo "")

if [ -n "$OPS" ]; then
    echo "[INFO] scheduler original running: $OPS, stopping..."
    sudo ./stop.sh
fi

sudo bpftool struct_ops register $1 /sys/fs/bpf/sched_ext
