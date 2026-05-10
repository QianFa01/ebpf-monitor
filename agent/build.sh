#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
BPF_DIR="${SCRIPT_DIR}/bpf"

echo "=== Building eBPF Monitor Agent ==="

for cmd in clang cmake make pkg-config; do
    if ! command -v $cmd &>/dev/null; then
        echo "ERROR: $cmd not found. Install: apt-get install $cmd"
        exit 1
    fi
done

if ! pkg-config --exists libbpf; then
    echo "ERROR: libbpf not found. Install: apt-get install libbpf-dev"
    exit 1
fi

if ! pkg-config --exists libcurl; then
    echo "ERROR: libcurl not found. Install: apt-get install libcurl4-openssl-dev"
    exit 1
fi

if command -v bpftool &>/dev/null; then
    echo "Generating vmlinux.h from kernel BTF..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${BPF_DIR}/vmlinux.h"
    echo "vmlinux.h generated successfully"
else
    echo "WARNING: bpftool not found, using existing vmlinux.h"
fi

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "Running cmake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

echo "Building..."
make -j$(nproc)

echo ""
echo "=== Build Complete ==="
echo "Agent binary: ${BUILD_DIR}/ebpf-monitor-agent"
echo "BPF objects:  ${BUILD_DIR}/bpf/*.bpf.o"
echo ""
echo "Usage: sudo ${BUILD_DIR}/ebpf-monitor-agent -s http://<server>:8000"
