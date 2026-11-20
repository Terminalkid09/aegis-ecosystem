#!/bin/bash
# Build inside a Debian container: install the toolchain and compile sensor + collector.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq clang llvm make gcc libbpf-dev libelf-dev zlib1g-dev linux-headers-amd64 bpftool > /dev/null
echo "[build] toolchain ready: $(clang --version | head -1)"
# vmlinux.h generated from the target kernel BTF (never committed, 3MB+)
if [ -f /sys/kernel/btf/vmlinux ]; then
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > /src/vmlinux.h
  echo "[build] generated vmlinux.h: $(wc -l < /src/vmlinux.h) lines"
else
  echo "[build] ERROR: /sys/kernel/btf/vmlinux missing (requires --privileged + kernel BTF)" >&2
  exit 1
fi
cd /src
make clean || true
make
echo "[build] OK:"; ls -la /src/aegis_exec.bpf.o /src/aegis-collector
