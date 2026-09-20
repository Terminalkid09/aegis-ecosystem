#!/bin/bash
# Build dentro container Debian: installa toolchain e compila sensore + collector.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq clang llvm make gcc libbpf-dev libelf-dev zlib1g-dev linux-headers-amd64 bpftool > /dev/null
echo "[build] toolchain pronta: $(clang --version | head -1)"
# vmlinux.h generato dal BTF del kernel target (mai committato, 3MB+)
if [ -f /sys/kernel/btf/vmlinux ]; then
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > /src/vmlinux.h
  echo "[build] vmlinux.h generato: $(wc -l < /src/vmlinux.h) righe"
else
  echo "[build] ERRORE: /sys/kernel/btf/vmlinux assente (serve --privileged + kernel BTF)" >&2
  exit 1
fi
cd /src
make clean || true
make
echo "[build] OK:"; ls -la /src/aegis_exec.bpf.o /src/aegis-collector
