#!/bin/bash
# One-shot CI: toolchain + build + bench + test funzionale + pulizia generati.
# Uso: docker run --rm --privileged -v $PWD:/src debian:bookworm-slim bash /src/ci.sh [N]
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq clang llvm make gcc libbpf-dev libelf-dev zlib1g-dev linux-headers-amd64 bpftool libbpf1 time
bash /src/build-in-docker.sh
bash /src/bench.sh "${1:-300}"
RC_BENCH=$?
bash /src/test-ebpf.sh
RC_TEST=$?
rm -f /src/aegis_exec.bpf.o /src/aegis-collector /src/vmlinux.h
if [ "$RC_BENCH" -ne 0 ] || [ "$RC_TEST" -ne 0 ]; then exit 1; fi
exit 0
