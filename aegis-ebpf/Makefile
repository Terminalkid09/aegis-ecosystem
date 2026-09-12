# Aegis eBPF sensor — build dentro container Debian (kernel BTF dal host).
#
#   docker build -t aegis-ebpf-builder -f Dockerfile.builder .
#   docker run --rm -v %cd%:/src aegis-ebpf-builder make -C /src
# Oppure tutto in un colpo (serve rete per apt):
#   docker run --rm -v %cd%:/src debian:bookworm-slim bash /src/build-in-docker.sh
#
# Test con privilegi (kernel >= 5.8, BTF in /sys/kernel/btf/vmlinux):
#   docker run --rm --privileged -v %cd%:/src debian:bookworm-slim \
#     bash -c 'apt-get update -qq && apt-get install -y -qq libbpf1 >/dev/null && /src/aegis-collector --obj /src/aegis_exec.bpf.o & sleep 1; for i in 1 2 3; do /bin/echo probe-$i; sleep 0.2; done; sleep 1; kill %1'

CC_BPF ?= clang
# -I multiarch: clang -target bpf non cerca /usr/include/x86_64-linux-gnu da solo
CFLAGS_BPF = -target bpf -O2 -g -Wall -fno-stack-protector -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86

all: aegis_exec.bpf.o aegis-collector

aegis_exec.bpf.o: aegis_exec.bpf.c
	$(CC_BPF) $(CFLAGS_BPF) -c $< -o $@

aegis-collector: aegis_collector.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf -lz

clean:
	rm -f aegis_exec.bpf.o aegis-collector
