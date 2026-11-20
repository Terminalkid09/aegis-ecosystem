# Aegis eBPF sensor — build inside a Debian container (kernel BTF from the host).
#
#   docker build -t aegis-ebpf-builder -f Dockerfile.builder .
#   docker run --rm -v %cd%:/src aegis-ebpf-builder make -C /src
# Or all in one shot (network needed for apt):
#   docker run --rm -v %cd%:/src debian:bookworm-slim bash /src/build-in-docker.sh
#
# Privileged test (kernel >= 5.8, BTF in /sys/kernel/btf/vmlinux):
#   docker run --rm --privileged -v %cd%:/src debian:bookworm-slim \
#     bash -c 'apt-get update -qq && apt-get install -y -qq libbpf1 >/dev/null && /src/aegis-collector --obj /src/aegis_exec.bpf.o & sleep 1; for i in 1 2 3; do /bin/echo probe-$i; sleep 0.2; done; sleep 1; kill %1'

CC_BPF ?= clang
# -I multiarch: clang -target bpf does not search /usr/include/x86_64-linux-gnu by itself
CFLAGS_BPF = -target bpf -O2 -g -Wall -fno-stack-protector -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86

all: aegis_exec.bpf.o aegis-collector

aegis_exec.bpf.o: aegis_exec.bpf.c
	$(CC_BPF) $(CFLAGS_BPF) -c $< -o $@

aegis-collector: aegis_collector.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf -lz

# Windows (MinGW-w64): user-mode ETW consumer, no driver and no signature.
# -lws2_32 is not optional: ntohl comes from winsock2.h.
# Running it requires an admin session. The manifest forces elevation when
# the helper is opened manually; the service starts it as LocalSystem.
CC_WIN ?= x86_64-w64-mingw32-gcc
WINDRES ?= x86_64-w64-mingw32-windres
# MinGW's default endfile spec injects a second, asInvoker manifest. Disable
# that object so the requireAdministrator resource is the only manifest.
WIN_SPECS ?= no-default-manifest.specs
aegis-etw.exe: aegis_etw.c aegis-etw.rc aegis-etw.manifest $(WIN_SPECS)
	$(WINDRES) -i aegis-etw.rc -O coff -o aegis-etw.res.o
	$(CC_WIN) -O2 -Wall -specs=$(WIN_SPECS) $< aegis-etw.res.o -o $@ -ladvapi32 -ltdh -lws2_32

clean:
	rm -f aegis_exec.bpf.o aegis-collector aegis-etw.exe aegis-etw.res.o
