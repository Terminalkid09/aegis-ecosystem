/* Aegis eBPF sensor — process exec/exit + TCP established dal kernel.
 *
 *  - exec:  tracepoint sched/sched_process_exec (stabile, CO-RE)
 *  - exit:  kprobe do_exit (il tracepoint sched_process_exit è stato rimosso
 *           dal kernel; do_exit(long code) è stabile da anni)
 *  - conn:  tracepoint sock/inet_sock_set_state filtrato su
 *           TCP_ESTABLISHED (niente kprobe version-specific su tcp_v4_connect,
 *           niente falsi positivi sui SYN falliti: solo handshake riusciti)
 * Eventi su ring buffer -> il collector stampa JSON (contratto EventSchema).
 *
 * Build: vmlinux.h è GENERATO dal BTF del kernel target (non committato):
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *   clang -target bpf -O2 -g -c aegis_exec.bpf.c -o aegis_exec.bpf.o
 * Runtime: kernel >= 5.8, BTF, CAP_BPF + CAP_PERFMON (o --privileged).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

char LICENSE[] SEC("license") = "GPL";

/* Evento verso userspace — campi allineati a EventSchema del brain.
 * kind: 0 = exec, 1 = exit, 2 = tcp established (remote_* validi). */
struct aegis_event {
	__u64 ts_ns;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	char comm[TASK_COMM_LEN];
	char filename[FILENAME_LEN];
	__u8 exited; /* 0 = exec, 1 = exit */
	__s32 exit_code; /* valido se exited */
	__u8 has_remote; /* 1 se remote_ip/port validi (conn) */
	__u32 remote_ip; /* BE32 (IPv4) */
	__u16 remote_port; /* host order */
	__u16 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

/* Filtro: PID da ignorare (es. il collector stesso per evitare loop). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} excluded_pids SEC(".maps");

static __always_inline int is_excluded(__u32 pid)
{
	__u8 *v = bpf_map_lookup_elem(&excluded_pids, &pid);
	return v != 0;
}

SEC("tracepoint/sched/sched_process_exec")
int on_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	/* ctx->pid = PID del processo che esegue (TP_fast_assign). */
	__u32 tpid = BPF_CORE_READ(ctx, pid);
	if (is_excluded(tpid))
		return 0;

	struct aegis_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = tpid;
	/* old_pid del tracepoint è il pid pre-exec dello STESSO processo:
	 * il vero parent è task->real_parent->tgid. */
	e->ppid = 0;
	{
		struct task_struct *task = bpf_get_current_task_btf();
		if (task)
			e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	}
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->exited = 0;
	e->exit_code = 0;
	e->has_remote = 0;
	e->remote_ip = 0;
	e->remote_port = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	__builtin_memset(e->filename, 0, sizeof(e->filename));
	{
		/* filename in __data: __data_loc_filename = offset (low 16 bit). */
		__u32 loc = BPF_CORE_READ(ctx, __data_loc_filename);
		__u16 off = (__u16)(loc & 0xFFFF);
		bpf_probe_read_str(e->filename, sizeof(e->filename), (const void *)ctx + off);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/do_exit")
int on_exit(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	if (is_excluded(pid))
		return 0;

	struct aegis_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->ppid = 0;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->exited = 1;
	e->exit_code = (__s32)PT_REGS_PARM1(ctx);
	e->has_remote = 0;
	e->remote_ip = 0;
	e->remote_port = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	__builtin_memset(e->filename, 0, sizeof(e->filename));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* TCP_ESTABLISHED = 1 (include/uapi/linux/tcp.h, stabile da sempre). */
#define TCP_ESTABLISHED 1

SEC("tracepoint/sock/inet_sock_set_state")
int on_tcp_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	int newstate;
	bpf_core_read(&newstate, sizeof(newstate), &ctx->newstate);
	if (newstate != TCP_ESTABLISHED)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	if (is_excluded(pid))
		return 0;

	const struct sock *sk = 0;
	bpf_core_read(&sk, sizeof(sk), &ctx->skaddr);
	if (!sk)
		return 0;

	/* Solo IPv4 qui (AF_INET=2); IPv6 in estensione futura documentata. */
	__u16 family = 0;
	bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
	if (family != 2)
		return 0;

	struct aegis_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->ppid = 0;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->exited = 2; /* connessione */
	e->exit_code = 0;
	e->has_remote = 1;
	/* daddr BE32, dport BE16: conversione esplicita, niente bpf_ntohs su BPF. */
	__be32 daddr = 0;
	__be16 dport = 0;
	bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
	bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
	e->remote_ip = daddr;
	e->remote_port = (__u16)__builtin_bswap16((__u16)dport);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	__builtin_memset(e->filename, 0, sizeof(e->filename));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
