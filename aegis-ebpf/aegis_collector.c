/* Aegis eBPF collector — userspace (libbpf).
 *
 * Carica aegis_exec.bpf.o, attacca i tracepoint, legge il ring buffer e
 * stampa una riga JSON per evento su stdout (contratto verso il brain:
 * gli stessi campi di EventSchema / PROCESS_CREATED).
 *
 * Uso:
 *   ./aegis-collector --obj aegis_exec.bpf.o [--exclude-pid PID]...
 * Test:
 *   ./aegis-collector & for i in 1 2 3; do /bin/echo probe-$i; sleep 0.2; done
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

struct aegis_event {
	uint64_t ts_ns;
	uint32_t pid;
	uint32_t ppid;
	uint32_t uid;
	char comm[TASK_COMM_LEN];
	char filename[FILENAME_LEN];
	uint8_t exited;
	int32_t exit_code;
	uint8_t has_remote;
	uint32_t remote_ip; /* BE32 */
	uint16_t remote_port; /* host order */
	uint16_t _pad;
};

static volatile int running = 1;

static void on_sigint(int sig)
{
	(void)sig;
	running = 0;
}

/* JSON escape minimo per comm/filename. */
static void json_str(FILE *f, const char *s, size_t max)
{
	fputc('"', f);
	for (size_t i = 0; i < max && s[i]; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '"' || c == '\\')
			fprintf(f, "\\%c", c);
		else if (c < 0x20)
			fprintf(f, "\\u%04x", c);
		else
			fputc(c, f);
	}
	fputc('"', f);
}

static int on_event(void *ctx, void *data, size_t len)
{
	(void)ctx;
	if (len < sizeof(struct aegis_event)) {
		fprintf(stderr, "short event: %zu\n", len);
		return 0;
	}
	struct aegis_event *e = data;
	printf("{\"ts_ns\":%llu,\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":",
	       (unsigned long long)e->ts_ns, e->pid, e->ppid, e->uid);
	char comm[TASK_COMM_LEN + 1] = {0};
	memcpy(comm, e->comm, TASK_COMM_LEN);
	json_str(stdout, comm, TASK_COMM_LEN);
	printf(",\"filename\":");
	char fn[FILENAME_LEN + 1] = {0};
	memcpy(fn, e->filename, FILENAME_LEN);
	json_str(stdout, fn, FILENAME_LEN);
	if (e->exited == 2) {
	 /* Connessione TCP stabilita: IP BE32 -> dotted quad (ntohl!). */
	 uint32_t ip = ntohl(e->remote_ip);
	 printf(",\"event_type\":\"CONNECTION_ESTABLISHED\",\"remote\":\"%u.%u.%u.%u:%u\"}\n",
	        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
	        e->remote_port);
	} else if (e->exited)
		printf(",\"event_type\":\"PROCESS_EXITED\",\"exit_code\":%d}\n", e->exit_code);
	else
		printf(",\"event_type\":\"PROCESS_CREATED\"}\n");
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	const char *obj_path = "aegis_exec.bpf.o";
	uint32_t exclude[64];
	int n_exclude = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--obj") && i + 1 < argc) {
			obj_path = argv[++i];
		} else if (!strcmp(argv[i], "--exclude-pid") && i + 1 < argc) {
			if (n_exclude < 64)
				exclude[n_exclude++] = (uint32_t)atoi(argv[++i]);
		} else {
			fprintf(stderr, "usage: %s [--obj FILE] [--exclude-pid PID]...\n", argv[0]);
			return 2;
		}
	}

	struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "open %s: %s\n", obj_path, strerror(-(int)libbpf_get_error(obj)));
		return 1;
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "load: %s\n", strerror(errno));
		return 1;
	}
	struct bpf_program *p;
	bpf_object__for_each_program(p, obj) {
		if (bpf_program__attach(p) == NULL) {
			fprintf(stderr, "attach %s: %s\n", bpf_program__name(p), strerror(errno));
			return 1;
		}
	}

	int map_fd = bpf_object__find_map_fd_by_name(obj, "excluded_pids");
	if (map_fd >= 0) {
		uint8_t one = 1;
		for (int i = 0; i < n_exclude; i++)
			bpf_map_update_elem(map_fd, &exclude[i], &one, BPF_ANY);
		/* Escludi sempre se stesso per evitare loop di osservazione. */
		uint32_t self = (uint32_t)getpid();
		bpf_map_update_elem(map_fd, &self, &one, BPF_ANY);
	}

	int rb_fd = bpf_object__find_map_fd_by_name(obj, "events");
	if (rb_fd < 0) {
		fprintf(stderr, "ringbuf map not found\n");
		return 1;
	}
	struct ring_buffer *rb = ring_buffer__new(rb_fd, on_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
		return 1;
	}

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);
	fprintf(stderr, "aegis-collector: listening (obj=%s), Ctrl-C per fermare\n", obj_path);
	while (running) {
		if (ring_buffer__poll(rb, 500) < 0 && errno != EINTR)
			break;
	}
	ring_buffer__free(rb);
	return 0;
}
