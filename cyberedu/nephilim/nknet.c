/* Source-level reconstruction of modules/nknet.ko. */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "struct.c"

#define AF_INET_VALUE 2
#define SOCK_DGRAM_VALUE 2
#define IPPROTO_UDP_VALUE 17
#define SHUT_RDWR_VALUE 2
#define NKNET_NODE_ANY (-1)
#define NKNET_CPU_UNBOUND 0x40

struct net;
struct msghdr;
struct kvec;

struct nk_msghdr {
    void *name;
    uint32_t name_len;
    uint32_t alignment;
    uint8_t opaque[0x58];
};

struct nk_kvec {
    void *base;
    size_t length;
};

extern struct net init_net;
extern int _printk(const char *fmt, ...);
extern int kernel_bind(struct socket *socket, void *address, int length);
extern int kernel_recvmsg(struct socket *socket, struct nk_msghdr *message,
                          struct nk_kvec *vector, size_t vector_count,
                          size_t length, int flags);
extern int kernel_sendmsg(struct socket *socket, struct nk_msghdr *message,
                          struct nk_kvec *vector, size_t vector_count,
                          size_t length);
extern int sock_create_kern(struct net *net, int family, int type, int protocol,
                            struct socket **socket_out);
extern void sock_release(struct socket *socket);
extern int kernel_sock_shutdown(struct socket *socket, int how);
extern struct task_struct *kthread_create_on_node(int (*threadfn)(void *),
                                                  void *data, int node,
                                                  const char *namefmt, ...);
extern int wake_up_process(struct task_struct *task);
extern int kthread_stop(struct task_struct *task);
extern int kthread_should_stop(void);
extern void kernel_sigaction(int signal);

struct task_struct *nk_thread;
struct socket *nk_sock;

static uint16_t nk_swap16(uint16_t value)
{
    return (uint16_t)((value << 8) | (value >> 8));
}

static void nk_set_status(uint8_t *reply, int status)
{
    int32_t value = status;

    memcpy(reply, &value, sizeof(value));
}

void nknet_send(struct nk_sockaddr_in *peer, uint8_t operation,
                uint16_t sequence, const void *payload,
                uint16_t payload_size)
{
    uint8_t packet[sizeof(struct nk_wire_header) + 0x100] = {0};
    struct nk_wire_header *header = (struct nk_wire_header *)packet;
    struct nk_msghdr message = {0};
    struct nk_kvec vector;
    uint32_t checksum = 0xffffdeadU;
    size_t packet_size = sizeof(*header) + payload_size;
    size_t i;

    memcpy(header->magic, NK_WIRE_MAGIC, sizeof(header->magic));
    header->version = NK_PROTOCOL_VERSION;
    header->op = operation;
    header->sequence = nk_swap16(sequence);
    header->payload_len = nk_swap16(payload_size);
    header->checksum = 0;
    memcpy(packet + sizeof(*header), payload, payload_size);

    for (i = 0; i < packet_size; ++i)
        checksum ^= packet[i];
    header->checksum = nk_swap16((uint16_t)checksum);

    message.name = peer;
    message.name_len = sizeof(*peer);
    vector.base = packet;
    vector.length = packet_size;
    kernel_sendmsg(nk_sock, &message, &vector, 1, packet_size);
}

void nknet_handle(const uint8_t *packet, size_t packet_size,
                  struct nk_sockaddr_in *peer)
{
    const struct nk_wire_header *header = (const struct nk_wire_header *)packet;
    const uint8_t *payload = packet + sizeof(*header);
    uint8_t reply[0x100] = {0};
    uint64_t id = 0;
    uint64_t value = 0;
    uint16_t payload_size;
    uint16_t sequence;
    uint16_t reply_size = 0;
    uint8_t operation;
    int status;

    if (packet_size <= sizeof(*header) - 1)
        return;
    if (memcmp(header->magic, NK_WIRE_MAGIC, sizeof(header->magic)) != 0)
        return;
    if (header->version != NK_PROTOCOL_VERSION)
        return;

    payload_size = nk_swap16(header->payload_len);
    if ((size_t)payload_size + sizeof(*header) > packet_size)
        return;

    operation = header->op;
    sequence = nk_swap16(header->sequence);

    switch (operation) {
    case NK_OP_CREATE: {
        void *context = NULL;
        struct nk_desc *desc = NULL;

        if (payload_size >= sizeof(uint64_t))
            memcpy(&value, payload, sizeof(value));
        context = (void *)(uintptr_t)value;
        status = nkrcu_create(context, &id, &desc);
        if (status != 0) {
            nk_set_status(reply, status);
            reply_size = sizeof(int32_t);
        } else {
            memcpy(reply, &id, sizeof(id));
            memcpy(reply + sizeof(id), &desc, sizeof(desc));
            reply_size = 0x10;
        }
        break;
    }

    case NK_OP_REMOVE:
        if (payload_size < sizeof(uint64_t))
            break;
        memcpy(&id, payload, sizeof(id));
        status = nkrcu_remove(id);
        nk_set_status(reply, status);
        reply_size = sizeof(int32_t);
        break;

    case NK_OP_SNAPSHOT:
        if (payload_size < sizeof(uint64_t))
            break;
        memcpy(&id, payload, sizeof(id));
        status = nkrcu_snap_create(id, &value);
        if (status != 0) {
            nk_set_status(reply, status);
            reply_size = sizeof(int32_t);
        } else {
            memcpy(reply, &value, sizeof(value));
            reply_size = sizeof(value);
        }
        break;

    case NK_OP_INFO:
        if (payload_size < sizeof(uint64_t))
            break;
        memcpy(&id, payload, sizeof(id));
        status = nkrcu_info(id, reply, 0x28);
        if (status != 0) {
            nk_set_status(reply, status);
            reply_size = sizeof(int32_t);
        } else {
            reply_size = 0x28;
        }
        break;

    case NK_OP_SPRAY_ALLOC: {
        void *address = NULL;

        if (payload_size <= 0x7f)
            break;
        status = nkrcu_spray_alloc(payload, &address);
        if (status != 0) {
            nk_set_status(reply, status);
            reply_size = sizeof(int32_t);
        } else {
            memcpy(reply, &address, sizeof(address));
            reply_size = sizeof(address);
        }
        break;
    }

    case NK_OP_SPRAY_FREE:
        if (payload_size < sizeof(uint64_t))
            break;
        memcpy(&value, payload, sizeof(value));
        status = nkrcu_spray_free((void *)(uintptr_t)value);
        nk_set_status(reply, status);
        reply_size = sizeof(int32_t);
        break;

    case NK_OP_RCU_SYNC:
        nkrcu_sync();
        nk_set_status(reply, 0);
        reply_size = sizeof(int32_t);
        break;

    default:
        return;
    }

    nknet_send(peer, operation, sequence, reply, reply_size);
}

int nknet_loop(void *arg)
{
    uint8_t packet[NKNET_RX_BUFFER_SIZE] = {0};
    struct nk_sockaddr_in peer = {0};

    (void)arg;
    kernel_sigaction(9);

    while (!kthread_should_stop()) {
        struct nk_msghdr message = {
            .name = &peer,
            .name_len = sizeof(peer),
        };
        struct nk_kvec vector = {
            .base = packet,
            .length = sizeof(packet),
        };
        int received = kernel_recvmsg(nk_sock, &message, &vector, 1,
                                      sizeof(packet), 0);

        if (received > 0)
            nknet_handle(packet, (size_t)received, &peer);
    }
    return 0;
}

int nknet_init(void)
{
    struct nk_sockaddr_in address = {
        .family = AF_INET_VALUE,
        .port = 0x697a,
        .address = 0,
    };
    int status;

    status = sock_create_kern(&init_net, AF_INET_VALUE, SOCK_DGRAM_VALUE,
                              IPPROTO_UDP_VALUE, &nk_sock);
    if (status != 0)
        return status;

    status = kernel_bind(nk_sock, &address, sizeof(address));
    if (status != 0) {
        sock_release(nk_sock);
        return status;
    }

    nk_thread = kthread_create_on_node(nknet_loop, NULL, NKNET_NODE_ANY,
                                       "nknet");
    if ((uintptr_t)nk_thread >= (uintptr_t)-4095) {
        status = (int)(intptr_t)nk_thread;
        sock_release(nk_sock);
        return status;
    }

    wake_up_process(nk_thread);
    _printk("nknet: listening on UDP %d\n", 0x7a69);
    return 0;
}

void nknet_exit(void)
{
    kernel_sock_shutdown(nk_sock, SHUT_RDWR_VALUE);
    kthread_stop(nk_thread);
    sock_release(nk_sock);
}
