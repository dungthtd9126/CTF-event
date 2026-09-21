#include <stddef.h>
#include <stdint.h>

#define NK_WIRE_MAGIC "NKTP"
#define NK_PROT
#define NK_DESC_SIZE 0xa20
#define NK_DESC_OPAQUE_OFFSET 0x50
#define NK_DESC_OPAQUE_SIZE (NK_DESC_SIZE - NK_DESC_OPAQUE_OFFSET)

#define NK_SNAPSHOT_SLOTS 8
#define NK_SPRAY_SLOTS 64
#define NK_SPRAY_COPY_SIZE 0x80

enum nk_operation {
    NK_OP_CREATE = 1,
    NK_OP_REMOVE = 2,
    NK_OP_SNAPSHOT = 3,
    NK_OP_INFO = 4,
    NK_OP_SPRAY_ALLOC = 5,
    NK_OP_SPRAY_FREE = 6,
    NK_OP_RCU_SYNC = 7,
};

struct nk_desc;

struct nk_ops {
    int (*validate)(struct nk_desc *desc);
    void (*reset)(struct nk_desc *desc);
    void (*dump)(struct nk_desc *desc);
    void (*destroy)(struct nk_desc *desc);
};

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct rcu_head {
    struct rcu_head *next;
    void (*func)(struct rcu_head *head);
};

struct nk_desc {
    uint64_t id;
    uint64_t state;
    struct nk_ops *ops;
    int (*log)(const char *fmt, ...);
    void (*pivot)(struct nk_desc *desc);
    struct list_head list;
    struct rcu_head rcu;
    void *context;
    uint8_t opaque[NK_DESC_OPAQUE_SIZE];
};

struct nk_snapshot {
    uint64_t snap_id;
    struct nk_desc *desc;
    uint64_t timestamp;
};

/* The multibyte header fields are serialized in network byte order. */
struct nk_wire_header {
    uint8_t magic[4];
    uint8_t version;
    uint8_t op;
    uint16_t sequence;
    uint16_t payload_len;
    uint16_t checksum;
};

struct nk_create_request {
    uint64_t context;
};

struct nk_id_request {
    uint64_t id;
};

struct nk_spray_free_request {
    uint64_t address;
};

struct nk_spray_alloc_payload {
    uint8_t data[NK_SPRAY_COPY_SIZE];
};

struct nk_create_response {
    uint64_t id;
    struct nk_desc *desc;
};

struct nk_info_response {
    uint64_t id;
    uint64_t state;
    struct nk_ops *ops;
    void *log;
    void *pivot;
};

struct nk_snapshot_response {
    uint64_t snap_id;
};

struct nk_spray_alloc_response {
    uint64_t address;
};

struct nk_status_response {
    int32_t status;
};

_Static_assert(sizeof(void *) == 8, "x86-64 pointers required");
_Static_assert(sizeof(uint64_t) == 8, "64-bit integers required");

_Static_assert(sizeof(struct nk_ops) == 0x20, "nk_ops size");
_Static_assert(offsetof(struct nk_ops, validate) == 0x00, "nk_ops.validate");
_Static_assert(offsetof(struct nk_ops, reset) == 0x08, "nk_ops.reset");
_Static_assert(offsetof(struct nk_ops, dump) == 0x10, "nk_ops.dump");
_Static_assert(offsetof(struct nk_ops, destroy) == 0x18, "nk_ops.destroy");

_Static_assert(sizeof(struct list_head) == 0x10, "list_head size");
_Static_assert(sizeof(struct rcu_head) == 0x10, "rcu_head size");

_Static_assert(offsetof(struct nk_desc, id) == 0x00, "nk_desc.id");
_Static_assert(offsetof(struct nk_desc, state) == 0x08, "nk_desc.state");
_Static_assert(offsetof(struct nk_desc, ops) == 0x10, "nk_desc.ops");
_Static_assert(offsetof(struct nk_desc, log) == 0x18, "nk_desc.log");
_Static_assert(offsetof(struct nk_desc, pivot) == 0x20, "nk_desc.pivot");
_Static_assert(offsetof(struct nk_desc, list) == 0x28, "nk_desc.list");
_Static_assert(offsetof(struct nk_desc, rcu) == 0x38, "nk_desc.rcu");
_Static_assert(offsetof(struct nk_desc, context) == 0x48, "nk_desc.context");
_Static_assert(offsetof(struct nk_desc, opaque) == NK_DESC_OPAQUE_OFFSET,
               "nk_desc.opaque");
_Static_assert(sizeof(struct nk_desc) == NK_DESC_SIZE, "nk_desc size");

_Static_assert(offsetof(struct nk_snapshot, snap_id) == 0x00,
               "nk_snapshot.snap_id");
_Static_assert(offsetof(struct nk_snapshot, desc) == 0x08,
               "nk_snapshot.desc");
_Static_assert(offsetof(struct nk_snapshot, timestamp) == 0x10,
               "nk_snapshot.timestamp");
_Static_assert(sizeof(struct nk_snapshot) == 0x18, "nk_snapshot size");

_Static_assert(offsetof(struct nk_wire_header, magic) == 0x00,
               "nk_wire_header.magic");
_Static_assert(offsetof(struct nk_wire_header, version) == 0x04,
               "nk_wire_header.version");
_Static_assert(offsetof(struct nk_wire_header, op) == 0x05,
               "nk_wire_header.op");
_Static_assert(offsetof(struct nk_wire_header, sequence) == 0x06,
               "nk_wire_header.sequence");
_Static_assert(offsetof(struct nk_wire_header, payload_len) == 0x08,
               "nk_wire_header.payload_len");
_Static_assert(offsetof(struct nk_wire_header, checksum) == 0x0a,
               "nk_wire_header.checksum");
_Static_assert(sizeof(struct nk_wire_header) == 0x0c, "nk_wire_header size");

_Static_assert(sizeof(struct nk_create_request) == 0x08,
               "nk_create_request size");
_Static_assert(sizeof(struct nk_id_request) == 0x08, "nk_id_request size");
_Static_assert(sizeof(struct nk_spray_free_request) == 0x08,
               "nk_spray_free_request size");
_Static_assert(sizeof(struct nk_spray_alloc_payload) == NK_SPRAY_COPY_SIZE,
               "nk_spray_alloc_payload size");

_Static_assert(sizeof(struct nk_create_response) == 0x10,
               "nk_create_response size");
_Static_assert(sizeof(struct nk_info_response) == 0x28,
               "nk_info_response size");
_Static_assert(sizeof(struct nk_snapshot_response) == 0x08,
               "nk_snapshot_response size");
_Static_assert(sizeof(struct nk_spray_alloc_response) == 0x08,
               "nk_spray_alloc_response size");
_Static_assert(sizeof(struct nk_status_response) == 0x04,
               "nk_status_response size");
