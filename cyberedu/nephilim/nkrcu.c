/* Source-level reconstruction of modules/nkrcu.ko. */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "struct.c"

#define NK_ALLOC_FLAGS 0x80
#define NK_PROC_MODE 0444
#define NK_FREE_MARKER UINT64_C(0xdead000000000122)

struct inode;
struct file;
struct seq_file;

extern int _printk(const char *fmt, ...);
extern void *kmalloc(size_t size, unsigned int flags);
extern void kfree(void *ptr);
extern void call_rcu(struct rcu_head *head,
                     void (*callback)(struct rcu_head *head));
extern void rcu_read_lock(void);
extern void rcu_read_unlock(void);
extern void synchronize_rcu(void);
extern uint64_t ktime_get_real_seconds(void);
extern void _raw_spin_lock(nk_spinlock_t *lock);
extern void _raw_spin_unlock(nk_spinlock_t *lock);
extern void _raw_spin_lock_bh(nk_spinlock_t *lock);
extern void _raw_spin_unlock_bh(nk_spinlock_t *lock);

extern struct proc_dir_entry *proc_mkdir(const char *name,
                                         struct proc_dir_entry *parent);
extern struct proc_dir_entry *proc_create(const char *name,
                                          unsigned int mode,
                                          struct proc_dir_entry *parent,
                                          const struct proc_ops *ops);
extern void remove_proc_entry(const char *name,
                              struct proc_dir_entry *parent);
extern int single_open(struct file *file,
                       int (*show)(struct seq_file *, void *), void *data);
extern int seq_printf(struct seq_file *file, const char *fmt, ...);

uint64_t nk_snap_counter = 1;
uint64_t nk_id_counter = 1;
struct list_head nk_list = { &nk_list, &nk_list };
struct proc_dir_entry *nk_proc_dir;
nk_spinlock_t nk_spray_lock;
void *nkrcu_spray_bufs[NK_SPRAY_SLOTS];
nk_spinlock_t nk_snap_lock;
struct nk_snapshot nk_snaps[NK_SNAPSHOT_SLOTS];
nk_spinlock_t nk_list_lock;
struct proc_ops nk_layout_ops;

static int nk_desc_validate(struct nk_desc *desc)
{
    (void)desc;
    return 0;
}

static void nk_desc_reset(struct nk_desc *desc)
{
    desc->context = NULL;
    memset(desc->opaque, 0, 0x30);
}

static void nk_desc_dump(struct nk_desc *desc)
{
    _printk("nkrcu: desc id=%llu\n", (unsigned long long)desc->id);
}

static void nk_desc_destroy(struct nk_desc *desc)
{
    (void)desc;
}

struct nk_ops nk_default_ops = {
    .validate = nk_desc_validate,
    .reset = nk_desc_reset,
    .dump = nk_desc_dump,
    .destroy = nk_desc_destroy,
};

static struct nk_desc *nk_find_desc(uint64_t id)
{
    struct list_head *entry;

    for (entry = nk_list.next; entry != &nk_list; entry = entry->next) {
        struct nk_desc *desc = (struct nk_desc *)
            ((char *)entry - offsetof(struct nk_desc, list));

        if (desc->id == id)
            return desc;
    }
    return NULL;
}

static void nk_list_add_desc(struct nk_desc *desc)
{
    struct list_head *head = &nk_list;
    struct list_head *first = head->next;

    desc->list.next = first;
    desc->list.prev = head;
    first->prev = &desc->list;
    head->next = &desc->list;
}

static void nk_desc_free_rcu(struct rcu_head *head)
{
    struct nk_desc *desc = (struct nk_desc *)
        ((char *)head - offsetof(struct nk_desc, rcu));

    kfree(desc);
}

int nkrcu_create(void *context, uint64_t *id_out,
                 struct nk_desc **descriptor_out)
{
    struct nk_desc *desc = kmalloc(NK_DESC_SIZE, NK_ALLOC_FLAGS);

    if (desc == NULL)
        return -ENOMEM;

    desc->id = __atomic_fetch_add(&nk_id_counter, 1, __ATOMIC_SEQ_CST);
    desc->state = 1;
    desc->ops = &nk_default_ops;
    desc->log = _printk;
    desc->pivot = nkrcu_pivot;
    memset(&desc->context, 0, 7 * sizeof(uint64_t));
    desc->context = context;

    desc->list.next = &desc->list;
    desc->list.prev = &desc->list;

    _raw_spin_lock(&nk_list_lock);
    nk_list_add_desc(desc);
    _raw_spin_unlock(&nk_list_lock);

    *id_out = desc->id;
    *descriptor_out = desc;
    return 0;
}

int nkrcu_remove(uint64_t id)
{
    struct nk_desc *desc;

    _raw_spin_lock(&nk_list_lock);
    desc = nk_find_desc(id);
    if (desc == NULL) {
        _raw_spin_unlock(&nk_list_lock);
        return -ENOENT;
    }

    desc->list.prev->next = desc->list.next;
    desc->list.next->prev = desc->list.prev;
    desc->list.prev = (struct list_head *)(uintptr_t)NK_FREE_MARKER;
    _raw_spin_unlock(&nk_list_lock);
    // UAF, free desc but not remove it from the list
    call_rcu(&desc->rcu, nk_desc_free_rcu); 
    return 0;
}

int nkrcu_snap_create(uint64_t id, uint64_t *snapshot_id_out)
{
    struct nk_desc *desc;
    struct nk_snapshot *slot = NULL;
    unsigned int i;

    rcu_read_lock();
    desc = nk_find_desc(id);
    if (desc == NULL) {
        rcu_read_unlock();
        return -ENOENT;
    }
    rcu_read_unlock();

    _raw_spin_lock_bh(&nk_snap_lock);
    for (i = 0; i < NK_SNAPSHOT_SLOTS; ++i) {
        if (nk_snaps[i].snap_id == 0) {
            slot = &nk_snaps[i];
            break;
        }
    }

    if (slot == NULL) {
        _raw_spin_unlock_bh(&nk_snap_lock);
        return -ENOSPC;
    }

    slot->snap_id = __atomic_fetch_add(&nk_snap_counter, 1,
                                       __ATOMIC_SEQ_CST);
    // desc still in nk_snaps[i]->desc;
    slot->desc = desc;
    slot->timestamp = ktime_get_real_seconds();
    *snapshot_id_out = slot->snap_id;
    _raw_spin_unlock_bh(&nk_snap_lock);
    return 0;
}

int nkrcu_info(uint64_t id, void *output, size_t output_size)
{
    struct nk_desc *desc;
    struct nk_info_response *info = output;

    if (output_size < sizeof(*info))
        return -EINVAL;

    rcu_read_lock();
    desc = nk_find_desc(id);
    if (desc == NULL) {
        rcu_read_unlock();
        return -ENOENT;
    }

    info->id = id;
    info->state = desc->state;
    info->ops = desc->ops;
    memcpy(&info->log, &desc->log, sizeof(info->log));
    memcpy(&info->pivot, &desc->pivot, sizeof(info->pivot));
    rcu_read_unlock();
    return 0;
}

int nkrcu_spray_alloc(const void *payload, void **address_out)
{
    void *object = kmalloc(NK_DESC_SIZE, NK_ALLOC_FLAGS);
    unsigned int i;

    if (object == NULL)
        return -ENOMEM;

    memcpy(object, payload, NK_SPRAY_COPY_SIZE);

    _raw_spin_lock(&nk_spray_lock);
    for (i = 0; i < NK_SPRAY_SLOTS; ++i) {
        if (nkrcu_spray_bufs[i] == NULL) {
            nkrcu_spray_bufs[i] = object;
            _raw_spin_unlock(&nk_spray_lock);
            *address_out = object;
            return 0;
        }
    }
    _raw_spin_unlock(&nk_spray_lock);

    kfree(object);
    return -ENOSPC;
}

int nkrcu_spray_free(void *address)
{
    unsigned int i;

    _raw_spin_lock(&nk_spray_lock);
    for (i = 0; i < NK_SPRAY_SLOTS; ++i) {
        if (nkrcu_spray_bufs[i] != address)
            continue;

        kfree(address);
        nkrcu_spray_bufs[i] = NULL;
        _raw_spin_unlock(&nk_spray_lock);
        return 0;
    }
    _raw_spin_unlock(&nk_spray_lock);
    return -ENOENT;
}

void nkrcu_snap_iter(nk_snapshot_callback callback, void *arg)
{
    struct nk_snapshot local[NK_SNAPSHOT_SLOTS];
    unsigned int count = 0;
    unsigned int i;

    memset(local, 0, sizeof(local));
    _raw_spin_lock_bh(&nk_snap_lock);
    for (i = 0; i < NK_SNAPSHOT_SLOTS; ++i) {
        if (nk_snaps[i].snap_id == 0)
            continue;
        local[count++] = nk_snaps[i];
    }
    _raw_spin_unlock_bh(&nk_snap_lock);

    for (i = 0; i < count; ++i)
        callback(&local[i], arg);
}

void nkrcu_sync(void)
{
    synchronize_rcu();
}

__attribute__((naked)) void nkrcu_pivot(struct nk_desc *desc)
{
    (void)desc;
    __asm__ volatile("mov (%%rdi), %%rsp\n\tret" ::: "memory");
}

static int nk_layout_show(struct seq_file *file, void *unused)
{
    unsigned int i;

    (void)unused;
    _raw_spin_lock_bh(&nk_snap_lock);
    for (i = 0; i < NK_SNAPSHOT_SLOTS; ++i) {
        if (nk_snaps[i].snap_id == 0)
            continue;
        seq_printf(file, "snap[%d]: snap_id=%llu timestamp=%llu\n", i,
                   (unsigned long long)nk_snaps[i].snap_id,
                   (unsigned long long)nk_snaps[i].timestamp);
    }
    _raw_spin_unlock_bh(&nk_snap_lock);
    return 0;
}

static __attribute__((unused)) int nk_layout_open(struct inode *inode,
                                                  struct file *file)
{
    (void)inode;
    return single_open(file, nk_layout_show, NULL);
}

int nkrcu_init(void)
{
    memset(nk_snaps, 0, sizeof(nk_snaps));
    memset(nkrcu_spray_bufs, 0, sizeof(nkrcu_spray_bufs));

    nk_proc_dir = proc_mkdir("nephilim", NULL);
    if (nk_proc_dir == NULL)
        return -ENOMEM;

    /* The original proc_ops table points at nk_layout_open and seq helpers. */
    if (proc_create("layout", NK_PROC_MODE, nk_proc_dir, &nk_layout_ops) == NULL) {
        remove_proc_entry("nephilim", NULL);
        return -ENOMEM;
    }

    _printk("nephilim loaded\n");
    return 0;
}

void nkrcu_exit(void)
{
    unsigned int i;

    remove_proc_entry("layout", nk_proc_dir);
    remove_proc_entry("nephilim", NULL);

    _raw_spin_lock(&nk_spray_lock);
    for (i = 0; i < NK_SPRAY_SLOTS; ++i) {
        kfree(nkrcu_spray_bufs[i]);
        nkrcu_spray_bufs[i] = NULL;
    }
    _raw_spin_unlock(&nk_spray_lock);
}
