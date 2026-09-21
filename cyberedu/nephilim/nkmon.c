/* Source-level reconstruction of modules/nkmon.ko. */

#include <stdint.h>
#include <string.h>

#include "struct.c"

#define NKMON_INTERVAL_JIFFIES 0x1388
#define NKMON_CPU_UNBOUND 0x40

struct workqueue_struct;

extern struct workqueue_struct *system_wq;
extern unsigned long jiffies;
extern int _printk(const char *fmt, ...);
extern int queue_work_on(int cpu, struct workqueue_struct *queue,
                         struct work_struct *work);
extern int mod_timer(struct timer_list *timer, unsigned long expires);
extern void init_timer_key(struct timer_list *timer,
                           void (*callback)(struct timer_list *),
                           unsigned int flags, const char *name,
                           void *key);
extern void timer_delete_sync(struct timer_list *timer);
extern void cancel_work_sync(struct work_struct *work);

struct work_struct nk_mon_work;
struct timer_list nk_mon_timer;

static void nk_init_work_recovered(struct work_struct *work,
                                    void (*callback)(struct work_struct *))
{
    memset(work, 0, sizeof(*work));
    memcpy(work->raw + 0x18, &callback, sizeof(callback));
}

void nk_mon_cb(struct nk_snapshot *snapshot, void *arg)
{
    struct nk_desc *desc;

    (void)arg;
    desc = snapshot->desc;
    if (desc == NULL || desc->ops == NULL || desc->ops->validate == NULL)
        return;

    desc->ops->validate(desc);
}

void nk_mon_work_fn(struct work_struct *work)
{
    (void)work;
    nkrcu_snap_iter(nk_mon_cb, NULL);
}

void nk_mon_tick(struct timer_list *timer)
{
    (void)timer;
    queue_work_on(NKMON_CPU_UNBOUND, system_wq, &nk_mon_work);
    mod_timer(&nk_mon_timer, jiffies + NKMON_INTERVAL_JIFFIES);
}

int nkmon_init(void)
{
    nk_init_work_recovered(&nk_mon_work, nk_mon_work_fn);
    init_timer_key(&nk_mon_timer, nk_mon_tick, 0, NULL, NULL);
    mod_timer(&nk_mon_timer, jiffies + NKMON_INTERVAL_JIFFIES);
    _printk("nkmon: loaded, interval=%ds\n", 5);
    return 0;
}

void nkmon_exit(void)
{
    timer_delete_sync(&nk_mon_timer);
    cancel_work_sync(&nk_mon_work);
}
