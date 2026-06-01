#include <bits/stdc++.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

using namespace std;

class Cage
{
public:
    typedef struct Block
    {
        uint64_t priv_size;
        uint64_t curr_size;
        char payload[];
    } Block;

private:
    void *base;
    void *top;
    vector<set<Block *>> bins;
    int debugmode;

    static uint64_t aln(uint64_t s)
    {
        if (s + sizeof(Block) + 0x10 < s)
            return 0;
        s += sizeof(Block);
        s = (s & 0xfULL) ? ((s & ~0xfULL) + 0x10) : s;
        return s > 0x20 ? s : 0x20;
    }

    bool is_top(Block *b) { return b == (Block *)top; }
    bool is_base(Block *b) { return b == (Block *)base; }
    bool prev_inuse(Block *b) { return b->curr_size & 1; }
    bool next_inuse(Block *b) { return next_blk(next_blk(b))->curr_size & 1; }
    void on_prev(Block *b) { b->curr_size |= 1ULL; }
    void off_prev(Block *b) { b->curr_size &= ~1ULL; }
    uint64_t SIZE(Block *b) { return b->curr_size & ~0xfULL; }
    uint64_t PSIZE(Block *b) { return b->priv_size & ~0xfULL; }
    Block *next_blk(Block *b) { return (Block *)((uint64_t)b + SIZE(b)); }
    Block *prev_blk(Block *b) { return (Block *)((uint64_t)b - PSIZE(b)); }
    char *to_data(Block *b) { return b->payload; }
    Block *from_data(void *p) { return (Block *)((uint64_t)p - sizeof(Block)); }

    int idx_of(uint64_t s)
    {
        int i = 0;
        s /= 0x20;
        while (s > 1 && i < 10)
        {
            s >>= 1;
            i++;
        }
        return i < 10 ? i : 9;
    }

    static bool sz_cmp(Block *l, Block *r) { return l->curr_size < r->curr_size; }

    void pop_bin(Block *b)
    {
        if (!b)
            return;
        bins[idx_of(SIZE(b))].erase(b);
    }

    Block *consolidate(Block *cur)
    {
        Block *lo = cur, *hi = cur;
        uint64_t newsz   = SIZE(cur);
        uint64_t pred_sz = SIZE(cur);

        while (!is_base(lo) && !prev_inuse(lo))
        {
            if (debugmode)
                printf("consolidate: 0x%llx\n", (unsigned long long)prev_blk(lo));
            pop_bin(prev_blk(lo));
            lo = prev_blk(lo);
            newsz += SIZE(lo);
        }
        while (!is_top(next_blk(hi)) && !next_inuse(hi))
        {
            if (debugmode)
                printf("consolidate: 0x%llx\n", (unsigned long long)next_blk(hi));
            pop_bin(next_blk(hi));
            hi = next_blk(hi);
            newsz += SIZE(hi);
        }

        if (is_top(next_blk(hi)))
        {
            lo->curr_size = newsz + SIZE((Block *)top);
            top = lo;
            return nullptr;
        }

        lo->curr_size            = newsz;
        next_blk(lo)->priv_size  = pred_sz;
        on_prev(lo);
        off_prev(next_blk(lo));
        return lo;
    }

    void put_into_bins(Block *b)
    {
        if (debugmode)
        {
            printf("Top: 0x%llx\n", (unsigned long long)top);
            printf("curr: 0x%llx, next: 0x%llx, nextsize: 0x%llx\n",
                   (unsigned long long)b,
                   (unsigned long long)next_blk(b),
                   (unsigned long long)SIZE(next_blk(b)));
            fflush(stdout);
        }

        if (!prev_inuse(b) || (!is_top(next_blk(b)) && !next_inuse(b)))
            b = consolidate(b);
        if (!b)
            return;

        if (is_top(next_blk(b)))
        {
            b->curr_size += SIZE((Block *)top);
            top = b;
        }
        else
        {
            off_prev(next_blk(b));
            bins[idx_of(SIZE(b))].insert(b);
        }
    }

    char *split_alloc(Block *b, uint64_t alsz)
    {
        if (SIZE(b) - alsz < 0x20)
        {
            on_prev(next_blk(b));
            return to_data(b);
        }
        bool pre = prev_inuse(b);
        Block *ret = b;
        Block *sp = (Block *)((uint64_t)b + alsz);

        if (debugmode)
            printf("split_mode: 0x%llx, 0x%llx\n",
                   (unsigned long long)ret, (unsigned long long)sp);

        sp->curr_size = SIZE(b) - alsz;
        sp->priv_size = alsz;
        ret->curr_size = alsz;

        on_prev(sp);
        if (pre)
            on_prev(ret);
        else
            off_prev(ret);

        next_blk(sp)->priv_size = SIZE(sp);

        bins[idx_of(SIZE(sp))].insert(sp);
        return to_data(ret);
    }

    char *top_alloc(uint64_t alsz)
    {
        if (SIZE((Block *)top) < alsz)
            return nullptr;

        Block *nc = (Block *)top;
        uint64_t pts = SIZE((Block *)top);
        bool tpi = prev_inuse((Block *)top);

        top = (void *)((uint64_t)top + alsz);
        ((Block *)top)->curr_size = pts - alsz;
        ((Block *)top)->priv_size = alsz;
        nc->curr_size = alsz;

        on_prev((Block *)top);
        if (tpi)
            on_prev(nc);
        else
            off_prev(nc);
        return to_data(nc);
    }

public:
    Cage()
    {
        int fd = open("/dev/urandom", O_RDONLY);
        uint64_t a = 0;
        debugmode = 0;
        if (fd < 0 || read(fd, &a, 4) != 4)
        {
            perror("urandom");
            exit(1);
        }
        close(fd);
        a = (a << 16) & 0xfffffffffffULL;
        if ((top = mmap((void *)a, 1u << 30, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) != (void *)a)
        {
            perror("mmap");
            exit(1);
        }
        base = top;
        ((Block *)top)->priv_size = 0;
        ((Block *)top)->curr_size = (1u << 26) + 1;
        bins.resize(10);
    }

    char *alloc(uint64_t sz)
    {
        uint64_t alsz = aln(sz);
        if (alsz == 0)
            return nullptr;
        Block *chosen = nullptr;
        Block tmp;
        tmp.curr_size = alsz;
        int st = idx_of(alsz);

        if (debugmode)
            printf("try to alloc 0x%llx size chunk\n", (unsigned long long)alsz);

        for (auto it = next(bins.begin(), st); it != bins.end(); ++it)
        {
            auto found = lower_bound(it->begin(), it->end(), &tmp, sz_cmp);
            if (found == it->end())
                continue;
            chosen = *found;
            it->erase(found);
            break;
        }

        if (debugmode && chosen)
            printf("found some bin, 0x%llx\n", (unsigned long long)chosen);

        if (chosen)
            return split_alloc(chosen, alsz);
        return top_alloc(alsz);
    }

    void release(void *p)
    {
        if (!p)
            return;
        Block *fc = from_data(p);
        if (debugmode)
            printf("free: 0x%llx, size: 0x%llx\n",
                   (unsigned long long)fc, (unsigned long long)SIZE(fc));
        put_into_bins(fc);
    }
};

Cage cage;
#define MAX_BOOKS 16
#define NOTES_PER_BOOK 48

typedef struct Note
{
    uint64_t size;
    char *data;
} Note;

typedef struct NoteBook
{
    Note notes[NOTES_PER_BOOK];
} NoteBook;

static uint64_t note_tags[MAX_BOOKS][NOTES_PER_BOOK];

NoteBook *books[MAX_BOOKS];
uint32_t active = 0;

static int rdi()
{
    int v;
    if (!(cin >> v))
        exit(0);
    return v;
}
static uint64_t rdu()
{
    uint64_t v;
    if (!(cin >> v))
        exit(0);
    return v;
}

static bool have(uint32_t a) { return a < MAX_BOOKS && books[a]; }

static void cmd_switch_book()
{
    cout << "Book: ";
    uint32_t idx;
    cin >> idx;
    if (idx >= MAX_BOOKS)
    {
        cout << "bad idx\n";
        return;
    }
    if (!books[idx])
    {
        books[idx] = (NoteBook *)cage.alloc(sizeof(NoteBook));
        if (!books[idx])
        {
            cout << "alloc failed\n";
            return;
        }
        memset(books[idx], 0, sizeof(NoteBook));
    }
    active = idx;
    cout << "active book " << active << "\n";
}

static void cmd_write_note()
{
    if (!have(active))
    {
        cout << "no book\n";
        return;
    }
    cout << "slot: ";
    int slot = rdi();
    if (slot < 0 || slot >= NOTES_PER_BOOK)
    {
        cout << "bad slot\n";
        return;
    }

    Note *n = &books[active]->notes[slot];
    if (n->data)
    {
        cout << "slot used\n";
        return;
    }

    cout << "size: ";
    uint64_t sz = rdu();
    if (sz == 0)
    {
        cout << "bad size\n";
        return;
    }

    n->size = sz;
    n->data = cage.alloc(sz);
    if (!n->data)
    {
        n->size = 0;
        cout << "alloc failed\n";
        return;
    }

    cout << "data: ";
    int r = read(0, n->data, sz);
    if (r < 0)
        cout << "(read failed)\n";
}

static void cmd_read_note()
{
    if (!have(active))
    {
        cout << "no book\n";
        return;
    }
    cout << "slot: ";
    int slot = rdi();
    if (slot < 0 || slot >= NOTES_PER_BOOK)
    {
        cout << "bad slot\n";
        return;
    }

    Note *n = &books[active]->notes[slot];
    if (!n->data)
    {
        cout << "empty\n";
        return;
    }

    write(1, n->data, n->size);
    cout << "\n";
}

__attribute__((used)) static void cmd_edit_note()
{
    if (!have(active))
    {
        cout << "no book\n";
        return;
    }
    cout << "slot: ";
    int slot = rdi();
    if (slot < 0 || slot >= NOTES_PER_BOOK)
    {
        cout << "bad slot\n";
        return;
    }

    Note *n = &books[active]->notes[slot];
    if (!n->data)
    {
        cout << "empty\n";
        return;
    }

    cout << "data: ";
    int r = read(0, n->data, n->size);
    if (r < 0)
        cout << "(read failed)\n";
}

static void cmd_erase_note()
{
    if (!have(active))
    {
        cout << "no book\n";
        return;
    }
    cout << "slot: ";
    int slot = rdi();
    if (slot < 0 || slot >= NOTES_PER_BOOK)
    {
        cout << "bad slot\n";
        return;
    }

    Note *n = &books[active]->notes[slot];
    if (!n->data)
    {
        cout << "empty\n";
        return;
    }

    cage.release(n->data);
    n->data = nullptr;
}

static void cmd_discard_book()
{
    if (!have(active))
    {
        cout << "no book\n";
        return;
    }
    for (int i = 0; i < NOTES_PER_BOOK; i++)
        if (books[active]->notes[i].data)
        {
            cout << "notes not empty\n";
            return;
        }
    cage.release(books[active]);
    books[active] = nullptr;
}

static void cmd_tag_note()
{
    if (!have(active))
    {
        cout << "no book\n";
        return;
    }
    cout << "slot: ";
    int slot = rdi();
    if (slot < 0 || slot >= NOTES_PER_BOOK)
    {
        cout << "bad slot\n";
        return;
    }
    cout << "tag: ";
    note_tags[active][slot] = rdu();
}

int main()
{
    setvbuf(stdin, nullptr, _IONBF, 0);
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    cout << "=== Note Book ===\n"
            "0:switch  1:write  2:read  3:erase  4:discard  5:tag  6:exit\n";

    while (true)
    {
        cout << "cmd > ";
        int c = rdi();
        switch (c)
        {
        case 0:
            cmd_switch_book();
            break;
        case 1:
            cmd_write_note();
            break;
        case 2:
            cmd_read_note();
            break;
        case 3:
            cmd_erase_note();
            break;
        case 4:
            cmd_discard_book();
            break;
        case 5:
            cmd_tag_note();
            break;
        case 6:
            return 0;
        default:
            cout << "?\n";
        }
    }
}