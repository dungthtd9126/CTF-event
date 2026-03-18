#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

typedef uint32_t ref_t;
typedef struct {
    uint16_t length;
    uint16_t mark_word; // LSB marks whether it contains pointers
    ref_t entries[];
} arr_header_t;

typedef struct {
    arr_header_t header;
    uint32_t *data;
    size_t obj_size;
} off_heap_obj_t;

#define OFF_HEAP_OBJ_LEN ((sizeof(off_heap_obj_t) - sizeof(arr_header_t))/sizeof(ref_t))

#define CONTAINS_REFERENCES_FLAG 0x1
#define REACHABLE_FLAG 0x2
#define OFF_HEAP_FLAG 0x4

char *heap_base;
size_t heap_size; // grow as needed
size_t heap_used;

void init_heap(size_t initial_size) {
    heap_base = mmap(NULL, 0x100000000LL, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // now, map the initial heap region
    mprotect(heap_base, initial_size, PROT_READ | PROT_WRITE);
    memset(heap_base, 0, initial_size);
    heap_size = initial_size;
    heap_used = 128; // reserve first 128 bytes for fun
}

void uninit_heap() {
    munmap(heap_base, 0x100000000LL);
}

void garbage_collect(ref_t *roots, size_t num_roots);

ref_t alloc_array(uint16_t length, bool contains_pointers) {
    size_t total_size = sizeof(arr_header_t) + length * sizeof(ref_t);
    if (heap_used + total_size > heap_size) {
        // grow heap
        size_t new_size = heap_size * 2;
        while (heap_used + total_size > new_size) {
            new_size *= 2;
        }
        mprotect(heap_base + heap_size, new_size - heap_size, PROT_READ | PROT_WRITE);
        heap_size = new_size;
    }
    ref_t arr_ref = (ref_t)heap_used;
    arr_header_t *arr = (arr_header_t *)(heap_base + arr_ref);
    arr->length = length;
    arr->mark_word = contains_pointers ? 1 : 0; // LSB marks whether it contains pointers
    memset(arr->entries, 0, length * sizeof(ref_t));
    heap_used += total_size;
    return arr_ref;
}

ref_t alloc_off_heap(size_t obj_size) {
    size_t total_size = sizeof(off_heap_obj_t) + obj_size * sizeof(uint32_t);
    if (heap_used + total_size > heap_size) {
        // grow heap
        size_t new_size = heap_size * 2;
        while (heap_used + total_size > new_size) {
            new_size *= 2;
        }
        mprotect(heap_base + heap_size, new_size - heap_size, PROT_READ | PROT_WRITE);
        heap_size = new_size;
    }
    ref_t arr_ref = (ref_t)heap_used;
    off_heap_obj_t *obj = (off_heap_obj_t *)(heap_base + arr_ref);
    obj->header.length = OFF_HEAP_OBJ_LEN;
    obj->header.mark_word = OFF_HEAP_FLAG; // mark as off-heap
    obj->obj_size = obj_size;
    obj->data = calloc(obj_size, sizeof(uint32_t));
    heap_used += total_size;
    return arr_ref;
}

#define AS_ARR_HEADER(ref) ((arr_header_t *)(heap_base + (ref)))
#define AS_OFF_HEAP_OBJ(ref) ((off_heap_obj_t *)(heap_base + (ref)))
#define IS_OFF_HEAP(ref) (AS_ARR_HEADER(ref)->mark_word & OFF_HEAP_FLAG)

typedef struct {
    ref_t object;
    size_t size;
} sized_object;

typedef struct gc_ctx {
    sized_object *objs;
    size_t obj_count;
    ref_t *new_locations;
} gc_ctx_t;

static void mark_reachable(ref_t ref, gc_ctx_t *visited) {
    arr_header_t *arr = AS_ARR_HEADER(ref);
    if (arr->mark_word & 0x2) { // already marked
        return;
    }
    arr->mark_word |= 0x2; // mark it
    // add to visited list
    visited->objs = realloc(visited->objs, sizeof(sized_object) * (visited->obj_count + 1));
    visited->objs[visited->obj_count++] = (sized_object){ .object = ref, .size = arr->length };
    if (arr->mark_word & 1) { // contains pointers
        for (uint16_t i = 0; i < arr->length; i++) {
            ref_t entry = arr->entries[i];
            if (entry != 0) // skip null pointers
                mark_reachable(entry, visited);
        }
    }
}

static int compare_sized_objects(const void *a, const void *b) {
    const sized_object *ref_a = (const sized_object *)a;
    const sized_object *ref_b = (const sized_object *)b;
    return (ref_a->object > ref_b->object) - (ref_a->object < ref_b->object);
}

void garbage_collect(ref_t *roots, size_t num_roots) {
    // Simple mark-and-sweep garbage collector
    // mark phase
    gc_ctx_t ctx = {0};
    for (size_t i = 0; i < num_roots; i++) {
        mark_reachable(roots[i], &ctx);
    }
    // sort the pointers so we can compact the heap
    qsort(ctx.objs, ctx.obj_count, sizeof(sized_object),
          (int (*)(const void *, const void *))compare_sized_objects);
    
    // create lookup table for new locations
    ctx.new_locations = malloc(sizeof(ref_t) * ctx.obj_count);
    // copy objects to new locations
    size_t new_heap_used = 128; // reserve first 128 bytes
    for (size_t i = 0; i < ctx.obj_count; i++) {
        arr_header_t *arr = AS_ARR_HEADER(ctx.objs[i].object);
        arr->mark_word &= ~0x2; // unmark for next GC
        size_t total_size = sizeof(arr_header_t) + ctx.objs[i].size * sizeof(ref_t);
        memmove(heap_base + new_heap_used, arr, total_size);
        ctx.new_locations[i] = (ref_t)new_heap_used;
        new_heap_used += total_size;
    }

    // update pointers on heap
    for (size_t i = 0; i < ctx.obj_count; i++) {
        arr_header_t *arr = AS_ARR_HEADER(ctx.new_locations[i]);
        if (arr->mark_word & 1) { // contains pointers
            for (uint16_t j = 0; j < arr->length; j++) {
                // binary search for new location
                ref_t old_ref = arr->entries[j];
                ref_t new_ref;
                if (old_ref == 0) {
                    new_ref = 0; // null pointer
                } else {
                    sized_object search_key = { .object = old_ref };
                    sized_object *found = bsearch(&search_key, ctx.objs, ctx.obj_count,
                                        sizeof(sized_object), compare_sized_objects);
                    new_ref = ctx.new_locations[found - ctx.objs];
                }
                arr->entries[j] = new_ref;
            }
        }
    }
    // update pointers in roots
    for (size_t i = 0; i < num_roots; i++) {
        ref_t old_ref = roots[i];
        ref_t new_ref;
        if (old_ref == 0) {
            new_ref = 0; // null pointer
        } else {
            sized_object search_key = { .object = old_ref };
            sized_object *found = bsearch(&search_key, ctx.objs, ctx.obj_count,
                                sizeof(sized_object), compare_sized_objects);
            new_ref = ctx.new_locations[found - ctx.objs];
        }
        roots[i] = new_ref;
    }

    heap_used = new_heap_used;
    free(ctx.objs);
    free(ctx.new_locations);
}

// GARDEN VM

typedef enum {
    PUSH_NUM_ARRAY, ADD_NUMS, SUB_NUMS, MUL_NUMS, DIV_NUMS, MOD_NUMS,
    GET_ELEM_OBJ, SET_ELEM_OBJ, GET_ELEM_NUM, SET_ELEM_NUM, PRINT_NUM_ARRAY,
    GET_OFFHEAP_NUM, SET_OFFHEAP_NUM,
    NEW_ARRAY_OBJ, NEW_ARRAY_NUM, NEW_OFFHEAP_OBJ,
    DUP, SWAP, DROP, DUP_X1,
    GARBAGE_COLLECT
} opcode_t;

ref_t *stack;
size_t sp = 0;
size_t stack_size;

void init_stack(size_t initial_size) {
    sp = 0;
    stack_size = initial_size;
    stack = calloc(stack_size, sizeof(ref_t));
}

void push(ref_t val) {
    if (sp >= stack_size) {
        stack_size *= 2;
        stack = realloc(stack, stack_size * sizeof(ref_t));
    }
    stack[sp++] = val;
}

ref_t pop() {
    if (sp == 0) {
        printf("Stack underflow\n");
        exit(1);
    }
    return stack[--sp];
}

uint32_t *insn_buf;
size_t ip = 0;
size_t insn_buf_size;

uint32_t next_insn_word() {
    if (ip >= insn_buf_size) {
        printf("Instruction pointer out of bounds\n");
        exit(1);
    }
    return insn_buf[ip++];
}

bool has_next_insn() {
    return ip < insn_buf_size;
}

#define REQUIRE_ON_HEAP(arr_header) \
    do { \
        if ((arr_header->mark_word & OFF_HEAP_FLAG) != 0) { \
            printf("Operation on off-heap object not supported\n"); \
            exit(1); \
        } \
    } while (0)

#define REQUIRE_NUMERIC(arr_header) \
    do { \
        if ((arr_header->mark_word & CONTAINS_REFERENCES_FLAG) != 0) { \
            printf("Operation on non-numeric array not supported\n"); \
            exit(1); \
        } \
    } while (0)

#define REQUIRE_NON_NUMERIC(arr_header) \
    do { \
        if ((arr_header->mark_word & CONTAINS_REFERENCES_FLAG) == 0) { \
            printf("Operation on numeric array not supported\n"); \
            exit(1); \
        } \
    } while (0)

void interpret() {
    while (has_next_insn()) {
        uint32_t insn_word = next_insn_word();
        if (insn_word < PUSH_NUM_ARRAY || insn_word > GARBAGE_COLLECT) {
            printf("Invalid instruction word: %u\n", insn_word);
            exit(1);
        }
        opcode_t op = (opcode_t)insn_word;
        // the insn PUSH_NUM_ARRAY
        // is followed by operands in the instruction stream
        switch (op) {
            case PUSH_NUM_ARRAY: {
                uint16_t length = (uint16_t)next_insn_word();
                ref_t arr_ref = alloc_array(length, false);
                arr_header_t *arr = AS_ARR_HEADER(arr_ref);
                for (uint16_t i = 0; i < length; i++) {
                    arr->entries[i] = next_insn_word();
                }
                push(arr_ref);
            } break;
            case ADD_NUMS: {
                arr_header_t *b = AS_ARR_HEADER(pop());
                arr_header_t *a = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(a);
                REQUIRE_ON_HEAP(b);
                REQUIRE_NUMERIC(a);
                REQUIRE_NUMERIC(b);
                if (a->length != b->length) {
                    printf("ADD_NUMS on arrays of different lengths\n");
                    exit(1);
                }
                ref_t res_ref = alloc_array(a->length, false);
                arr_header_t *res = AS_ARR_HEADER(res_ref);
                for (uint16_t i = 0; i < a->length; i++) {
                    res->entries[i] = a->entries[i] + b->entries[i];
                }
                push(res_ref);
            } break;
            case SUB_NUMS: {
                arr_header_t *b = AS_ARR_HEADER(pop());
                arr_header_t *a = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(a);
                REQUIRE_ON_HEAP(b);
                REQUIRE_NUMERIC(a);
                REQUIRE_NUMERIC(b);
                if (a->length != b->length) {
                    printf("SUB_NUMS on arrays of different lengths\n");
                    exit(1);
                }
                ref_t res_ref = alloc_array(a->length, false);
                arr_header_t *res = AS_ARR_HEADER(res_ref);
                for (uint16_t i = 0; i < a->length; i++) {
                    res->entries[i] = a->entries[i] - b->entries[i];
                }
                push(res_ref);
            } break;
            case MUL_NUMS: {
                arr_header_t *b = AS_ARR_HEADER(pop());
                arr_header_t *a = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(a);
                REQUIRE_ON_HEAP(b);
                REQUIRE_NUMERIC(a);
                REQUIRE_NUMERIC(b);
                if (a->length != b->length) {
                    printf("MUL_NUMS on arrays of different lengths\n");
                    exit(1);
                }
                ref_t res_ref = alloc_array(a->length, false);
                arr_header_t *res = AS_ARR_HEADER(res_ref);
                for (uint16_t i = 0; i < a->length; i++) {
                    res->entries[i] = a->entries[i] * b->entries[i];
                }
                push(res_ref);
            } break;
            case DIV_NUMS: {
                arr_header_t *b = AS_ARR_HEADER(pop());
                arr_header_t *a = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(a);
                REQUIRE_ON_HEAP(b);
                REQUIRE_NUMERIC(a);
                REQUIRE_NUMERIC(b);
                if (a->length != b->length) {
                    printf("DIV_NUMS on arrays of different lengths\n");
                    exit(1);
                }
                ref_t res_ref = alloc_array(a->length, false);
                arr_header_t *res = AS_ARR_HEADER(res_ref);
                for (uint16_t i = 0; i < a->length; i++) {
                    if (b->entries[i] == 0) {
                        printf("Division by zero in DIV_NUMS\n");
                        exit(1);
                    }
                    res->entries[i] = a->entries[i] / b->entries[i];
                }
                push(res_ref);
            } break;
            case MOD_NUMS: {
                arr_header_t *b = AS_ARR_HEADER(pop());
                arr_header_t *a = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(a);
                REQUIRE_ON_HEAP(b);
                REQUIRE_NUMERIC(a);
                REQUIRE_NUMERIC(b);
                if (a->length != b->length) {
                    printf("MOD_NUMS on arrays of different lengths\n");
                    exit(1);
                }
                ref_t res_ref = alloc_array(a->length, false);
                arr_header_t *res = AS_ARR_HEADER(res_ref);
                for (uint16_t i = 0; i < a->length; i++) {
                    if (b->entries[i] == 0) {
                        printf("Division by zero in MOD_NUMS\n");
                        exit(1);
                    }
                    res->entries[i] = a->entries[i] % b->entries[i];
                }
                push(res_ref);
            } break;
            case GET_ELEM_OBJ: {
                arr_header_t *index = AS_ARR_HEADER(pop());
                arr_header_t *arr = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(index);
                REQUIRE_ON_HEAP(arr);
                REQUIRE_NUMERIC(index);
                REQUIRE_NON_NUMERIC(arr);
                uint32_t idx = index->entries[0];
                if (idx >= arr->length) {
                    printf("GET_ELEM_OBJ index out of bounds\n");
                    exit(1);
                }
                push(arr->entries[idx]);
            } break;
            case SET_ELEM_OBJ: {
                arr_header_t *index = AS_ARR_HEADER(pop());
                ref_t val = pop();
                arr_header_t *arr = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(index);
                REQUIRE_ON_HEAP(arr);
                REQUIRE_NUMERIC(index);
                REQUIRE_NON_NUMERIC(arr);
                uint32_t idx = index->entries[0];
                if (idx >= arr->length) {
                    printf("SET_ELEM_OBJ index out of bounds\n");
                    exit(1);
                }
                arr->entries[idx] = val;
            } break;
            case GET_ELEM_NUM: {
                arr_header_t *index = AS_ARR_HEADER(pop());
                arr_header_t *arr = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(index);
                REQUIRE_ON_HEAP(arr);
                REQUIRE_NUMERIC(index);
                REQUIRE_NUMERIC(arr);
                uint32_t idx = index->entries[0];
                if (idx >= arr->length) {
                    printf("GET_ELEM_NUM index out of bounds\n");
                    exit(1);
                }
                ref_t new_num = alloc_array(1, false);
                arr_header_t *num_arr = AS_ARR_HEADER(new_num);
                num_arr->entries[0] = arr->entries[idx];
                push(new_num);
            } break;
            case SET_ELEM_NUM: {
                arr_header_t *index = AS_ARR_HEADER(pop());
                arr_header_t *value = AS_ARR_HEADER(pop());
                arr_header_t *arr = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(value);
                REQUIRE_ON_HEAP(index);
                REQUIRE_ON_HEAP(arr);
                REQUIRE_NUMERIC(value);
                REQUIRE_NUMERIC(index);
                REQUIRE_NUMERIC(arr);
                uint32_t idx = index->entries[0];
                if (idx >= arr->length) {
                    printf("SET_ELEM_NUM index out of bounds\n");
                    exit(1);
                }
                uint32_t val = value->entries[0];
                arr->entries[idx] = val;
            } break;
            case PRINT_NUM_ARRAY: {
                arr_header_t *arr = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(arr);
                REQUIRE_NUMERIC(arr);
                printf("Numeric array of length %d: [", arr->length);
                for (uint16_t i = 0; i < arr->length; i++) {
                    printf("%u", arr->entries[i]);
                    if (i < arr->length - 1) {
                        printf(", ");
                    }
                }
                printf("]\n");
            } break;
            case GET_OFFHEAP_NUM: {
                arr_header_t *index = AS_ARR_HEADER(pop());
                ref_t off_heap_ref = pop();
                if (!IS_OFF_HEAP(off_heap_ref)) {
                    printf("GET_OFFHEAP_NUM on non-off-heap object\n");
                    exit(1);
                }
                off_heap_obj_t *arr = AS_OFF_HEAP_OBJ(off_heap_ref);
                REQUIRE_ON_HEAP(index);
                REQUIRE_NUMERIC(index);
                uint32_t idx = index->entries[0];
                if (idx >= arr->obj_size) {
                    printf("GET_OFFHEAP_NUM index out of bounds\n");
                    exit(1);
                }
                ref_t new_num = alloc_array(1, false);
                arr_header_t *num_arr = AS_ARR_HEADER(new_num);
                num_arr->entries[0] = arr->data[idx];
                push(new_num);
            } break;
            case SET_OFFHEAP_NUM: {
                arr_header_t *index = AS_ARR_HEADER(pop());
                arr_header_t *value = AS_ARR_HEADER(pop());
                ref_t off_heap_ref = pop();
                if (!IS_OFF_HEAP(off_heap_ref)) {
                    printf("SET_OFFHEAP_NUM on non-off-heap object\n");
                    exit(1);
                }
                off_heap_obj_t *arr = AS_OFF_HEAP_OBJ(off_heap_ref);
                REQUIRE_ON_HEAP(value);
                REQUIRE_ON_HEAP(index);
                REQUIRE_NUMERIC(value);
                REQUIRE_NUMERIC(index);
                uint32_t idx = index->entries[0];
                if (idx >= arr->obj_size) {
                    printf("SET_OFFHEAP_NUM index out of bounds\n");
                    exit(1);
                }
                uint32_t val = value->entries[0];
                arr->data[idx] = val;
            } break;
            case NEW_ARRAY_OBJ: {
                arr_header_t *length = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(length);
                REQUIRE_NUMERIC(length);
                ref_t arr_ref = alloc_array(length->entries[0], true);
                push(arr_ref);
            } break;
            case NEW_ARRAY_NUM: {
                arr_header_t *length = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(length);
                REQUIRE_NUMERIC(length);
                ref_t arr_ref = alloc_array(length->entries[0], false);
                push(arr_ref);
            } break;
            case NEW_OFFHEAP_OBJ: {
                arr_header_t *size = AS_ARR_HEADER(pop());
                REQUIRE_ON_HEAP(size);
                REQUIRE_NUMERIC(size);
                ref_t off_heap_ref = alloc_off_heap(size->entries[0]);
                push(off_heap_ref);
            } break;
            case DUP: {
                ref_t a = pop();
                push(a);
                push(a);
            } break;
            case SWAP: {
                ref_t a = pop();
                ref_t b = pop();
                push(a);
                push(b);
            } break;
            case DROP: {
                (void)pop();
            } break;
            case DUP_X1: {
                ref_t a = pop();
                ref_t b = pop();
                push(a);
                push(b);
                push(a);
            } break;
            case GARBAGE_COLLECT: {
                garbage_collect(stack, sp); // use entire stack as roots
            } break;
            default:
                printf("Unknown opcode: %d\n", op);
                exit(1);
        }
    }
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    init_heap(4096); // 4KB initial heap
    init_stack(1024); // stack with 1024 entries

    printf("Garden VM\n");
    printf("Enter instruction buffer size (number of 32-bit words): ");
    size_t buf_size;
    scanf("%zu", &buf_size);
    insn_buf_size = buf_size;
    insn_buf = calloc(insn_buf_size, sizeof(uint32_t));
    printf("Enter %zu instruction words (as unsigned integers):\n", buf_size);
    for (size_t i = 0; i < buf_size; i++) {
        scanf("%u", &insn_buf[i]);
    }

    printf("Starting interpretation\n");
    interpret();

    printf("Done\n");

    uninit_heap();
    return 0;
}
