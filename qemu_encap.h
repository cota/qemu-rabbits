#ifndef _QEMU_ENCAP_
#define _QEMU_ENCAP_

#include "qemu_systemc.h"
#include "systemc_imports.h"

struct GDBState;

struct cacheline {
    uint8_t	data[CACHE_LINE_BYTES];
};

struct set_mutex {
    int locked;
    int cpu;
};

/*
 * Types of cache line entries
 */
#define QEMU_CACHE_NONE	0
#define QEMU_CACHE_DATA	1
#define QEMU_CACHE_INST	2

struct cacheline_entry {
    unsigned long	tag;
    int8_t		age;
    int8_t		type;
    int8_t		dirty;
};

/*
 * Use -1 for an unknown way, to be retrieved by the helpers below.
 * @grp: on L1, denotes CPU; on L2; denotes bank.
 */
struct cacheline_desc {
    unsigned long	tag;
    int			idx;
    int8_t		grp;
    int8_t		way;
};

static inline void print_cacheline_desc(const struct cacheline_desc *desc)
{
    printf("cl %p: grp %d way %2d tag 0x%08lx idx 0x%x\n",
	   desc, desc->grp, desc->way, desc->tag, desc->idx);
}

static inline void print_cacheline(const struct cacheline *line)
{
    uint32_t *data = (uint32_t *)&line->data[0];
    int i;

    printf("(");
    for (i = 0; i < CACHE_LINE_u32s; i++) {
        printf("0x%08x%s", data[i], i == CACHE_LINE_BYTES - 4 ? "" : ",");
    }
    printf(")\n");
}

static inline int
entry_match(const struct cacheline_entry *entry, unsigned long tag, int type)
{
    return entry->tag == tag && entry->type == type;
}

/*
 * Cache Read/Write rationale
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Read hit : call __lru_update().
 * Read miss: __lru_update() not called in __cache_hit(), no eviction
 *   necessary since we do write-through. LRU is done in __cache_refresh(),
 *   where line->way is updated.
 *
 * Write hit: __lru_update() called.
 * Write miss: __lru_update() not called, since we directly commit the
 *   partial write of the line to memory. Subsequent reads would miss and
 *   fetch the complete line--see rationale behind reads above.
 */


/* Note: line->way must be properly set upon calling this function */
static inline void
__lru_update(int n, int n_ways, struct cacheline_entry (*cache)[n][n_ways],
             const struct cacheline_desc *desc)
{
    struct cacheline_entry *mru_entry;
    int way;

    if (desc->way == -1)
	printf("warning: %s: desc->way == -1\n", __func__);

    mru_entry = &cache[desc->grp][desc->idx][desc->way];

    for (way = 0; way < n_ways; way++) {
	struct cacheline_entry *entry = &cache[desc->grp][desc->idx][way];

	if (entry->age < mru_entry->age)
	    entry->age++;
    }
    mru_entry->age = 0;
}

static inline int
__lru_find(int n, int n_ways, struct cacheline_entry (*cache)[n][n_ways],
           const struct cacheline_desc *desc)
{
    int oldest_so_far = 0;
    int oldest_way = 0;
    int way;

    for (way = 0; way < n_ways; way++) {
	struct cacheline_entry *entry = &cache[desc->grp][desc->idx][way];

	if (entry->age > oldest_so_far) {
	    oldest_so_far = entry->age;
	    oldest_way = way;
	}
    }
    if (oldest_so_far != n_ways - 1) {
	printf("%s: oldest cacheline seen of age %d on grp%d idx %d\n",
	      __func__, oldest_so_far, desc->grp, desc->idx);
    }
    return oldest_way;
}

/*
 * "Turn in" a line so that it becomes the LRU.
 * Normally this function is called BEFORE invalidating a line.
 * NOTE: desc->way must be properly set upon calling this function.
 */
static inline void
__lru_turn_in(int n, int n_ways, struct cacheline_entry (*cache)[n][n_ways],
              struct cacheline_desc *desc)
{
    struct cacheline_entry *lru_entry;
    int way;

    if (desc->way == -1)
	printf("warning: %s: desc->way == unknown\n", __func__);

    lru_entry = &cache[desc->grp][desc->idx][desc->way];

    for (way = 0; way < n_ways; way++) {
	struct cacheline_entry *entry = &cache[desc->grp][desc->idx][way];

	if (entry->age > lru_entry->age)
	    entry->age--;
    }
    lru_entry->age = n_ways - 1;
}

static inline void
__cache_invalidate(int n, int n_ways, struct cacheline_entry (*cache)[n][n_ways],
                   struct cacheline_desc *desc)
{
#ifdef DEBUG
    printf("inv : ");
    print_cacheline_desc(desc);
#endif
    __lru_turn_in(n, n_ways, cache, desc);
    cache[desc->grp][desc->idx][desc->way].tag = ~0;
    cache[desc->grp][desc->idx][desc->way].type = QEMU_CACHE_NONE;
}

static inline void
dcache_invalidate(struct cacheline_entry (*cache)[DCACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    return __cache_invalidate(DCACHE_LPS, CACHE_WAYS, cache, desc);
}

static inline void
icache_invalidate(struct cacheline_entry (*cache)[ICACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    return __cache_invalidate(ICACHE_LPS, CACHE_WAYS, cache, desc);
}

/*
 * We first iterate over all the ways for the tag.
 * If we find the matching entry, desc->way is updated and 1 is returned.
 * Otherwise return 0.
 */
static inline int
__cache_hit(int n, int n_ways, struct cacheline_entry (*cache)[n][n_ways],
            struct cacheline_desc *desc, int type, int update)
{
    int way;

    for (way = 0; way < n_ways; way++) {
	struct cacheline_entry *entry = &cache[desc->grp][desc->idx][way];

	if (entry_match(entry, desc->tag, type)) {
	    desc->way = way;
	    if (update)
		__lru_update(n, n_ways, cache, desc);
#ifdef DEBUG
	    printf("hit : ");
	    print_cacheline_desc(desc);
#endif
	    return 1;
	}
    }
#ifdef DEBUG
    printf("miss: ");
    print_cacheline_desc(desc);
#endif
    return 0;
}

static inline int
dcache_hit(struct cacheline_entry (*cache)[DCACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    return __cache_hit(DCACHE_LPS, CACHE_WAYS, cache, desc, QEMU_CACHE_DATA, 1);
}

static inline int
dcache_hit_no_update(struct cacheline_entry (*cache)[DCACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    return __cache_hit(DCACHE_LPS, CACHE_WAYS, cache, desc, QEMU_CACHE_DATA, 0);
}

static inline int
icache_hit(struct cacheline_entry (*cache)[ICACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    return __cache_hit(ICACHE_LPS, CACHE_WAYS, cache, desc, QEMU_CACHE_INST, 1);
}

static inline int
icache_hit_no_update(struct cacheline_entry (*cache)[ICACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    return __cache_hit(ICACHE_LPS, CACHE_WAYS, cache, desc, QEMU_CACHE_INST, 0);
}

static inline int
l2d_hit(struct cacheline_entry (*cache)[L2_LPS][L2_WAYS],
        struct cacheline_desc *desc)
{
#ifdef DEBUG
    printf("l2d ");
#endif
    return __cache_hit(L2_LPS, L2_WAYS, cache, desc, QEMU_CACHE_DATA, 1);
}

/*
 * We then find a suitable way, update the caller's descriptor with it, and
 * update our corresponding cache entry.
 */
static inline void
__cache_refresh(int n, int n_ways, struct cacheline_entry (*cache)[n][n_ways],
                struct cacheline_desc *desc, int type, int valid)
{
    struct cacheline_entry *entry;

    if (!valid) {
        if (desc->way != -1)
            printf("warning: %s: invalid way value: (%d) != -1\n", __func__, desc->way);
        desc->way = __lru_find(n, n_ways, cache, desc);
    }

    entry = &cache[desc->grp][desc->idx][desc->way];
    entry->tag = desc->tag;
    entry->type = type;
    __lru_update(n, n_ways, cache, desc);
}

static inline void
dcache_refresh(struct cacheline_entry (*cache)[DCACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    __cache_refresh(DCACHE_LPS, CACHE_WAYS, cache, desc, QEMU_CACHE_DATA, 0);
}

static inline void
icache_refresh(struct cacheline_entry (*cache)[ICACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    __cache_refresh(ICACHE_LPS, CACHE_WAYS, cache, desc, QEMU_CACHE_INST, 0);
}

static inline void
l2d_refresh(struct cacheline_entry (*cache)[L2_LPS][L2_WAYS], struct cacheline_desc *desc)
{
    __cache_refresh(L2_LPS, L2_WAYS, cache, desc, QEMU_CACHE_DATA, 0);
}

static inline void
l2d_refresh_way(struct cacheline_entry (*cache)[L2_LPS][L2_WAYS], struct cacheline_desc *desc)
{
    __cache_refresh(L2_LPS, L2_WAYS, cache, desc, QEMU_CACHE_DATA, 1);
}

static inline void __l2_set_dirty(struct cacheline_entry (*cache)[L2_LPS][L2_WAYS],
                                  const struct cacheline_desc *desc, int val)
{
    struct cacheline_entry *entry;

    entry = &cache[desc->grp][desc->idx][desc->way];
    entry->dirty = val;
}

/*
 * Do not access cpu_{d,i}{cache,cache_data} directly; use the qi_* accessors
 * defined below.
 */
typedef struct 
{
    int                     id;
    int                     NOCPUs;
    struct cacheline_entry  (*cpu_dcache)	[DCACHE_LPS][CACHE_WAYS];
    struct cacheline_entry  (*cpu_icache)	[ICACHE_LPS][CACHE_WAYS];
    struct cacheline        (*cpu_dcache_data)	[DCACHE_LPS][CACHE_WAYS];
    struct cacheline        (*cpu_icache_data)	[ICACHE_LPS][CACHE_WAYS];
    struct cacheline_entry  (*l2_cache)		[L2_LPS][L2_WAYS];
    struct cacheline	    (*l2_cache_data)	[L2_LPS][L2_WAYS];
    struct set_mutex        mem_lock;
    void                    **irqs_systemc;

    void                    *first_cpu;
    void                    **envs;
    int                     io_mem_nb;
    void                    *io_mem_write;
    void                    *io_mem_read;
    void                    *io_mem_opaque;
    int                     io_mem_watch;
    void                    *ioport_opaque;
    void                    *ioport_read_table;
    void                    *ioport_write_table;
    void                    *l1_map;
    void                    **l1_phys_map;
    int                     nb_tbs;
    unsigned char           *phys_ram_dirty;
    int                     ram_size;
    void                    *tb_phys_hash;
    void                    *tbs;
    uint8_t                 code_gen_buffer[CODE_GEN_BUFFER_SIZE];
    uint8_t                 *code_gen_ptr;
    unsigned long           init_point_1;
    unsigned long           flush_head;

    struct GDBState         *gdb;

    struct systemc_import_t systemc;

    //log
    FILE                    *fim;
    FILE                    *fdm;
    unsigned long           log_cnt_instr;
    unsigned long           log_cnt_data;
} qemu_instance;

#define qi_dcache(qi)	((qi)->cpu_dcache)
#define qi_dcache_data(qi)	((qi)->cpu_dcache_data)
#define qi_icache(qi)	((qi)->cpu_icache)
#define qi_icache_data(qi)	((qi)->cpu_icache_data)

extern qemu_instance        *crt_qemu_instance;

#endif

