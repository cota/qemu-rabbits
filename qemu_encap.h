#ifndef _QEMU_ENCAP_
#define _QEMU_ENCAP_

#include "qemu_systemc.h"
#include "systemc_imports.h"

struct GDBState;

struct cacheline {
    uint8_t	data[CACHE_LINE_BYTES];
};

struct cacheline_entry {
    unsigned long	tag;
    int			age;
};

/* Use -1 for an unknown way, to be retrieved by the helpers below. */
struct cacheline_desc {
    int			cpu;
    unsigned long	tag;
    int			idx;
    int			way;
};

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
__lru_update(int n, struct cacheline_entry (*cache)[n][CACHE_WAYS], struct cacheline_desc *desc)
{
    int age;
    int way;

    for (way = 0; way < CACHE_WAYS; way++) {
	struct cacheline_entry *entry = &cache[desc->cpu][desc->idx][way];

	if (entry->tag == desc->tag) {
	    age = entry->age;
	    break;
	}
    }

    for (way = 0; way < CACHE_WAYS; way++) {
	struct cacheline_entry *entry = &cache[desc->cpu][desc->idx][way];

	if (entry->tag == desc->tag) {
	    entry->age = 0;
	    continue;
	}
	if (entry->age < age)
	    entry->age++;
    }
}

static inline int
__lru_find(int n, struct cacheline_entry (*cache)[n][CACHE_WAYS], struct cacheline_desc *desc)
{
    int oldest_so_far = 0;
    int oldest_way = 0;
    int way;

    for (way = 0; way < CACHE_WAYS; way++) {
	struct cacheline_entry *entry = &cache[desc->cpu][desc->idx][way];

	if (entry->age > oldest_so_far) {
	    oldest_so_far = entry->age;
	    oldest_way = way;
	}
    }
    if (oldest_so_far != CACHE_WAYS - 1) {
	printf("%s: oldest cacheline seen of age %d on cpu%d idx %d\n",
	      __func__, oldest_so_far, desc->cpu, desc->idx);
    }
    return oldest_way;
}

/*
 * "Turn in" a line so that it becomes the LRU.
 * Normally this function is called BEFORE invalidating a line.
 */
static inline void
__lru_turn_in(int n, struct cacheline_entry (*cache)[n][CACHE_WAYS], struct cacheline_desc *desc)
{
    int way;
    int age = -1;

    for (way = 0; way < CACHE_WAYS; way++) {
	struct cacheline_entry *entry = &cache[desc->cpu][desc->idx][way];

	if (entry->tag == desc->tag) {
	    age = entry->age;
	    break;
	}
    }

    if (age == -1)
	printf("%s: could not find valid cacheline", __func__);

    for (way = 0; way < CACHE_WAYS; way++) {
	struct cacheline_entry *entry = &cache[desc->cpu][desc->idx][way];

	if (entry->tag == desc->tag) {
	    entry->age = CACHE_WAYS - 1;
	    continue;
	}
	if (entry->age > age)
	    entry->age--;
    }
}

static inline void
dcache_invalidate(struct cacheline_entry (*cache)[DCACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    __lru_turn_in(DCACHE_LPS, cache, desc);
    cache[desc->cpu][desc->idx][desc->way].tag = ~0;
}

static inline void
icache_invalidate(struct cacheline_entry (*cache)[ICACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    __lru_turn_in(ICACHE_LPS, cache, desc);
    cache[desc->cpu][desc->idx][desc->way].tag = ~0;
}

/*
 * We first iterate over all the ways for the tag.
 * If we find the matching entry, desc->way is updated and 1 is returned.
 * Otherwise return 0.
 */
static inline int
__cache_hit(int n, struct cacheline_entry (*cache)[n][CACHE_WAYS], struct cacheline_desc *desc, int update)
{
    int way;

    for (way = 0; way < CACHE_WAYS; way++) {
	struct cacheline_entry *entry = &cache[desc->cpu][desc->idx][way];

	if (entry->tag == desc->tag) {
	    desc->way = way;
	    if (update)
		__lru_update(n, cache, desc);
	    return 1;
	}
    }
    return 0;
}

static inline int
dcache_hit(struct cacheline_entry (*cache)[DCACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    return __cache_hit(DCACHE_LPS, cache, desc, 1);
}

static inline int
dcache_hit_no_update(struct cacheline_entry (*cache)[DCACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    return __cache_hit(DCACHE_LPS, cache, desc, 0);
}

static inline int
icache_hit(struct cacheline_entry (*cache)[ICACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    return __cache_hit(ICACHE_LPS, cache, desc, 1);
}

static inline int
icache_hit_no_update(struct cacheline_entry (*cache)[ICACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    return __cache_hit(ICACHE_LPS, cache, desc, 0);
}

/*
 * This function is called right after a miss, ie desc->way must be -1.
 * We then find a suitable way, update the caller's descriptor with it, and
 * update our corresponding cache entry.
 */
static inline void
__cache_refresh(int n, struct cacheline_entry (*cache)[n][CACHE_WAYS], struct cacheline_desc *desc)
{
    if (desc->way != -1)
	printf("warning: %s: invalid way value: (%d) != -1\n", __func__, desc->way);

    desc->way = __lru_find(n, cache, desc);

    cache[desc->cpu][desc->idx][desc->way].tag = desc->tag;
    __lru_update(n, cache, desc);
}

static inline void
dcache_refresh(struct cacheline_entry (*cache)[DCACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    __cache_refresh(DCACHE_LPS, cache, desc);
}

static inline void
icache_refresh(struct cacheline_entry (*cache)[ICACHE_LPS][CACHE_WAYS], struct cacheline_desc *desc)
{
    __cache_refresh(ICACHE_LPS, cache, desc);
}


/*
 * Do not access cpu_{d,i}{cache,cache_data} directly; use the qi_* accessors
 * defined below.
 */
typedef struct 
{
    int                     id;
    int                     NOCPUs;
#ifdef IMPLEMENT_COMBINED_CACHE
    struct cacheline_entry  (*cpu_cache)	[DCACHE_LPS][CACHE_WAYS];
    struct cacheline        (*cpu_cache_data)	[DCACHE_LPS][CACHE_WAYS];
#else
    struct cacheline_entry  (*cpu_dcache)	[DCACHE_LPS][CACHE_WAYS];
    struct cacheline_entry  (*cpu_icache)	[ICACHE_LPS][CACHE_WAYS];
    struct cacheline        (*cpu_dcache_data)	[DCACHE_LPS][CACHE_WAYS];
    struct cacheline        (*cpu_icache_data)	[ICACHE_LPS][CACHE_WAYS];
#endif /* IMPLEMENT_COMBINED_CACHE */
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

#ifdef IMPLEMENT_COMBINED_CACHE
#define qi_dcache(qi)	((qi)->cpu_cache)
#define qi_dcache_data(qi)	((qi)->cpu_cache_data)
#define qi_icache(qi)	((qi)->cpu_cache)
#define qi_icache_data(qi)	((qi)->cpu_cache_data)
#else
#define qi_dcache(qi)	((qi)->cpu_dcache)
#define qi_dcache_data(qi)	((qi)->cpu_dcache_data)
#define qi_icache(qi)	((qi)->cpu_icache)
#define qi_icache_data(qi)	((qi)->cpu_icache_data)
#endif /* IMPLEMENT_COMBINED_CACHE */


extern qemu_instance        *crt_qemu_instance;

#endif

