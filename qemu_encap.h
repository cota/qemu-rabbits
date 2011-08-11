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
};

struct cacheline_desc {
    int			cpu;
    unsigned long	tag;
    int			idx;
};

static inline int
__cache_hit(int n, struct cacheline_entry (*cache)[n], struct cacheline_desc *line)
{
    return cache[line->cpu][line->idx].tag == line->tag;
}

static inline int
dcache_hit(struct cacheline_entry (*cache)[DCACHE_LINES], struct cacheline_desc *line)
{
    return __cache_hit(DCACHE_LINES, cache, line);
}

static inline int
icache_hit(struct cacheline_entry (*cache)[ICACHE_LINES], struct cacheline_desc *line)
{
    return __cache_hit(ICACHE_LINES, cache, line);
}

static inline void
__cache_refresh(int n, struct cacheline_entry (*cache)[n], struct cacheline_desc *line)
{
    cache[line->cpu][line->idx].tag = line->tag;
}

static inline void
dcache_refresh(struct cacheline_entry (*cache)[DCACHE_LINES], struct cacheline_desc *line)
{
    __cache_refresh(DCACHE_LINES, cache, line);
}

static inline void
icache_refresh(struct cacheline_entry (*cache)[ICACHE_LINES], struct cacheline_desc *line)
{
    __cache_refresh(ICACHE_LINES, cache, line);
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
    struct cacheline_entry  (*cpu_cache)[DCACHE_LINES];
    struct cacheline        (*cpu_cache_data)[DCACHE_LINES];
#else
    struct cacheline_entry  (*cpu_dcache)[DCACHE_LINES];
    struct cacheline_entry  (*cpu_icache)[ICACHE_LINES];
    struct cacheline        (*cpu_dcache_data)[DCACHE_LINES];
    struct cacheline        (*cpu_icache_data)[ICACHE_LINES];
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

