/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <signal.h>
#include "hw/hw.h"

#include "exec-all.h"
#include "cpu.h"
#include "qemu_encap.h"
#include "../../components/qemu_wrapper/qemu_imported.h"
#include "gdb_srv.h"

//#define DEBUG_UNUSED_IOPORT
//#define DEBUG_IOPORT

/* XXX: use a two level table to limit memory usage */
#define MAX_IOPORTS 65536
#define macro_ioport_opaque ((void *(*)) crt_qemu_instance->ioport_opaque)
#define macro_ioport_read_table ((IOPortReadFunc *(*)[MAX_IOPORTS]) crt_qemu_instance->ioport_read_table)
#define macro_ioport_write_table ((IOPortWriteFunc *(*)[MAX_IOPORTS]) crt_qemu_instance->ioport_write_table)

extern CPUState         *cpu_single_env;
qemu_instance           *crt_qemu_instance = NULL;
qemu_instance           *qemu_instances[10];
int                     no_qemu_instances = 0;

void
sigsegv_h (int x)
{
    printf ("SIGSEGV signal received! (%d)\n", x);
    exit (1);
}

void
sigabrt_h (int x)
{
    printf ("SIGABRT signal received! (%d)\n", x);
}

void
sigint_h (int x)
{
    printf ("sigint_h\n");

    if (!start_debug ())
        exit (2);
}

int start_debug (void)
{
    int                 idx, bstart = 0;
    for (idx = 0; idx < no_qemu_instances; idx++)
    {
        if (qemu_instances[idx]->gdb->running_state != STATE_DETACH)
        {
            qemu_instances[idx]->gdb->running_state = STATE_STEP;
            bstart = 1;
        }
    }
    return bstart;
}

static uint32_t default_ioport_readb(void *opaque, uint32_t address)
{
#ifdef DEBUG_UNUSED_IOPORT
    fprintf(stderr, "unused inb: port=0x%04x\n", address);
#endif
    return 0xff;
}

static void default_ioport_writeb(void *opaque, uint32_t address, uint32_t data)
{
#ifdef DEBUG_UNUSED_IOPORT
    fprintf(stderr, "unused outb: port=0x%04x data=0x%02x\n", address, data);
#endif
}

/* default is to make two byte accesses */
static uint32_t default_ioport_readw(void *opaque, uint32_t address)
{
    uint32_t data;
    data = macro_ioport_read_table[0][address](macro_ioport_opaque[address], address);
    address = (address + 1) & (MAX_IOPORTS - 1);
    data |= macro_ioport_read_table[0][address](macro_ioport_opaque[address], address) << 8;
    return data;
}

static void default_ioport_writew(void *opaque, uint32_t address, uint32_t data)
{
    macro_ioport_write_table[0][address](macro_ioport_opaque[address], address, data & 0xff);
    address = (address + 1) & (MAX_IOPORTS - 1);
    macro_ioport_write_table[0][address](macro_ioport_opaque[address], address, (data >> 8) & 0xff);
}

static uint32_t default_ioport_readl(void *opaque, uint32_t address)
{
#ifdef DEBUG_UNUSED_IOPORT
    fprintf(stderr, "unused inl: port=0x%04x\n", address);
#endif
    return 0xffffffff;
}

static void default_ioport_writel(void *opaque, uint32_t address, uint32_t data)
{
#ifdef DEBUG_UNUSED_IOPORT
    fprintf(stderr, "unused outl: port=0x%04x data=0x%02x\n", address, data);
#endif
}

static void init_ioports(void)
{
    int i;

    for(i = 0; i < MAX_IOPORTS; i++) {
        macro_ioport_read_table[0][i] = default_ioport_readb;
        macro_ioport_write_table[0][i] = default_ioport_writeb;
        macro_ioport_read_table[1][i] = default_ioport_readw;
        macro_ioport_write_table[1][i] = default_ioport_writew;
        macro_ioport_read_table[2][i] = default_ioport_readl;
        macro_ioport_write_table[2][i] = default_ioport_writel;
    }
}

/* size is the word size in byte */
int register_ioport_read(int start, int length, int size,
                         IOPortReadFunc *func, void *opaque)
{
    int i, bsize;

    if (size == 1) {
        bsize = 0;
    } else if (size == 2) {
        bsize = 1;
    } else if (size == 4) {
        bsize = 2;
    } else {
        hw_error("register_ioport_read: invalid size");
        return -1;
    }
    for(i = start; i < start + length; i += size) { 
        macro_ioport_read_table[bsize][i] = func;
        if (macro_ioport_opaque[i] != NULL && macro_ioport_opaque[i] != opaque)
            hw_error("register_ioport_read: invalid opaque");
        macro_ioport_opaque[i] = opaque;
    }
    return 0;
}

/* size is the word size in byte */
int register_ioport_write(int start, int length, int size,
                          IOPortWriteFunc *func, void *opaque)
{
    int i, bsize;

    if (size == 1) {
        bsize = 0;
    } else if (size == 2) {
        bsize = 1;
    } else if (size == 4) {
        bsize = 2;
    } else {
        hw_error("register_ioport_write: invalid size");
        return -1;
    }
    for(i = start; i < start + length; i += size) {
        macro_ioport_write_table[bsize][i] = func;
        if (macro_ioport_opaque[i] != NULL && macro_ioport_opaque[i] != opaque)
            hw_error("register_ioport_write: invalid opaque");
        macro_ioport_opaque[i] = opaque;
    }
    return 0;
}

void cpu_outb(CPUState *env, int addr, int val)
{
#ifdef DEBUG_IOPORT
    if (loglevel & CPU_LOG_IOPORT)
        fprintf(logfile, "outb: %04x %02x\n", addr, val);
#endif
    macro_ioport_write_table[0][addr](macro_ioport_opaque[addr], addr, val);
}

void cpu_outw(CPUState *env, int addr, int val)
{
#ifdef DEBUG_IOPORT
    if (loglevel & CPU_LOG_IOPORT)
        fprintf(logfile, "outw: %04x %04x\n", addr, val);
#endif
    macro_ioport_write_table[1][addr](macro_ioport_opaque[addr], addr, val);
}

void cpu_outl(CPUState *env, int addr, int val)
{
#ifdef DEBUG_IOPORT
    if (loglevel & CPU_LOG_IOPORT)
        fprintf(logfile, "outl: %04x %08x\n", addr, val);
#endif
    macro_ioport_write_table[2][addr](macro_ioport_opaque[addr], addr, val);
}

int cpu_inb(CPUState *env, int addr)
{
    int val;
    val = macro_ioport_read_table[0][addr](macro_ioport_opaque[addr], addr);
#ifdef DEBUG_IOPORT
    if (loglevel & CPU_LOG_IOPORT)
        fprintf(logfile, "inb : %04x %02x\n", addr, val);
#endif
    return val;
}

int cpu_inw(CPUState *env, int addr)
{
    int val;
    val = macro_ioport_read_table[1][addr](macro_ioport_opaque[addr], addr);
#ifdef DEBUG_IOPORT
    if (loglevel & CPU_LOG_IOPORT)
        fprintf(logfile, "inw : %04x %04x\n", addr, val);
#endif
    return val;
}

int cpu_inl(CPUState *env, int addr)
{
    int val;
    val = macro_ioport_read_table[2][addr](macro_ioport_opaque[addr], addr);
#ifdef DEBUG_IOPORT
    if (loglevel & CPU_LOG_IOPORT)
        fprintf(logfile, "inl : %04x %08x\n", addr, val);
#endif
    return val;
}

void hw_error(const char *fmt, ...)
{
    va_list ap;
    CPUState *env;

    va_start(ap, fmt);
    fprintf(stderr, "qemu: hardware error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    for (env = (CPUState *) crt_qemu_instance->first_cpu; env != NULL; env = env->next_cpu)
    {
        fprintf(stderr, "CPU #%d:\n", env->cpu_index);
        #ifdef TARGET_I386
        cpu_dump_state(env, stderr, fprintf, X86_DUMP_FPU);
        #else
        cpu_dump_state(env, stderr, fprintf, 0);
        #endif
    }
    va_end(ap);
    abort();
}

/***********************************************************/
/* main execution loop */

extern unsigned long s_crt_nr_cycles_instr;
extern unsigned long s_crt_ns_misses;
extern int irq_pending (CPUState *penv);

long
qemu_cpu_loop (CPUState *penv)
{
    crt_qemu_instance = penv->qemu.qemu_instance;

    int             ret = cpu_exec (penv);

    unsigned long   ninstr = s_crt_nr_cycles_instr;
    s_crt_nr_cycles_instr = 0;

    #ifdef IMPLEMENT_LATE_CACHES
    unsigned long   ns_misses = s_crt_ns_misses;
    if (ns_misses)
    {
        s_crt_ns_misses = 0;
        penv->qemu.qemu_instance->systemc.systemc_qemu_consume_ns (ns_misses);
    }
    #endif

    if (ninstr)
    {
        penv->qemu.qemu_instance->systemc.systemc_qemu_consume_instruction_cycles (
            penv->qemu.sc_obj, ninstr);
    }
    if ((ret == EXCP_HLT || ret == EXCP_HALTED) && irq_pending (penv))
        ret = EXCP_INTERRUPT;
	crt_qemu_instance = NULL;

  return ret;
}

void *
qemu_get_set_cpu_obj (qemu_instance *instance, unsigned long index, void *sc_obj)
{
    qemu_instance       *save_instance;
    CPUState         	*penv;
    int                 i;

    save_instance = crt_qemu_instance;
    crt_qemu_instance = instance;
    penv = (CPUState *) crt_qemu_instance->first_cpu;

    for (i = 0; i < index; i++)
        penv = penv->next_cpu;

    penv->qemu.sc_obj = sc_obj;

    crt_qemu_instance = save_instance;

    penv->sc_mem_host_addr = (unsigned long)
        crt_qemu_instance->systemc.systemc_get_mem_addr (penv->qemu.sc_obj, 0);

    return penv;
}

static void init_cacheline(struct cacheline *line)
{
    uint32_t *data = (uint32_t *)line;
    int i;

    for (i = 0; i < CACHE_LINE_BYTES / sizeof(uint32_t); i++)
	data[i] = 0xdeadbeef;
}

static void init_cacheline_entry(struct cacheline_entry *entry, int age)
{
    entry->tag = ~0;
    entry->age = age;
    entry->type = QEMU_CACHE_NONE;
}

static inline void set_mutex_init(struct set_mutex *mutex)
{
    mutex->locked = 0;
    mutex->cpu = -1;
}

void
qemu_init_caches (void)
{
    int way, idx, cpu, bank;

    qi_dcache(crt_qemu_instance) = malloc (crt_qemu_instance->NOCPUs *
        DCACHE_LPS * CACHE_WAYS * sizeof (struct cacheline_entry));
    for (cpu = 0; cpu < crt_qemu_instance->NOCPUs; cpu++)
	for (idx = 0; idx < DCACHE_LPS; idx++)
	    for (way = 0; way < CACHE_WAYS; way++)
		init_cacheline_entry(&qi_dcache(crt_qemu_instance)[cpu][idx][way], way);

    qi_dcache_data(crt_qemu_instance) = malloc (crt_qemu_instance->NOCPUs *
        DCACHE_LPS * CACHE_WAYS * sizeof(struct cacheline));
    for (cpu = 0; cpu < crt_qemu_instance->NOCPUs; cpu++)
	for (idx = 0; idx < DCACHE_LPS; idx++)
	    for (way = 0; way < CACHE_WAYS; way++)
		init_cacheline(&qi_dcache_data(crt_qemu_instance)[cpu][idx][way]);

    qi_icache(crt_qemu_instance) = malloc (crt_qemu_instance->NOCPUs *
        ICACHE_LPS * CACHE_WAYS * sizeof (struct cacheline_entry));
    for (cpu = 0; cpu < crt_qemu_instance->NOCPUs; cpu++)
	for (idx = 0; idx < ICACHE_LPS; idx++)
	    for (way = 0; way < CACHE_WAYS; way++)
		init_cacheline_entry(&qi_icache(crt_qemu_instance)[cpu][idx][way], way);

    qi_icache_data(crt_qemu_instance) = malloc (crt_qemu_instance->NOCPUs *
        ICACHE_LPS * CACHE_WAYS * sizeof(struct cacheline));
    for (cpu = 0; cpu < crt_qemu_instance->NOCPUs; cpu++)
	for (idx = 0; idx < ICACHE_LPS; idx++)
	    for (way = 0; way < CACHE_WAYS; way++)
		init_cacheline(&qi_icache_data(crt_qemu_instance)[cpu][idx][way]);

    crt_qemu_instance->l2_cache = malloc(L2_BANKS * L2_LPS * L2_WAYS *
                                        sizeof(struct cacheline_entry));
    for (bank = 0; bank < L2_BANKS; bank++)
        for (idx = 0; idx < L2_LPS; idx++)
            for (way = 0; way < L2_WAYS; way++)
                init_cacheline_entry(&crt_qemu_instance->l2_cache[bank][idx][way], way);

    crt_qemu_instance->l2_cache_data = malloc(L2_BANKS * L2_LPS * L2_WAYS *
                                        sizeof(struct cacheline));
    for (bank = 0; bank < L2_BANKS; bank++)
        for (idx = 0; idx < L2_LPS; idx++)
            for (way = 0; way < L2_WAYS; way++)
                init_cacheline(&crt_qemu_instance->l2_cache_data[bank][idx][way]);

    set_mutex_init(&crt_qemu_instance->mem_lock);
}

void
qemu_release ()
{
}

void qemu_add_map (qemu_instance *instance, unsigned long base, unsigned long size, int type);
void qemu_set_cpu_fv_percent (CPUState *penv, unsigned long fv_percent);
void qemu_irq_update (qemu_instance *instance, int cpu_mask, int level);
void qemu_get_counters (unsigned long long *no_instr,
    unsigned long long *no_dcache_miss,
    unsigned long long *no_write,
    unsigned long long *no_icache_miss,
    unsigned long long *no_uncached);
void qemu_invalidate_address (qemu_instance *instance, unsigned long addr, int src_idx);
void glue(TARGET_ARCH_,_generic_machine_init) (int ram_size, const char *cpu_model);
void exec_c_init (void);

void *
glue(TARGET_ARCH_, _qemu_init) (int id, int ncpu, const char *cpu_model, int _ramsize,
    struct qemu_import_t *qi, struct systemc_import_t *systemc_fcs)
{
    signal (SIGSEGV, sigsegv_h);
    signal (SIGABRT, sigabrt_h);

    signal (SIGINT, sigint_h);

    //fill the systemc function address table
    qi->qemu_add_map = (qemu_add_map_fc_t) qemu_add_map;
    qi->qemu_release = (qemu_release_fc_t) qemu_release;
    qi->qemu_get_set_cpu_obj = (qemu_get_set_cpu_obj_fc_t) qemu_get_set_cpu_obj;
    qi->qemu_cpu_loop = (qemu_cpu_loop_fc_t) qemu_cpu_loop;
    qi->qemu_set_cpu_fv_percent = (qemu_set_cpu_fv_percent_fc_t) qemu_set_cpu_fv_percent;
    qi->qemu_irq_update = (qemu_irq_update_fc_t) qemu_irq_update;
    qi->qemu_get_counters = (qemu_get_counters_fc_t) qemu_get_counters;
    qi->qemu_invalidate_address = (qemu_invalidate_address_fc_t) qemu_invalidate_address;
    qi->gdb_srv_start_and_wait = (gdb_srv_start_and_wait_fc_t) gdb_srv_start_and_wait;

    //init current qemu simulator "object"
    crt_qemu_instance = malloc (sizeof (qemu_instance));
    memset (crt_qemu_instance, 0, sizeof (qemu_instance));
    crt_qemu_instance->systemc = *systemc_fcs;
    crt_qemu_instance->NOCPUs = ncpu;
    crt_qemu_instance->id = id;
    crt_qemu_instance->ram_size = _ramsize;
    crt_qemu_instance->io_mem_opaque = malloc (IO_MEM_NB_ENTRIES * sizeof (void *));
    memset (crt_qemu_instance->io_mem_opaque, 0, IO_MEM_NB_ENTRIES * sizeof (void *));
    crt_qemu_instance->io_mem_read = malloc (IO_MEM_NB_ENTRIES * 4 * sizeof (CPUReadMemoryFunc *));
    memset (crt_qemu_instance->io_mem_read, 0, IO_MEM_NB_ENTRIES * 4 * sizeof (CPUReadMemoryFunc *));
    crt_qemu_instance->io_mem_write = malloc (IO_MEM_NB_ENTRIES * 4 * sizeof (CPUWriteMemoryFunc *));
    memset (crt_qemu_instance->io_mem_write, 0, IO_MEM_NB_ENTRIES * 4 * sizeof (CPUWriteMemoryFunc *));
    crt_qemu_instance->ioport_opaque = malloc (MAX_IOPORTS * sizeof (void *));
    memset (crt_qemu_instance->ioport_opaque, 0, MAX_IOPORTS * sizeof (void *));
    crt_qemu_instance->ioport_read_table = malloc (3 * MAX_IOPORTS * sizeof (IOPortReadFunc *));
    memset (crt_qemu_instance->ioport_read_table, 0, 3 * MAX_IOPORTS * sizeof (IOPortReadFunc *));
    crt_qemu_instance->ioport_write_table = malloc (3 * MAX_IOPORTS * sizeof (IOPortWriteFunc *));
    memset (crt_qemu_instance->ioport_write_table, 0, 3 * MAX_IOPORTS * sizeof (IOPortWriteFunc *));
    exec_c_init ();
    qemu_instances[no_qemu_instances++] = crt_qemu_instance;

    init_ioports ();
    glue(TARGET_ARCH_,_generic_machine_init) (_ramsize, cpu_model);
    qemu_init_caches ();

    CPUState    *penv = (CPUState *) crt_qemu_instance->first_cpu;
    int         cpu_index = 0;
    crt_qemu_instance->envs = malloc (ncpu * sizeof (CPUState *));
    while (penv)
    {
        crt_qemu_instance->envs[cpu_index++] = penv;
        penv = penv->next_cpu;
    }

    //gdb server
    crt_qemu_instance->gdb = malloc (sizeof (struct GDBState));
    memset (crt_qemu_instance->gdb, 0, sizeof (struct GDBState));
    crt_qemu_instance->gdb->running_state = STATE_DETACH;

    return crt_qemu_instance;
}

void
log_pc (unsigned long addr)
{
    if (cpu_single_env->cpu_index != 0 || crt_qemu_instance->log_cnt_instr++ > 100000)
        return;

    unsigned long       crt_cycle =
        *crt_qemu_instance->systemc.no_cycles_cpu0 + s_crt_nr_cycles_instr;

    unsigned long       soft_thread = 
        crt_qemu_instance->systemc.systemc_qemu_get_crt_thread (cpu_single_env->qemu.sc_obj);
  
    if (crt_qemu_instance->fim == NULL)
    {
        char            buf[50];
        sprintf (buf, "qemu_fim_%d.lst", crt_qemu_instance->id);
        crt_qemu_instance->fim = fopen (buf, "w");
    }

    fprintf (crt_qemu_instance->fim, "%x\t%lu\t%d\tth=%lx"
        #if TARGET_SPARC
        "\tcwp=%lu,wim=%lu,w3.O0=%x,w3.l3=%x,sp=%x,spb=%x\n"
        #endif
        ,(unsigned int) addr, crt_cycle,
        cpu_single_env->cpu_index, soft_thread
        #if TARGET_SPARC
        ,(unsigned long)cpu_single_env->cwp,
        (unsigned long)cpu_single_env->wim,
        (unsigned int)cpu_single_env->regbase[3*16+0],
        (unsigned int)cpu_single_env->regbase[3*16+11],
        (unsigned int)cpu_single_env->regbase[cpu_single_env->cwp*16+6],
        (unsigned int)cpu_single_env->regbase[cpu_single_env->cwp*16+6] & 0xFFFFF000
        #endif
        );

    fflush (crt_qemu_instance->fim);
}

void
log_data_cache (unsigned long addr_miss)
{
    if (cpu_single_env->cpu_index != 0 || crt_qemu_instance->log_cnt_data++ > 100000)
        return;

    unsigned long       crt_cycle =
        *crt_qemu_instance->systemc.no_cycles_cpu0 + s_crt_nr_cycles_instr;

    if (crt_qemu_instance->fdm == NULL)
    {
        char            buf[50];
        sprintf (buf, "qemu_fdm_%d.lst", crt_qemu_instance->id);
        crt_qemu_instance->fdm = fopen (buf, "w");
    }

    fprintf (crt_qemu_instance->fdm, "%x\t\t%lu\n",
        (unsigned int) addr_miss, crt_cycle);
    fflush (crt_qemu_instance->fdm);
}

