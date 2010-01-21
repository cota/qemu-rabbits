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

//#define DEBUG_UNUSED_IOPORT
//#define DEBUG_IOPORT

/* XXX: use a two level table to limit memory usage */
#define MAX_IOPORTS 65536
#define macro_ioport_opaque ((void *(*)) crt_qemu_instance->ioport_opaque)
#define macro_ioport_read_table ((IOPortReadFunc *(*)[MAX_IOPORTS]) crt_qemu_instance->ioport_read_table)
#define macro_ioport_write_table ((IOPortWriteFunc *(*)[MAX_IOPORTS]) crt_qemu_instance->ioport_write_table)

extern CPUState         *cpu_single_env;
qemu_instance           *crt_qemu_instance = NULL;

#if defined(TARGET_ARM)
void arm_generic_machine_init (int ram_size, const char *cpu_model);
#endif

void exec_c_init (void);

void
sigsegv_h (int x)
{
  printf ("SIGSEGV signal received! (%d)\n", x);
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
    for (env = (CPUState *) crt_qemu_instance->first_cpu; env != NULL; env = env->next_cpu) {
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

long
qemu_cpu_loop (CPUState *penv)
{
	crt_qemu_instance = penv->qemu.qemu_instance;
	tb_invalidated_flag = crt_qemu_instance->tb_invalidated_flag;

	int             ret = cpu_exec (penv);
	unsigned long   ninstr = s_crt_nr_cycles_instr;

  if (ninstr)
		{
			s_crt_nr_cycles_instr = 0;
			systemc_qemu_consume_instruction_cycles (penv->qemu.sc_obj, ninstr,
																							 &penv->qemu.ns_in_cpu_exec);
		}
	penv->qemu.qemu_instance->tb_invalidated_flag = tb_invalidated_flag;
	crt_qemu_instance = NULL;

  return ret;
}

unsigned long
qemu_get_set_cpu_obj (unsigned long index, unsigned long sc_obj)
{
  int i;
	CPUARMState		*penv = (CPUState *) crt_qemu_instance->first_cpu;

  for (i = 0; i < index; i++)
    penv = penv->next_cpu;

  penv->qemu.sc_obj = sc_obj;

  return (unsigned long) penv;
}

void
qemu_init_caches (void)
{
  int line, cpu;

	crt_qemu_instance->cpu_dcache = malloc (crt_qemu_instance->NOCPUs * DCACHE_LINES * sizeof (unsigned long));
	for (cpu = 0; cpu < crt_qemu_instance->NOCPUs; cpu++)
      for (line = 0; line < DCACHE_LINES; line++)
				  crt_qemu_instance->cpu_dcache[cpu][line] = (unsigned long) -1;

	crt_qemu_instance->cpu_icache = malloc (crt_qemu_instance->NOCPUs * ICACHE_LINES * sizeof (unsigned long));
	for (cpu = 0; cpu < crt_qemu_instance->NOCPUs; cpu++)
      for (line = 0; line < ICACHE_LINES; line++)
				  crt_qemu_instance->cpu_icache[cpu][line] = (unsigned long) -1;

    int         w;
    crt_qemu_instance->cpu_dcache_data = malloc (crt_qemu_instance->NOCPUs * DCACHE_LINES * DCACHE_LINE_BYTES * sizeof (unsigned char));
    for (cpu = 0; cpu < crt_qemu_instance->NOCPUs; cpu++)
        for (line = 0; line < DCACHE_LINES; line++)
            for (w = 0; w < DCACHE_LINE_WORDS; w++)
                ((unsigned long *) crt_qemu_instance->cpu_dcache_data[cpu][line])[w] = (unsigned long) 0xDEADBEAF;

    crt_qemu_instance->cpu_icache_data = malloc (crt_qemu_instance->NOCPUs * ICACHE_LINES * ICACHE_LINE_BYTES * sizeof (unsigned char));
    for (cpu = 0; cpu < crt_qemu_instance->NOCPUs; cpu++)
        for (line = 0; line < ICACHE_LINES; line++)
            for (w = 0; w < ICACHE_LINE_WORDS; w++)
                ((unsigned long *) crt_qemu_instance->cpu_icache_data[cpu][line])[w] = (unsigned long) 0xDEADBEAF;

}

unsigned long qemu_init (int id, int ncpu, const char *cpu_model, int _ramsize)
{

    crt_qemu_instance = malloc (sizeof (qemu_instance));
    memset (crt_qemu_instance, 0, sizeof (qemu_instance));
    crt_qemu_instance->NOCPUs = ncpu;
    crt_qemu_instance->id = id;
    crt_qemu_instance->io_mem_opaque = (unsigned long) malloc (IO_MEM_NB_ENTRIES * sizeof (void *));
    memset ((void *) crt_qemu_instance->io_mem_opaque, 0, IO_MEM_NB_ENTRIES * sizeof (void *));
    crt_qemu_instance->io_mem_read = (unsigned long) malloc (IO_MEM_NB_ENTRIES * 4 * sizeof (CPUReadMemoryFunc *));
    memset ((void *) crt_qemu_instance->io_mem_read, 0, IO_MEM_NB_ENTRIES * 4 * sizeof (CPUReadMemoryFunc *));
    crt_qemu_instance->io_mem_write = (unsigned long) malloc (IO_MEM_NB_ENTRIES * 4 * sizeof (CPUWriteMemoryFunc *));
    memset ((void *) crt_qemu_instance->io_mem_write, 0, IO_MEM_NB_ENTRIES * 4 * sizeof (CPUWriteMemoryFunc *));
    crt_qemu_instance->ioport_opaque = (unsigned long) malloc (MAX_IOPORTS * sizeof (void *));
    memset ((void *) crt_qemu_instance->ioport_opaque, 0, MAX_IOPORTS * sizeof (void *));
    crt_qemu_instance->ioport_read_table = (unsigned long) malloc (3 * MAX_IOPORTS * sizeof (IOPortReadFunc *));
    memset ((void *) crt_qemu_instance->ioport_read_table, 0, 3 * MAX_IOPORTS * sizeof (IOPortReadFunc *));
    crt_qemu_instance->ioport_write_table = (unsigned long) malloc (3 * MAX_IOPORTS * sizeof (IOPortWriteFunc *));
    memset ((void *) crt_qemu_instance->ioport_write_table, 0, 3 * MAX_IOPORTS * sizeof (IOPortWriteFunc *));
    exec_c_init ();

    signal (SIGSEGV, sigsegv_h);

    /* init the memory */
    crt_qemu_instance->ram_size = _ramsize;

    init_ioports ();

    #if defined(TARGET_ARM)
    arm_generic_machine_init (_ramsize, cpu_model);
    #endif

    qemu_init_caches ();

    return (unsigned long) crt_qemu_instance;
}

void
qemu_release ()
{
}

extern unsigned long no_cycles_cpu0;
void
log_pc (unsigned long addr)
{
    if (crt_qemu_instance->fim == NULL)
		{
			  char            buf[50];
        sprintf (buf, "qemu_fim_%d.lst", crt_qemu_instance->id);
        crt_qemu_instance->fim = fopen (buf, "w");
    }
    fprintf (crt_qemu_instance->fim, "%X\t\t%lu\t\t%d\n",
						 (unsigned int) addr, no_cycles_cpu0 + s_crt_nr_cycles_instr,
						 cpu_single_env->cpu_index);
}

void
log_data_cache (unsigned long adr_miss)
{
	if (cpu_single_env->cpu_index != 0 || crt_qemu_instance->log_cnt_data++ > 100000)
    return;

	if (crt_qemu_instance->fdm == NULL)
    {
        char            buf[50];
        sprintf (buf, "qemu_fdm_%d.lst", crt_qemu_instance->id);
        crt_qemu_instance->fdm = fopen (buf, "w");
    }
	fprintf (crt_qemu_instance->fdm, "%X\t\t%lu\n",
	   (unsigned int) addr_miss, no_cycles_cpu0 + s_crt_nr_cycles_instr);
}

