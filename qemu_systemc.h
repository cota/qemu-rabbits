#ifndef _QEMU_SYSTEMC_H_
#define _QEMU_SYSTEMC_H_

#define COUNT_INSTR_FOR_DEBUG

//#define LOG_PC
//#define WRITE_PC_FOR_DEBUG
#define GDB_ENABLED

#define CYCLES_LATENCY_CACHE            2
#define CYCLES_LATENCY_CACHE_MISS       28
#define CYCLES_LATENCY_WRITE            1

#define MEM_LIMIT           0x8000000

#define DCACHE_LINES        256
#define DCACHE_LINE_BITS    5
#define DCACHE_LINE_WORDS   (1 << (DCACHE_LINE_BITS - 2))
#define DCACHE_LINE_BYTES   (1 << DCACHE_LINE_BITS)
#define DCACHE_LINE_MASK    ((1 << DCACHE_LINE_BITS) - 1)

#define ICACHE_LINES        256
#define ICACHE_LINE_BITS    5
#define ICACHE_LINE_WORDS   (1 << (ICACHE_LINE_BITS - 2))
#define ICACHE_LINE_BYTES   (1 << ICACHE_LINE_BITS)
#define ICACHE_LINE_MASK    ((1 << ICACHE_LINE_BITS) - 1)

#endif
