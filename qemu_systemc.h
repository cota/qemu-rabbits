#ifndef _QEMU_SYSTEMC_H_
#define _QEMU_SYSTEMC_H_

#include <cfg.h>

#define CODE_GEN_BUFFER_SIZE     (8 * 1024 * 1024)

//#define COUNT_INSTR_FOR_STATISTICS

//#define LOG_INFO_FOR_DEBUG
//#define WRITE_PC_FOR_DEBUG

#define CYCLES_LATENCY_CACHE            2
#define CYCLES_LATENCY_CACHE_MISS       28
#define CYCLES_LATENCY_WRITE            1

#define NS_ICACHE_MISS                  92
#define NS_DCACHE_MISS                  92
#define NS_WRITE_ACCESS                 15

#define MEM_LIMIT           0x8000000

#define CACHE_BITS_TO_WORDS(bits)	(1 << ((bits) - 2))
#define CACHE_BITS_TO_BYTES(bits)	(1 <<  (bits))
#define CACHE_BITS_TO_MASK(bits)	(CACHE_BITS_TO_BYTES(bits) - 1)

#ifdef IMPLEMENT_COMBINED_CACHE
#define DCACHE_LINES		512
#define ICACHE_LINES		DCACHE_LINES
#else
#define DCACHE_LINES        256
#define ICACHE_LINES        256
#endif /* IMPLEMENT_COMBINED_CACHE */

#define __cache_tag_to_idx(tag, lines)	((tag) & ((lines) - 1))
#define dcache_tag_to_idx(tag)		__cache_tag_to_idx (tag,  DCACHE_LINES)
#define icache_tag_to_idx(tag)		__cache_tag_to_idx (tag,  ICACHE_LINES)

/*
 * The size of each cacheline is the same for Instruction and Data caches.
 * The number of lines on each of them may vary though.
 */
#define CACHE_LINE_BITS		5
#define CACHE_LINE_WORDS	CACHE_BITS_TO_WORDS(CACHE_LINE_BITS)
#define CACHE_LINE_BYTES	CACHE_BITS_TO_BYTES(CACHE_LINE_BITS)
#define CACHE_LINE_MASK		CACHE_BITS_TO_MASK (CACHE_LINE_BITS)

#define cache_addr_to_tag(addr)	((addr) >> CACHE_LINE_BITS)
#define cache_addr_to_ofs(addr)	((addr) & CACHE_LINE_MASK)

#define dcache_addr_to_tag(addr)	cache_addr_to_tag(addr)
#define dcache_addr_to_ofs(addr)	cache_addr_to_ofs(addr)
#define icache_addr_to_tag(addr)	cache_addr_to_tag(addr)
#define icache_addr_to_ofs(addr)	cache_addr_to_ofs(addr)

#endif
