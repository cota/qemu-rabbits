#ifndef _QEMU_SYSTEMC_H_
#define _QEMU_SYSTEMC_H_

#include <cfg.h>

#ifndef BIT
#define BIT(nr)	(1UL << (nr))
#endif

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

#define DCACHE_BITS	13
#define ICACHE_BITS	13

#define CACHE_BITS_TO_MASK(bits)	(BIT(bits) - 1)

/*
 * The size of each cacheline is the same for Instruction and Data caches.
 * The number of lines on each of them may vary though.
 */
#define CACHE_LINE_BITS		5
#define CACHE_LINE_BYTES	BIT(CACHE_LINE_BITS)
#define CACHE_LINE_u32s		(CACHE_LINE_BYTES / sizeof(uint32_t))
#define CACHE_LINE_MASK		CACHE_BITS_TO_MASK (CACHE_LINE_BITS)

#define CACHE_WAYS	BIT(CACHE_ASSOC)
#define CACHE_WAYS_MASK	(CACHE_WAYS - 1)

#define DCACHE_LINES		BIT(DCACHE_BITS - CACHE_LINE_BITS)
#define ICACHE_LINES		BIT(ICACHE_BITS - CACHE_LINE_BITS)

#define L2_ASSOC		2
#define L2_WAYS			BIT(L2_ASSOC)
#define L2_BANKS		1
#define L2_SIZE_BITS		15
#define L2_LPS			BIT(L2_SIZE_BITS - CACHE_LINE_BITS - L2_ASSOC)

//#define L2M_MASK		0x3000
#define L2M_MASK 0
//#define L3_REMOTE

#define OOB_NONE		0x0
#define OOB_HIT			0x1
#define OOB_MISS		0x2

/*
 * As the associativity increases, so does the number of bits per tag.
 * Conversely, n_bits(index) diminishes. Examples:
 *
 * | tag      | idx   | line | -> direct mapped
 * | tag        | idx | line | -> 2-way set-associative
 * | tag         |idx | line | -> 4-way
 * | tag          |idx| line | -> 8-way
 *
 * Note that n_bits(index) = log(lines per set), whereas the tag takes one
 * bit to the right each time the associativity is increased.
 * Tag and index do not overlap; if this was implemented in hardware,
 * this point would become important.
 */
#define TAG_SHIFT(cache_bits)	((cache_bits) - CACHE_ASSOC)

/* Lines Per Set (LPS) */
#define DCACHE_LPS	(DCACHE_LINES >> CACHE_ASSOC)
#define ICACHE_LPS	(ICACHE_LINES >> CACHE_ASSOC)

#define __addr_to_tag(addr, cache_bits)	((addr) >> TAG_SHIFT(cache_bits))
#define dcache_addr_to_tag(addr)	__addr_to_tag(addr, DCACHE_BITS)
#define icache_addr_to_tag(addr)	__addr_to_tag(addr, ICACHE_BITS)
#define __addr_to_ofs(addr)	((addr) & CACHE_LINE_MASK)

#define __cache_addr_to_idx(addr, lps) (((addr) >> CACHE_LINE_BITS) & (lps - 1))
#define dcache_addr_to_idx(addr)	__cache_addr_to_idx(addr, DCACHE_LPS)
#define icache_addr_to_idx(addr)	__cache_addr_to_idx(addr, ICACHE_LPS)

#define L2_TAG_SHIFT	(L2_SIZE_BITS - L2_ASSOC)
#define l2_addr_to_tag(addr)	((addr) >> L2_TAG_SHIFT)
#define l2_addr_to_idx(addr)	(((addr) >> CACHE_LINE_BITS) & (L2_LPS - 1))
#define l2_build_addr(tag, idx)                         \
    (((tag) << L2_TAG_SHIFT) | ((idx) << CACHE_LINE_BITS))

#endif
