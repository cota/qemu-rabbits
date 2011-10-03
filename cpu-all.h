/*
 * defines common to all virtual CPUs
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef CPU_ALL_H
#define CPU_ALL_H

#if defined(__arm__) || defined(__sparc__) || defined(__mips__)
#define WORDS_ALIGNED
#endif

/* some important defines:
 *
 * WORDS_ALIGNED : if defined, the host cpu can only make word aligned
 * memory accesses.
 *
 * WORDS_BIGENDIAN : if defined, the host cpu is big endian and
 * otherwise little endian.
 *
 * (TARGET_WORDS_ALIGNED : same for target cpu (not supported yet))
 *
 * TARGET_WORDS_BIGENDIAN : same for target cpu
 */

#include "bswap.h"

#if defined(WORDS_BIGENDIAN) != defined(TARGET_WORDS_BIGENDIAN)
#define BSWAP_NEEDED
#endif

#ifdef BSWAP_NEEDED

static inline uint8_t tswap8(uint8_t s)
{
    return s;
}

static inline uint16_t tswap16(uint16_t s)
{
    return bswap16(s);
}

static inline uint32_t tswap32(uint32_t s)
{
    return bswap32(s);
}

static inline uint64_t tswap64(uint64_t s)
{
    return bswap64(s);
}

static inline void tswap16s(uint16_t *s)
{
    *s = bswap16(*s);
}

static inline void tswap32s(uint32_t *s)
{
    *s = bswap32(*s);
}

static inline void tswap64s(uint64_t *s)
{
    *s = bswap64(*s);
}

#else

static inline uint8_t tswap8(uint8_t s)
{
    return s;
}

static inline uint16_t tswap16(uint16_t s)
{
    return s;
}

static inline uint32_t tswap32(uint32_t s)
{
    return s;
}

static inline uint64_t tswap64(uint64_t s)
{
    return s;
}

static inline void tswap16s(uint16_t *s)
{
}

static inline void tswap32s(uint32_t *s)
{
}

static inline void tswap64s(uint64_t *s)
{
}

#endif

#if TARGET_LONG_SIZE == 4
#define tswapl(s) tswap32(s)
#define tswapls(s) tswap32s((uint32_t *)(s))
#define bswaptls(s) bswap32s(s)
#else
#define tswapl(s) tswap64(s)
#define tswapls(s) tswap64s((uint64_t *)(s))
#define bswaptls(s) bswap64s(s)
#endif

/**
 * upper_32_bits - return bits 32-63 of a number
 * @n: the number we're accessing
 *
 * A basic shift-right of a 64- or 32-bit quantity.  Use this to suppress
 * the "right shift count >= width of type" warning when that quantity is
 * 32-bits.
 */
#define upper_32_bits(n) ((uint32_t)(((n) >> 16) >> 16))

/**
 * lower_32_bits - return bits 0-31 of a number
 * @n: the number we're accessing
 */
#define lower_32_bits(n) ((uint32_t)(n))

/* NOTE: arm FPA is horrible as double 32 bit words are stored in big
   endian ! */
typedef union {
    float64 d;
#if defined(WORDS_BIGENDIAN) \
    || (defined(__arm__) && !defined(__VFP_FP__) && !defined(CONFIG_SOFTFLOAT))
    struct {
        uint32_t upper;
        uint32_t lower;
    } l;
#else
    struct {
        uint32_t lower;
        uint32_t upper;
    } l;
#endif
    uint64_t ll;
} CPU_DoubleU;

#ifdef TARGET_SPARC
typedef union {
    float128 q;
#if defined(WORDS_BIGENDIAN) \
    || (defined(__arm__) && !defined(__VFP_FP__) && !defined(CONFIG_SOFTFLOAT))
    struct {
        uint32_t upmost;
        uint32_t upper;
        uint32_t lower;
        uint32_t lowest;
    } l;
    struct {
        uint64_t upper;
        uint64_t lower;
    } ll;
#else
    struct {
        uint32_t lowest;
        uint32_t lower;
        uint32_t upper;
        uint32_t upmost;
    } l;
    struct {
        uint64_t lower;
        uint64_t upper;
    } ll;
#endif
} CPU_QuadU;
#endif

/* CPU memory access without any memory or io remapping */

/*
 * the generic syntax for the memory accesses is:
 *
 * load: ld{type}{sign}{size}{endian}_{access_type}(ptr)
 *
 * store: st{type}{size}{endian}_{access_type}(ptr, val)
 *
 * type is:
 * (empty): integer access
 *   f    : float access
 *
 * sign is:
 * (empty): for floats or 32 bit size
 *   u    : unsigned
 *   s    : signed
 *
 * size is:
 *   b: 8 bits
 *   w: 16 bits
 *   l: 32 bits
 *   q: 64 bits
 *
 * endian is:
 * (empty): target cpu endianness or 8 bit access
 *   r    : reversed target cpu endianness (not implemented yet)
 *   be   : big endian (not implemented yet)
 *   le   : little endian (not implemented yet)
 *
 * access_type is:
 *   raw    : host memory access
 *   user   : user mode access using soft MMU
 *   kernel : kernel mode access using soft MMU
 */
static inline int ldub_p(void *ptr)
{
    return *(uint8_t *)ptr;
}

static inline int ldsb_p(void *ptr)
{
    return *(int8_t *)ptr;
}

static inline void stb_p(void *ptr, int v)
{
    *(uint8_t *)ptr = v;
}

/* NOTE: on arm, putting 2 in /proc/sys/debug/alignment so that the
   kernel handles unaligned load/stores may give better results, but
   it is a system wide setting : bad */
#if defined(WORDS_BIGENDIAN) || defined(WORDS_ALIGNED)

/* conservative code for little endian unaligned accesses */
static inline int lduw_le_p(void *ptr)
{
#ifdef __powerpc__
    int val;
    __asm__ __volatile__ ("lhbrx %0,0,%1" : "=r" (val) : "r" (ptr));
    return val;
#else
    uint8_t *p = ptr;
    return p[0] | (p[1] << 8);
#endif
}

static inline int ldsw_le_p(void *ptr)
{
#ifdef __powerpc__
    int val;
    __asm__ __volatile__ ("lhbrx %0,0,%1" : "=r" (val) : "r" (ptr));
    return (int16_t)val;
#else
    uint8_t *p = ptr;
    return (int16_t)(p[0] | (p[1] << 8));
#endif
}

static inline int ldl_le_p(void *ptr)
{
#ifdef __powerpc__
    int val;
    __asm__ __volatile__ ("lwbrx %0,0,%1" : "=r" (val) : "r" (ptr));
    return val;
#else
    uint8_t *p = ptr;
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
#endif
}

static inline uint64_t ldq_le_p(void *ptr)
{
    uint8_t *p = ptr;
    uint32_t v1, v2;
    v1 = ldl_le_p(p);
    v2 = ldl_le_p(p + 4);
    return v1 | ((uint64_t)v2 << 32);
}

static inline void stw_le_p(void *ptr, int v)
{
#ifdef __powerpc__
    __asm__ __volatile__ ("sthbrx %1,0,%2" : "=m" (*(uint16_t *)ptr) : "r" (v), "r" (ptr));
#else
    uint8_t *p = ptr;
    p[0] = v;
    p[1] = v >> 8;
#endif
}

static inline void stl_le_p(void *ptr, int v)
{
#ifdef __powerpc__
    __asm__ __volatile__ ("stwbrx %1,0,%2" : "=m" (*(uint32_t *)ptr) : "r" (v), "r" (ptr));
#else
    uint8_t *p = ptr;
    p[0] = v;
    p[1] = v >> 8;
    p[2] = v >> 16;
    p[3] = v >> 24;
#endif
}

static inline void stq_le_p(void *ptr, uint64_t v)
{
    uint8_t *p = ptr;
    stl_le_p(p, (uint32_t)v);
    stl_le_p(p + 4, v >> 32);
}

/* float access */

static inline float32 ldfl_le_p(void *ptr)
{
    union {
        float32 f;
        uint32_t i;
    } u;
    u.i = ldl_le_p(ptr);
    return u.f;
}

static inline void stfl_le_p(void *ptr, float32 v)
{
    union {
        float32 f;
        uint32_t i;
    } u;
    u.f = v;
    stl_le_p(ptr, u.i);
}

static inline float64 ldfq_le_p(void *ptr)
{
    CPU_DoubleU u;
    u.l.lower = ldl_le_p(ptr);
    u.l.upper = ldl_le_p(ptr + 4);
    return u.d;
}

static inline void stfq_le_p(void *ptr, float64 v)
{
    CPU_DoubleU u;
    u.d = v;
    stl_le_p(ptr, u.l.lower);
    stl_le_p(ptr + 4, u.l.upper);
}

#else

static inline int lduw_le_p(void *ptr)
{
    return *(uint16_t *)ptr;
}

static inline int ldsw_le_p(void *ptr)
{
    return *(int16_t *)ptr;
}

static inline int ldl_le_p(void *ptr)
{
    return *(uint32_t *)ptr;
}

static inline uint64_t ldq_le_p(void *ptr)
{
    return *(uint64_t *)ptr;
}

static inline void stw_le_p(void *ptr, int v)
{
    *(uint16_t *)ptr = v;
}

static inline void stl_le_p(void *ptr, int v)
{
    *(uint32_t *)ptr = v;
}

static inline void stq_le_p(void *ptr, uint64_t v)
{
    volatile uint64_t   t = v;
    *(uint64_t *) ptr = t;
}

/* float access */

static inline float32 ldfl_le_p(void *ptr)
{
    return *(float32 *)ptr;
}

static inline float64 ldfq_le_p(void *ptr)
{
    return *(float64 *)ptr;
}

static inline void stfl_le_p(void *ptr, float32 v)
{
    *(float32 *)ptr = v;
}

static inline void stfq_le_p(void *ptr, float64 v)
{
    *(float64 *)ptr = v;
}
#endif

#if !defined(WORDS_BIGENDIAN) || defined(WORDS_ALIGNED)

static inline int lduw_be_p(void *ptr)
{
#if defined(__i386__)
    int val;
    asm volatile ("movzwl %1, %0\n"
                  "xchgb %b0, %h0\n"
                  : "=q" (val)
                  : "m" (*(uint16_t *)ptr));
    return val;
#else
    uint8_t *b = (uint8_t *) ptr;
    return ((b[0] << 8) | b[1]);
#endif
}

static inline int ldsw_be_p(void *ptr)
{
#if defined(__i386__)
    int val;
    asm volatile ("movzwl %1, %0\n"
                  "xchgb %b0, %h0\n"
                  : "=q" (val)
                  : "m" (*(uint16_t *)ptr));
    return (int16_t)val;
#else
    uint8_t *b = (uint8_t *) ptr;
    return (int16_t)((b[0] << 8) | b[1]);
#endif
}

static inline int ldl_be_p(void *ptr)
{
#if defined(__i386__) || defined(__x86_64__)
    int val;
    asm volatile ("movl %1, %0\n"
                  "bswap %0\n"
                  : "=r" (val)
                  : "m" (*(uint32_t *)ptr));
    return val;
#else
    uint8_t *b = (uint8_t *) ptr;
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
#endif
}

static inline uint64_t ldq_be_p(void *ptr)
{
    uint32_t a,b;
    a = ldl_be_p(ptr);
    b = ldl_be_p(ptr+4);
    return (((uint64_t)a<<32)|b);
}

static inline void stw_be_p(void *ptr, int v)
{
#if defined(__i386__)
    asm volatile ("xchgb %b0, %h0\n"
                  "movw %w0, %1\n"
                  : "=q" (v)
                  : "m" (*(uint16_t *)ptr), "0" (v));
#else
    uint8_t *d = (uint8_t *) ptr;
    d[0] = v >> 8;
    d[1] = v;
#endif
}

static inline void stl_be_p(void *ptr, int v)
{
#if defined(__i386__) || defined(__x86_64__)
    asm volatile ("bswap %0\n"
                  "movl %0, %1\n"
                  : "=r" (v)
                  : "m" (*(uint32_t *)ptr), "0" (v));
#else
    uint8_t *d = (uint8_t *) ptr;
    d[0] = v >> 24;
    d[1] = v >> 16;
    d[2] = v >> 8;
    d[3] = v;
#endif
}

static inline void stq_be_p(void *ptr, uint64_t v)
{
    stl_be_p(ptr, v >> 32);
    stl_be_p(ptr + 4, v);
}

/* float access */

static inline float32 ldfl_be_p(void *ptr)
{
    union {
        float32 f;
        uint32_t i;
    } u;
    u.i = ldl_be_p(ptr);
    return u.f;
}

static inline void stfl_be_p(void *ptr, float32 v)
{
    union {
        float32 f;
        uint32_t i;
    } u;
    u.f = v;
    stl_be_p(ptr, u.i);
}

static inline float64 ldfq_be_p(void *ptr)
{
    CPU_DoubleU u;
    u.l.upper = ldl_be_p(ptr);
    u.l.lower = ldl_be_p(ptr + 4);
    return u.d;
}

static inline void stfq_be_p(void *ptr, float64 v)
{
    CPU_DoubleU u;
    u.d = v;
    stl_be_p(ptr, u.l.upper);
    stl_be_p(ptr + 4, u.l.lower);
}

#else

static inline int lduw_be_p(void *ptr)
{
    return *(uint16_t *)ptr;
}

static inline int ldsw_be_p(void *ptr)
{
    return *(int16_t *)ptr;
}

static inline int ldl_be_p(void *ptr)
{
    return *(uint32_t *)ptr;
}

static inline uint64_t ldq_be_p(void *ptr)
{
    return *(uint64_t *)ptr;
}

static inline void stw_be_p(void *ptr, int v)
{
    *(uint16_t *)ptr = v;
}

static inline void stl_be_p(void *ptr, int v)
{
    *(uint32_t *)ptr = v;
}

static inline void stq_be_p(void *ptr, uint64_t v)
{
    *(uint64_t *)ptr = v;
}

/* float access */

static inline float32 ldfl_be_p(void *ptr)
{
    return *(float32 *)ptr;
}

static inline float64 ldfq_be_p(void *ptr)
{
    return *(float64 *)ptr;
}

static inline void stfl_be_p(void *ptr, float32 v)
{
    *(float32 *)ptr = v;
}

static inline void stfq_be_p(void *ptr, float64 v)
{
    *(float64 *)ptr = v;
}

#endif

/* target CPU memory access functions */
#if defined(TARGET_WORDS_BIGENDIAN)
#define lduw_p(p) lduw_be_p(p)
#define ldsw_p(p) ldsw_be_p(p)
#define ldl_p(p) ldl_be_p(p)
#define ldq_p(p) ldq_be_p(p)
#define ldfl_p(p) ldfl_be_p(p)
#define ldfq_p(p) ldfq_be_p(p)
#define stw_p(p, v) stw_be_p(p, v)
#define stl_p(p, v) stl_be_p(p, v)
#define stq_p(p, v) stq_be_p(p, v)
#define stfl_p(p, v) stfl_be_p(p, v)
#define stfq_p(p, v) stfq_be_p(p, v)
#else
#define lduw_p(p) lduw_le_p(p)
#define ldsw_p(p) ldsw_le_p(p)
#define ldl_p(p) ldl_le_p(p)
#define ldq_p(p) ldq_le_p(p)
#define ldfl_p(p) ldfl_le_p(p)
#define ldfq_p(p) ldfq_le_p(p)
#define stw_p(p, v) stw_le_p(p, v)
#define stl_p(p, v) stl_le_p(p, v)
#define stq_p(p, v) stq_le_p(p, v)
#define stfl_p(p, v) stfl_le_p(p, v)
#define stfq_p(p, v) stfq_le_p(p, v)
#endif

/* MMU memory access macros */

#if defined(CONFIG_USER_ONLY)
/* On some host systems the guest address space is reserved on the host.
 * This allows the guest address space to be offset to a convenient location.
 */
//#define GUEST_BASE 0x20000000
#define GUEST_BASE 0

/* All direct uses of g2h and h2g need to go away for usermode softmmu.  */
#define g2h(x) ((void *)((unsigned long)(x) + GUEST_BASE))
#define h2g(x) ((target_ulong)(x - GUEST_BASE))

#define saddr(x) g2h(x)
#define laddr(x) g2h(x)

#else /* !CONFIG_USER_ONLY */
/* NOTE: we use double casts if pointers and target_ulong have
   different sizes */
#define saddr(x) (uint8_t *)(long)(x)
#define laddr(x) (uint8_t *)(long)(x)
#endif

#define ldub_raw(p) ldub_p(laddr((p)))
#define ldsb_raw(p) ldsb_p(laddr((p)))
#define lduw_raw(p) lduw_p(laddr((p)))
#define ldsw_raw(p) ldsw_p(laddr((p)))
#define ldl_raw(p) ldl_p(laddr((p)))
#define ldq_raw(p) ldq_p(laddr((p)))
#define ldfl_raw(p) ldfl_p(laddr((p)))
#define ldfq_raw(p) ldfq_p(laddr((p)))
#define stb_raw(p, v) stb_p(saddr((p)), v)
#define stw_raw(p, v) stw_p(saddr((p)), v)
#define stl_raw(p, v) stl_p(saddr((p)), v)
#define stq_raw(p, v) stq_p(saddr((p)), v)
#define stfl_raw(p, v) stfl_p(saddr((p)), v)
#define stfq_raw(p, v) stfq_p(saddr((p)), v)


#if defined(CONFIG_USER_ONLY)

/* if user mode, no other memory access functions */
#define ldub(p) ldub_raw(p)
#define ldsb(p) ldsb_raw(p)
#define lduw(p) lduw_raw(p)
#define ldsw(p) ldsw_raw(p)
#define ldl(p) ldl_raw(p)
#define ldq(p) ldq_raw(p)
#define ldfl(p) ldfl_raw(p)
#define ldfq(p) ldfq_raw(p)
#define stb(p, v) stb_raw(p, v)
#define stw(p, v) stw_raw(p, v)
#define stl(p, v) stl_raw(p, v)
#define stq(p, v) stq_raw(p, v)
#define stfl(p, v) stfl_raw(p, v)
#define stfq(p, v) stfq_raw(p, v)

#define ldub_code(p) ldub_raw(p)
#define ldsb_code(p) ldsb_raw(p)
#define lduw_code(p) lduw_raw(p)
#define ldsw_code(p) ldsw_raw(p)
#define ldl_code(p) ldl_raw(p)
#define ldq_code(p) ldq_raw(p)

#define ldub_kernel(p) ldub_raw(p)
#define ldsb_kernel(p) ldsb_raw(p)
#define lduw_kernel(p) lduw_raw(p)
#define ldsw_kernel(p) ldsw_raw(p)
#define ldl_kernel(p) ldl_raw(p)
#define ldq_kernel(p) ldq_raw(p)
#define ldfl_kernel(p) ldfl_raw(p)
#define ldfq_kernel(p) ldfq_raw(p)
#define stb_kernel(p, v) stb_raw(p, v)
#define stw_kernel(p, v) stw_raw(p, v)
#define stl_kernel(p, v) stl_raw(p, v)
#define stq_kernel(p, v) stq_raw(p, v)
#define stfl_kernel(p, v) stfl_raw(p, v)
#define stfq_kernel(p, vt) stfq_raw(p, v)

#endif /* defined(CONFIG_USER_ONLY) */

/* page related stuff */

#define TARGET_PAGE_SIZE (1 << TARGET_PAGE_BITS)
#define TARGET_PAGE_MASK ~(TARGET_PAGE_SIZE - 1)
#define TARGET_PAGE_ALIGN(addr) (((addr) + TARGET_PAGE_SIZE - 1) & TARGET_PAGE_MASK)

/* ??? These should be the larger of unsigned long and target_ulong.  */
extern unsigned long qemu_real_host_page_size;
extern unsigned long qemu_host_page_bits;
extern unsigned long qemu_host_page_size;
extern unsigned long qemu_host_page_mask;

#define HOST_PAGE_ALIGN(addr) (((addr) + qemu_host_page_size - 1) & qemu_host_page_mask)

/* same as PROT_xxx */
#define PAGE_READ      0x0001
#define PAGE_WRITE     0x0002
#define PAGE_EXEC      0x0004
#define PAGE_BITS      (PAGE_READ | PAGE_WRITE | PAGE_EXEC)
#define PAGE_VALID     0x0008
/* original state of the write flag (used when tracking self-modifying
   code */
#define PAGE_WRITE_ORG 0x0010
#define PAGE_RESERVED  0x0020

void page_dump(FILE *f);
int page_get_flags(target_ulong address);
void page_set_flags(target_ulong start, target_ulong end, int flags);
int page_check_range(target_ulong start, target_ulong len, int flags);

CPUState *cpu_copy(CPUState *env);

void cpu_dump_state(CPUState *env, FILE *f,
                    int (*cpu_fprintf)(FILE *f, const char *fmt, ...),
                    int flags);
void cpu_dump_statistics (CPUState *env, FILE *f,
                          int (*cpu_fprintf)(FILE *f, const char *fmt, ...),
                          int flags);

void cpu_abort(CPUState *env, const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)))
    __attribute__ ((__noreturn__));
extern CPUState *cpu_single_env;

#define CPU_INTERRUPT_EXIT   0x01 /* wants exit from main loop */
#define CPU_INTERRUPT_HARD   0x02 /* hardware interrupt pending */
#define CPU_INTERRUPT_EXITTB 0x04 /* exit the current TB (use for x86 a20 case) */
#define CPU_INTERRUPT_TIMER  0x08 /* internal timer exception pending */
#define CPU_INTERRUPT_FIQ    0x10 /* Fast interrupt pending.  */
#define CPU_INTERRUPT_HALT   0x20 /* CPU halt wanted */
#define CPU_INTERRUPT_SMI    0x40 /* (x86 only) SMI interrupt pending */
#define CPU_INTERRUPT_DEBUG  0x80 /* Debug event occured.  */
#define CPU_INTERRUPT_VIRQ   0x100 /* virtual interrupt pending.  */

void cpu_interrupt(CPUState *s, int mask);
void cpu_reset_interrupt(CPUState *env, int mask);

int cpu_watchpoint_insert(CPUState *env, target_ulong addr);
int cpu_watchpoint_remove(CPUState *env, target_ulong addr);
int cpu_breakpoint_insert(CPUState *env, target_ulong pc);
int cpu_breakpoint_remove(CPUState *env, target_ulong pc);
void cpu_single_step(CPUState *env, int enabled);
void cpu_reset(CPUState *s);

/* Return the physical page corresponding to a virtual one. Use it
   only for debugging because no protection checks are done. Return -1
   if no page found. */
target_phys_addr_t cpu_get_phys_page_debug(CPUState *env, target_ulong addr);

#define CPU_LOG_TB_OUT_ASM (1 << 0)
#define CPU_LOG_TB_IN_ASM  (1 << 1)
#define CPU_LOG_TB_OP      (1 << 2)
#define CPU_LOG_TB_OP_OPT  (1 << 3)
#define CPU_LOG_INT        (1 << 4)
#define CPU_LOG_EXEC       (1 << 5)
#define CPU_LOG_PCALL      (1 << 6)
#define CPU_LOG_IOPORT     (1 << 7)
#define CPU_LOG_TB_CPU     (1 << 8)

/* define log items */
typedef struct CPULogItem {
    int mask;
    const char *name;
    const char *help;
} CPULogItem;

void cpu_set_log(int log_flags);
void cpu_set_log_filename(const char *filename);
int cpu_str_to_log_mask(const char *str);

/* IO ports API */

/* NOTE: as these functions may be even used when there is an isa
   brige on non x86 targets, we always defined them */
#ifndef NO_CPU_IO_DEFS
void cpu_outb(CPUState *env, int addr, int val);
void cpu_outw(CPUState *env, int addr, int val);
void cpu_outl(CPUState *env, int addr, int val);
int cpu_inb(CPUState *env, int addr);
int cpu_inw(CPUState *env, int addr);
int cpu_inl(CPUState *env, int addr);
#endif

/* memory API */

extern uint8_t *phys_ram_base;

/* physical memory access */
#define TLB_INVALID_MASK   (1 << 3)
#define IO_MEM_SHIFT       4
#define IO_MEM_NB_ENTRIES  (1 << (TARGET_PAGE_BITS  - IO_MEM_SHIFT))

#define IO_MEM_RAM         (0 << IO_MEM_SHIFT) /* hardcoded offset */
#define IO_MEM_ROM         (1 << IO_MEM_SHIFT) /* hardcoded offset */
#define IO_MEM_UNASSIGNED  (2 << IO_MEM_SHIFT)
#define IO_MEM_NOTDIRTY    (4 << IO_MEM_SHIFT) /* used internally, never use directly */
/* acts like a ROM when read and like a device when written. As an
   exception, the write memory callback gets the ram offset instead of
   the physical address */
#define IO_MEM_ROMD        (1)
#define IO_MEM_SUBPAGE     (2)
#define IO_MEM_SUBWIDTH    (4)

typedef void CPUWriteMemoryFunc(void *opaque, target_phys_addr_t addr, uint32_t value);
typedef uint32_t CPUReadMemoryFunc(void *opaque, target_phys_addr_t addr);

void cpu_register_physical_memory(target_phys_addr_t start_addr,
                                  unsigned long size,
                                  unsigned long phys_offset);
uint32_t cpu_get_physical_page_desc(target_phys_addr_t addr);
int cpu_register_io_memory(int io_index,
                           CPUReadMemoryFunc **mem_read,
                           CPUWriteMemoryFunc **mem_write,
                           void *opaque);
CPUWriteMemoryFunc **cpu_get_io_memory_write(int io_index);
CPUReadMemoryFunc **cpu_get_io_memory_read(int io_index);

void cpu_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf,
                            int len, int is_write);
static inline void cpu_physical_memory_read(target_phys_addr_t addr,
                                            uint8_t *buf, int len)
{
    cpu_physical_memory_rw(addr, buf, len, 0);
}
static inline void cpu_physical_memory_write(target_phys_addr_t addr,
                                             const uint8_t *buf, int len)
{
    cpu_physical_memory_rw(addr, (uint8_t *)buf, len, 1);
}
uint32_t ldub_phys(target_phys_addr_t addr);
uint32_t lduw_phys(target_phys_addr_t addr);
uint32_t ldl_phys(target_phys_addr_t addr);
uint64_t ldq_phys(target_phys_addr_t addr);
void stl_phys_notdirty(target_phys_addr_t addr, uint32_t val);
void stq_phys_notdirty(target_phys_addr_t addr, uint64_t val);
void stb_phys(target_phys_addr_t addr, uint32_t val);
void stw_phys(target_phys_addr_t addr, uint32_t val);
void stl_phys(target_phys_addr_t addr, uint32_t val);
void stq_phys(target_phys_addr_t addr, uint64_t val);

void cpu_physical_memory_write_rom(target_phys_addr_t addr,
                                   const uint8_t *buf, int len);
int cpu_memory_rw_debug(CPUState *env, target_ulong addr,
                        uint8_t *buf, int len, int is_write);

#define VGA_DIRTY_FLAG  0x01
#define CODE_DIRTY_FLAG 0x02

/* read dirty bit (return 0 or 1) */
static inline int cpu_physical_memory_is_dirty(ram_addr_t addr)
{
    return crt_qemu_instance->phys_ram_dirty[addr >> TARGET_PAGE_BITS] == 0xff;
}

static inline int cpu_physical_memory_get_dirty(ram_addr_t addr,
                                                int dirty_flags)
{
    return crt_qemu_instance->phys_ram_dirty[addr >> TARGET_PAGE_BITS] & dirty_flags;
}

static inline void cpu_physical_memory_set_dirty(ram_addr_t addr)
{
    crt_qemu_instance->phys_ram_dirty[addr >> TARGET_PAGE_BITS] = 0xff;
}

void cpu_physical_memory_reset_dirty(ram_addr_t start, ram_addr_t end,
                                     int dirty_flags);
void cpu_tlb_update_dirty(CPUState *env);

void dump_exec_info(FILE *f,
                    int (*cpu_fprintf)(FILE *f, const char *fmt, ...));

/*******************************************/
/* host CPU ticks (if available) */

#if defined(__powerpc__)

static inline uint32_t get_tbl(void)
{
    uint32_t tbl;
    asm volatile("mftb %0" : "=r" (tbl));
    return tbl;
}

static inline uint32_t get_tbu(void)
{
	uint32_t tbl;
	asm volatile("mftbu %0" : "=r" (tbl));
	return tbl;
}

static inline int64_t cpu_get_real_ticks(void)
{
    uint32_t l, h, h1;
    /* NOTE: we test if wrapping has occurred */
    do {
        h = get_tbu();
        l = get_tbl();
        h1 = get_tbu();
    } while (h != h1);
    return ((int64_t)h << 32) | l;
}

#elif defined(__i386__)

static inline int64_t cpu_get_real_ticks(void)
{
    int64_t val;
    asm volatile ("rdtsc" : "=A" (val));
    return val;
}

#elif defined(__x86_64__)

static inline int64_t cpu_get_real_ticks(void)
{
    uint32_t low,high;
    int64_t val;
    asm volatile("rdtsc" : "=a" (low), "=d" (high));
    val = high;
    val <<= 32;
    val |= low;
    return val;
}

#elif defined(__ia64)

static inline int64_t cpu_get_real_ticks(void)
{
	int64_t val;
	asm volatile ("mov %0 = ar.itc" : "=r"(val) :: "memory");
	return val;
}

#elif defined(__s390__)

static inline int64_t cpu_get_real_ticks(void)
{
    int64_t val;
    asm volatile("stck 0(%1)" : "=m" (val) : "a" (&val) : "cc");
    return val;
}

#elif defined(__sparc_v8plus__) || defined(__sparc_v8plusa__) || defined(__sparc_v9__)

static inline int64_t cpu_get_real_ticks (void)
{
#if     defined(_LP64)
        uint64_t        rval;
        asm volatile("rd %%tick,%0" : "=r"(rval));
        return rval;
#else
        union {
                uint64_t i64;
                struct {
                        uint32_t high;
                        uint32_t low;
                }       i32;
        } rval;
        asm volatile("rd %%tick,%1; srlx %1,32,%0"
                : "=r"(rval.i32.high), "=r"(rval.i32.low));
        return rval.i64;
#endif
}

#elif defined(__mips__)

static inline int64_t cpu_get_real_ticks(void)
{
#if __mips_isa_rev >= 2
    uint32_t count;
    static uint32_t cyc_per_count = 0;

    if (!cyc_per_count)
        __asm__ __volatile__("rdhwr %0, $3" : "=r" (cyc_per_count));

    __asm__ __volatile__("rdhwr %1, $2" : "=r" (count));
    return (int64_t)(count * cyc_per_count);
#else
    /* FIXME */
    static int64_t ticks = 0;
    return ticks++;
#endif
}

#else
/* The host CPU doesn't have an easily accessible cycle counter.
   Just return a monotonically increasing value.  This will be
   totally wrong, but hopefully better than nothing.  */
static inline int64_t cpu_get_real_ticks (void)
{
    static int64_t ticks = 0;
    return ticks++;
}
#endif

/* profiling */
#ifdef CONFIG_PROFILER
static inline int64_t profile_getclock(void)
{
    return cpu_get_real_ticks();
}

extern int64_t kqemu_time, kqemu_time_start;
extern int64_t qemu_time, qemu_time_start;
extern int64_t tlb_flush_time;
extern int64_t kqemu_exec_count;
extern int64_t dev_time;
extern int64_t kqemu_ret_int_count;
extern int64_t kqemu_ret_excp_count;
extern int64_t kqemu_ret_intr_count;

#endif

#endif /* CPU_ALL_H */
