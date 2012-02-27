/*
 *  i386 emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
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
#include <stdlib.h>
#include <cfg.h>
#include "config.h"
#include "exec.h"
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <string.h>
#include "qemu_encap.h"
#include "gdb_srv.h"

static int cpu_halted_systemc(void);

#if !defined(CONFIG_SOFTMMU)
#undef EAX
#undef ECX
#undef EDX
#undef EBX
#undef ESP
#undef EBP
#undef ESI
#undef EDI
#undef EIP
#include <signal.h>
#include <sys/ucontext.h>
#include <byteswap.h>
#endif

//#define DEBUG_EXEC
//#define DEBUG_SIGNAL

#define SAVE_GLOBALS()
#define RESTORE_GLOBALS()

#if defined(__sparc__) && !defined(HOST_SOLARIS)
#include <features.h>
#if defined(__GLIBC__) && ((__GLIBC__ < 2) || \
                           ((__GLIBC__ == 2) && (__GLIBC_MINOR__ <= 90)))
// Work around ugly bugs in glibc that mangle global register contents

static volatile void *saved_env;
static volatile unsigned long saved_t0, saved_i7;
#undef SAVE_GLOBALS
#define SAVE_GLOBALS() do {                                     \
        saved_env = env;                                        \
        saved_t0 = T0;                                          \
        asm volatile ("st %%i7, [%0]" : : "r" (&saved_i7));     \
    } while(0)

#undef RESTORE_GLOBALS
#define RESTORE_GLOBALS() do {                                  \
        env = (void *)saved_env;                                \
        T0 = saved_t0;                                          \
        asm volatile ("ld [%0], %%i7" : : "r" (&saved_i7));     \
    } while(0)

static int sparc_setjmp(jmp_buf buf)
{
    int ret;

    SAVE_GLOBALS();
    ret = setjmp(buf);
    RESTORE_GLOBALS();
    return ret;
}
#undef setjmp
#define setjmp(jmp_buf) sparc_setjmp(jmp_buf)

static void sparc_longjmp(jmp_buf buf, int val)
{
    SAVE_GLOBALS();
    longjmp(buf, val);
}
#define longjmp(jmp_buf, val) sparc_longjmp(jmp_buf, val)
#endif
#endif


//#define DEBUG_TB_ALLOC
#ifdef DEBUG_TB_ALLOC
    #define DTBALLOCPRINTF printf
#else
    #define DTBALLOCPRINTF if (0) printf
#endif

void
qemu_invalidate_address (qemu_instance *instance, unsigned long addr, int src_idx);

void cpu_loop_exit(void)
{
    /* NOTE: the register at this point must be saved by hand because
       longjmp restore them */
    regs_to_env();
    longjmp(env->jmp_env, 1);
}

#if !(defined(TARGET_SPARC) || defined(TARGET_SH4) || defined(TARGET_M68K))
#define reg_T2
#endif

/* exit the current TB from a signal handler. The host registers are
   restored in a state compatible with the CPU emulator
 */
void cpu_resume_from_signal(CPUState *env1, void *puc)
{
#if !defined(CONFIG_SOFTMMU)
    struct ucontext *uc = puc;
#endif

    env = env1;

    /* XXX: restore cpu registers saved in host registers */

#if !defined(CONFIG_SOFTMMU)
    if (puc) {
        /* XXX: use siglongjmp ? */
        sigprocmask(SIG_SETMASK, &uc->uc_sigmask, NULL);
    }
#endif
    longjmp(env->jmp_env, 1);
}

unsigned char b_use_backdoor = 0;
#define macro_tb_phys_hash ((TranslationBlock *(*)) crt_qemu_instance->tb_phys_hash)

static TranslationBlock *tb_find_slow(target_ulong pc,
                                      target_ulong cs_base,
                                      uint64_t flags)
{
    TranslationBlock *tb, **ptb1;
    int code_gen_size;
    unsigned int h;
    target_ulong phys_pc, phys_page1, phys_page2, virt_page2;
    uint8_t *tc_ptr;

    /* spin_lock(&tb_lock); */

    regs_to_env(); /* XXX: do it just before cpu_gen_code() */

    env->tb_invalidated_flag = 0;

    /* find translated block using physical mappings */
    phys_pc = get_phys_addr_code(env, pc);
    phys_page1 = phys_pc & TARGET_PAGE_MASK;
    phys_page2 = -1;
    h = tb_phys_hash_func(phys_pc);
    ptb1 = &macro_tb_phys_hash[h];
    for(;;) {
        tb = *ptb1;
        if (!tb)
            goto not_found;
        if (tb->pc == pc &&
            tb->page_addr[0] == phys_page1 &&
            tb->cs_base == cs_base &&
            tb->flags == flags) {
            /* check next page if needed */
            if (tb->page_addr[1] != -1) {
                virt_page2 = (pc & TARGET_PAGE_MASK) +
                    TARGET_PAGE_SIZE;
                phys_page2 = get_phys_addr_code(env, virt_page2);
                if (tb->page_addr[1] == phys_page2)
                    goto found;
            } else {
                goto found;
            }
        }
        ptb1 = &tb->phys_hash_next;
    }
 not_found:
    /* if no translated code available, then translate it now */
    tb = tb_alloc(pc);
    if (!tb) {
        /* flush must be done */
        tb_flush(env);
        /* cannot fail at this point */
        tb = tb_alloc(pc);
        /* don't forget to invalidate previous TB info */
        env->tb_invalidated_flag = 1;
    }
    tc_ptr = crt_qemu_instance->code_gen_ptr;
    tb->tc_ptr = tc_ptr;
    tb->cs_base = cs_base;
    tb->flags = flags;
    SAVE_GLOBALS();
    cpu_gen_code(env, tb, &code_gen_size);
    RESTORE_GLOBALS();
    crt_qemu_instance->code_gen_ptr =
        (void *)(((unsigned long)crt_qemu_instance->code_gen_ptr +
        code_gen_size + CODE_GEN_ALIGN - 1) & ~(CODE_GEN_ALIGN - 1));

    tb->flush_tc_end = crt_qemu_instance->code_gen_ptr;

    /* check next page if needed */
    virt_page2 = (pc + tb->size - 1) & TARGET_PAGE_MASK;
    phys_page2 = -1;
    if ((pc & TARGET_PAGE_MASK) != virt_page2) {
        phys_page2 = get_phys_addr_code(env, virt_page2);
    }
    tb_link_phys(tb, phys_pc, phys_page2);

 found:
    /* we add the TB in the virtual pc hash table */
    env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
    /* spin_unlock(&tb_lock); */

    return tb;
}

static inline TranslationBlock *tb_find_fast(void)
{
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint64_t flags;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
#if defined(TARGET_I386)
    flags = env->hflags;
    flags |= (env->eflags & (IOPL_MASK | TF_MASK | VM_MASK));
    flags |= env->intercept;
    cs_base = env->segs[R_CS].base;
    pc = cs_base + env->eip;
#elif defined(TARGET_ARM)
    flags = env->thumb | (env->vfp.vec_len << 1)
            | (env->vfp.vec_stride << 4);
    if ((env->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_USR)
        flags |= (1 << 6);
    if (env->vfp.xregs[ARM_VFP_FPEXC] & (1 << 30))
        flags |= (1 << 7);
    flags |= (env->condexec_bits << 8);
    cs_base = 0;
    pc = env->regs[15];
#elif defined(TARGET_SPARC)
#ifdef TARGET_SPARC64
    // Combined FPU enable bits . PRIV . DMMU enabled . IMMU enabled
    flags = (((env->pstate & PS_PEF) >> 1) | ((env->fprs & FPRS_FEF) << 2))
        | (env->pstate & PS_PRIV) | ((env->lsu & (DMMU_E | IMMU_E)) >> 2);
#else
    // FPU enable . Supervisor
    flags = (env->psref << 4) | env->psrs;
#endif
    cs_base = env->npc;
    pc = env->pc;
#elif defined(TARGET_PPC)
    flags = env->hflags;
    cs_base = 0;
    pc = env->nip;
#elif defined(TARGET_MIPS)
    flags = env->hflags & (MIPS_HFLAG_TMASK | MIPS_HFLAG_BMASK);
    cs_base = 0;
    pc = env->PC[env->current_tc];
#elif defined(TARGET_M68K)
    flags = (env->fpcr & M68K_FPCR_PREC)  /* Bit  6 */
            | (env->sr & SR_S)            /* Bit  13 */
            | ((env->macsr >> 4) & 0xf);  /* Bits 0-3 */
    cs_base = 0;
    pc = env->pc;
#elif defined(TARGET_SH4)
    flags = env->flags;
    cs_base = 0;
    pc = env->pc;
#elif defined(TARGET_ALPHA)
    flags = env->ps;
    cs_base = 0;
    pc = env->pc;
#elif defined(TARGET_CRIS)
    flags = 0;
    cs_base = 0;
    pc = env->pc;
#else
#error unsupported CPU
#endif
    tb = env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    if (__builtin_expect(!tb || tb->pc != pc || tb->cs_base != cs_base ||
                         tb->flags != flags, 0)) {
        tb = tb_find_slow(pc, cs_base, flags);
        /* Note: we do it here to avoid a gcc bug on Mac OS X when
           doing it in tb_find_slow */
        if (env->tb_invalidated_flag) {
            /* as some TB could have been invalidated because
               of memory exceptions while generating the code, we
               must recompute the hash index here */
            T0 = 0;
        }
    }
    return tb;
}

#define BREAK_CHAIN T0 = 0

static void flush_orphan_tb ()
{
    if (cpu_single_env->flush_last_tb == NULL)
        return;

    TranslationBlock    *tb = cpu_single_env->flush_last_tb;
    int                 tb_idx = ((unsigned long) tb -
        (unsigned long) crt_qemu_instance->tbs) / sizeof (TranslationBlock);

    cpu_single_env->flush_last_tb = NULL;

    if (cpu_single_env->need_flush)
    {
        if (!tb->flush_cnt)
        {
            printf ("%s: env->need_flush=%d, tb->flush_cnt=%d\n",
                __FUNCTION__, cpu_single_env->need_flush, tb->flush_cnt);
            exit (1);
        }
        if (tb_idx != cpu_single_env->flush_idx_blocked_tb)
        {
            printf ("%s: tb blocked=%d, tb freed=%d!\n",
                __FUNCTION__, cpu_single_env->flush_idx_blocked_tb, tb_idx);
            exit (1);
        }

        cpu_single_env->need_flush = 0;
        cpu_single_env->flush_idx_blocked_tb = -1;
        tb->flush_cnt--;
        T0 = 0;

        DTBALLOCPRINTF ("FREE cpu=%d, tb=%d, pc=0x%lx, cnt=%d\n",
            cpu_single_env->cpu_index,
            tb_idx,
            (unsigned long) tb->pc, tb->flush_cnt);

        if (tb->flush_cnt == 0)
        {
            TranslationBlock    **ptb;
            ptb = (struct TranslationBlock **) &crt_qemu_instance->flush_head;
            while (*ptb && *ptb != tb)
                ptb = & (*ptb)->flush_next;
            if (!*ptb)
            {
                printf ("%s: cannot find TB in the flushing list!\n", __FUNCTION__);
                exit (1);
            }
            *ptb = tb->flush_next;
            tb->flush_next = NULL;
        }
    }
}



/* main execution loop */

int cpu_exec(CPUState *env1)
{
    #define DECLARE_HOST_REGS 1
    #include "hostregs_helper.h"

    #if defined(TARGET_SPARC)
    #if defined(reg_REGWPTR)
    uint32_t *saved_regwptr;
    #endif
    #endif

    int ret, interrupt_request;
    void (*gen_func)(void);
    TranslationBlock *tb;
    uint8_t *tc_ptr;

    b_use_backdoor = 1;

    cpu_single_env = env1;

    if (cpu_halted_systemc () == EXCP_HALTED)
        return EXCP_HALTED;

    /* first we save global registers */
    #define SAVE_HOST_REGS 1
    #include "hostregs_helper.h"
    env = env1;
    SAVE_GLOBALS();
    env_to_regs();

    #if defined(TARGET_I386)
    /* put eflags in CPU temporary format */
    CC_SRC = env->eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    DF = 1 - (2 * ((env->eflags >> 10) & 1));
    CC_OP = CC_OP_EFLAGS;
    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    #elif defined(TARGET_SPARC)
    #if defined(reg_REGWPTR)
    saved_regwptr = REGWPTR;
    #endif
    #elif defined(TARGET_M68K)
    env->cc_op = CC_OP_FLAGS;
    env->cc_dest = env->sr & 0xf;
    env->cc_x = (env->sr >> 4) & 1;
    #elif defined(TARGET_ALPHA)
    #elif defined(TARGET_ARM)
    #elif defined(TARGET_PPC)
    #elif defined(TARGET_MIPS)
    #elif defined(TARGET_SH4)
    #elif defined(TARGET_CRIS)
    /* XXXXX */
    #else
    #error unsupported target CPU
    #endif

    env->exception_index = -1;

    /* prepare setjmp context for exception handling */
    for(;;) {
        if (setjmp(env->jmp_env) == 0) {
            env->current_tb = NULL;
            /* if an exception is pending, we execute it here */
            if (env->exception_index >= 0) {
                if (env->exception_index >= EXCP_INTERRUPT) {
                    /* exit request from the cpu execution loop */
                    ret = env->exception_index;
                    break;
                } else if (env->user_mode_only) {
                    /* if user mode only, we simulate a fake exception
                       which will be handled outside the cpu execution
                       loop */
                    #if defined(TARGET_I386)
                    do_interrupt_user (env->exception_index,
                        env->exception_is_int, env->error_code, env->exception_next_eip);
                    #endif

                    ret = env->exception_index;
                    break;
                } else {
                    #if defined(TARGET_I386)
                    /* simulate a real cpu exception. On i386, it can
                        trigger new exceptions, but we do not handle
                        double or triple faults yet. */
                    do_interrupt (env->exception_index,
                        env->exception_is_int, env->error_code, env->exception_next_eip, 0);
                    /* successfully delivered */
                    env->old_exception = -1;
                    #elif defined(TARGET_PPC)
                    do_interrupt (env);
                    #elif defined(TARGET_MIPS)
                    do_interrupt (env);
                    #elif defined(TARGET_SPARC)
                    do_interrupt (env->exception_index);
                    #elif defined(TARGET_ARM)
                    do_interrupt (env);
                    #elif defined(TARGET_SH4)
                    do_interrupt (env);
                    #elif defined(TARGET_ALPHA)
                    do_interrupt (env);
                    #elif defined(TARGET_CRIS)
                    do_interrupt (env);
                    #elif defined(TARGET_M68K)
                    do_interrupt (0);
                    #endif
                }
                env->exception_index = -1;
            }

            T0 = 0; /* force lookup of first TB */
            for(;;) {
                SAVE_GLOBALS();
                interrupt_request = env->interrupt_request;
                if (__builtin_expect(interrupt_request, 0)) {
                    if (interrupt_request & CPU_INTERRUPT_DEBUG) {
                        env->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
                        env->exception_index = EXCP_DEBUG;
                        cpu_loop_exit();
                    }

                    #if defined(TARGET_ARM) || defined(TARGET_SPARC) || defined(TARGET_MIPS) || \
                        defined(TARGET_PPC) || defined(TARGET_ALPHA) || defined(TARGET_CRIS)
                    if (interrupt_request & CPU_INTERRUPT_HALT) {
                        env->interrupt_request &= ~CPU_INTERRUPT_HALT;
                        env->halted = 1;
                        env->exception_index = EXCP_HLT;
                        cpu_loop_exit();
                    }
                    #endif

                    #if defined(TARGET_ARM)
                    if (interrupt_request & CPU_INTERRUPT_FIQ
                        && !(env->uncached_cpsr & CPSR_F)) {
                        env->exception_index = EXCP_FIQ;
                        do_interrupt(env);
                        BREAK_CHAIN;
                    }
                    /* ARMv7-M interrupt return works by loading a magic value
                       into the PC.  On real hardware the load causes the
                       return to occur.  The qemu implementation performs the
                       jump normally, then does the exception return when the
                       CPU tries to execute code at the magic address.
                       This will cause the magic PC value to be pushed to
                       the stack if an interrupt occured at the wrong time.
                       We avoid this by disabling interrupts when
                       pc contains a magic address.  */
                    if ((interrupt_request & CPU_INTERRUPT_HARD)
                        && ((IS_M(env) && (env->regs[15] < 0xfffffff0))
                            || !(env->uncached_cpsr & CPSR_I)))
                    {
                        env->exception_index = EXCP_IRQ;
                        do_interrupt(env);
                        BREAK_CHAIN;
                    }
                    #elif defined(TARGET_SPARC)
                    if ((interrupt_request & CPU_INTERRUPT_HARD) && (env->psret != 0))
                    {
                        int pil = env->interrupt_index & 15;
                        int type = env->interrupt_index & 0xf0;

                        if (((type == TT_EXTINT) && (pil == 15 || pil > env->psrpil)) || type != TT_EXTINT)
                        {
                            env->interrupt_request &= ~CPU_INTERRUPT_HARD;
                            do_interrupt (env->interrupt_index);
                            env->interrupt_index = 0;
                            #if !defined(TARGET_SPARC64) && !defined(CONFIG_USER_ONLY)
                            cpu_check_irqs (env);
                            #endif
                            BREAK_CHAIN;
                        }
                    }
                    else if (interrupt_request & CPU_INTERRUPT_TIMER)
                    {
                        //do_interrupt(0, 0, 0, 0, 0);
                        env->interrupt_request &= ~CPU_INTERRUPT_TIMER;
                    }
                    #endif

                   /* Don't use the cached interupt_request value,
                      do_interrupt may have updated the EXITTB flag. */
                    if (env->interrupt_request & CPU_INTERRUPT_EXITTB) {
                        env->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
                        /* ensure that no TB jump will be modified as
                           the program flow was changed */
                        BREAK_CHAIN;
                    }

                    if (interrupt_request & CPU_INTERRUPT_EXIT) {
                        env->interrupt_request &= ~CPU_INTERRUPT_EXIT;
                        env->exception_index = EXCP_INTERRUPT;
                        cpu_loop_exit();
                    }
                }
                tb = tb_find_fast();
                RESTORE_GLOBALS();
                /* see if we can patch the calling TB. When the TB
                   spans two pages, we cannot safely do a direct
                   jump. */
                if (T0 != 0 && tb->page_addr[1] == -1)
                {
                    TranslationBlock    *tb_prev = (TranslationBlock *)(long)(T0 & ~3);

                    if (tb_prev->flush_cnt == 0)
                    {
                        CPUState             *penv;
                        for (penv = (CPUState *) crt_qemu_instance->first_cpu;
                             penv != NULL; penv = penv->next_cpu)
                        {
                            if (tb_prev == penv->flush_last_tb && penv->interrupt_request)
                                break;
                        }

                        if (!penv)
                        {
                            DTBALLOCPRINTF ("LINK cpu=%d, tb=%lu.pc=0x%lx[%d]->tb=%lu.pc=0x%lx\n",
                                cpu_single_env->cpu_index,
                                ((unsigned long) tb_prev - (unsigned long) crt_qemu_instance->tbs) / sizeof (TranslationBlock),
                                (unsigned long) tb_prev->pc, T0 & 3,
                                ((unsigned long) tb - (unsigned long) crt_qemu_instance->tbs) / sizeof (TranslationBlock),
                                (unsigned long) tb->pc
                                );
                            tb_add_jump(tb_prev, T0 & 3, tb);
                        }
                        else
                            T0 = 0;
                    }
                    else
                        T0 = 0;
                }

                tc_ptr = tb->tc_ptr;
                env->current_tb = tb;
                /* execute the generated code */
                gen_func = (void *)tc_ptr;
                b_use_backdoor = 0;
                gen_func();
                b_use_backdoor = 1;
                env->current_tb = NULL;
                flush_orphan_tb ();
            } /* for(;;) */
        }
        else
        {
            env_to_regs();
            b_use_backdoor = 1;
            flush_orphan_tb ();
        }
    } /* for(;;) */


    #if defined(TARGET_I386)
    /* restore flags in standard format */
    env->eflags = env->eflags | cc_table[CC_OP].compute_all () | (DF & DF_MASK);
    #elif defined(TARGET_ARM)
    /* XXX: Save/restore host fpu exception state?.  */
    #elif defined(TARGET_SPARC)
    #if defined(reg_REGWPTR)
    REGWPTR = saved_regwptr;
    #endif
    #elif defined(TARGET_PPC)
    #elif defined(TARGET_M68K)
    cpu_m68k_flush_flags (env, env->cc_op);
    env->cc_op = CC_OP_FLAGS;
    env->sr = (env->sr & 0xffe0) | env->cc_dest | (env->cc_x << 4);
    #elif defined(TARGET_MIPS)
    #elif defined(TARGET_SH4)
    #elif defined(TARGET_ALPHA)
    #elif defined(TARGET_CRIS)
    /* XXXXX */
    #else
    #error unsupported target CPU
    #endif

    /* restore global registers */
    RESTORE_GLOBALS();
    #include "hostregs_helper.h"
    #include "cpu.h"

    /* fail safe : never use cpu_single_env outside cpu_exec() */
    cpu_single_env = NULL;
    return ret;
}

/* must only be called from the generated code as an exception can be
   generated */
void tb_invalidate_page_range(target_ulong start, target_ulong end)
{
    /* XXX: cannot enable it yet because it yields to MMU exception
       where NIP != read address on PowerPC */
#if 0
    target_ulong phys_addr;
    phys_addr = get_phys_addr_code(env, start);
    tb_invalidate_phys_page_range(phys_addr, phys_addr + end - start, 0);
#endif
}

#if defined(TARGET_I386) && defined(CONFIG_USER_ONLY)

void cpu_x86_load_seg(CPUX86State *s, int seg_reg, int selector)
{
    CPUX86State *saved_env;

    saved_env = env;
    env = s;
    if (!(env->cr[0] & CR0_PE_MASK) || (env->eflags & VM_MASK)) {
        selector &= 0xffff;
        cpu_x86_load_seg_cache(env, seg_reg, selector,
                               (selector << 4), 0xffff, 0);
    } else {
        load_seg(seg_reg, selector);
    }
    env = saved_env;
}

void cpu_x86_fsave(CPUX86State *s, target_ulong ptr, int data32)
{
    CPUX86State *saved_env;

    saved_env = env;
    env = s;

    helper_fsave(ptr, data32);

    env = saved_env;
}

void cpu_x86_frstor(CPUX86State *s, target_ulong ptr, int data32)
{
    CPUX86State *saved_env;

    saved_env = env;
    env = s;

    helper_frstor(ptr, data32);

    env = saved_env;
}

#endif /* TARGET_I386 */

#if !defined(CONFIG_SOFTMMU)

#if defined(TARGET_I386)

/* 'pc' is the host PC at which the exception was raised. 'address' is
   the effective address of the memory exception. 'is_write' is 1 if a
   write caused the exception and otherwise 0'. 'old_set' is the
   signal set which should be restored */
static inline int handle_cpu_signal(unsigned long pc, unsigned long address,
                                    int is_write, sigset_t *old_set,
                                    void *puc)
{
    TranslationBlock *tb;
    int ret;

    if (cpu_single_env)
        env = cpu_single_env; /* XXX: find a correct solution for multithread */
#if defined(DEBUG_SIGNAL)
    qemu_printf("qemu: SIGSEGV pc=0x%08lx address=%08lx w=%d oldset=0x%08lx\n",
                pc, address, is_write, *(unsigned long *)old_set);
#endif
    /* XXX: locking issue */
    if (is_write && page_unprotect(h2g(address), pc, puc)) {
        return 1;
    }

    /* see if it is an MMU fault */
    ret = cpu_x86_handle_mmu_fault(env, address, is_write, MMU_USER_IDX, 0);
    if (ret < 0)
        return 0; /* not an MMU fault */
    if (ret == 0)
        return 1; /* the MMU fault was handled without causing real CPU fault */
    /* now we have a real cpu fault */
    tb = tb_find_pc(pc);
    if (tb) {
        /* the PC is inside the translated code. It means that we have
           a virtual CPU fault */
        cpu_restore_state(tb, env, pc, puc);
    }
    if (ret == 1) {
#if 0
        printf("PF exception: EIP=0x%08x CR2=0x%08x error=0x%x\n",
               env->eip, env->cr[2], env->error_code);
#endif
        /* we restore the process signal mask as the sigreturn should
           do it (XXX: use sigsetjmp) */
        sigprocmask(SIG_SETMASK, old_set, NULL);
        raise_exception_err(env->exception_index, env->error_code);
    } else {
        /* activate soft MMU for this block */
        env->hflags |= HF_SOFTMMU_MASK;
        cpu_resume_from_signal(env, puc);
    }
    /* never comes here */
    return 1;
}

#elif defined(TARGET_ARM)
static inline int handle_cpu_signal(unsigned long pc, unsigned long address,
                                    int is_write, sigset_t *old_set,
                                    void *puc)
{
    TranslationBlock *tb;
    int ret;

    if (cpu_single_env)
        env = cpu_single_env; /* XXX: find a correct solution for multithread */
#if defined(DEBUG_SIGNAL)
    printf("qemu: SIGSEGV pc=0x%08lx address=%08lx w=%d oldset=0x%08lx\n",
           pc, address, is_write, *(unsigned long *)old_set);
#endif
    /* XXX: locking issue */
    if (is_write && page_unprotect(h2g(address), pc, puc)) {
        return 1;
    }
    /* see if it is an MMU fault */
    ret = cpu_arm_handle_mmu_fault(env, address, is_write, MMU_USER_IDX, 0);
    if (ret < 0)
        return 0; /* not an MMU fault */
    if (ret == 0)
        return 1; /* the MMU fault was handled without causing real CPU fault */
    /* now we have a real cpu fault */
    tb = tb_find_pc(pc);
    if (tb) {
        /* the PC is inside the translated code. It means that we have
           a virtual CPU fault */
        cpu_restore_state(tb, env, pc, puc);
    }
    /* we restore the process signal mask as the sigreturn should
       do it (XXX: use sigsetjmp) */
    sigprocmask(SIG_SETMASK, old_set, NULL);
    cpu_loop_exit();
}
#elif defined(TARGET_SPARC)
static inline int handle_cpu_signal(unsigned long pc, unsigned long address,
                                    int is_write, sigset_t *old_set,
                                    void *puc)
{
    TranslationBlock *tb;
    int ret;

    if (cpu_single_env)
        env = cpu_single_env; /* XXX: find a correct solution for multithread */
#if defined(DEBUG_SIGNAL)
    printf("qemu: SIGSEGV pc=0x%08lx address=%08lx w=%d oldset=0x%08lx\n",
           pc, address, is_write, *(unsigned long *)old_set);
#endif
    /* XXX: locking issue */
    if (is_write && page_unprotect(h2g(address), pc, puc)) {
        return 1;
    }
    /* see if it is an MMU fault */
    ret = cpu_sparc_handle_mmu_fault(env, address, is_write, MMU_USER_IDX, 0);
    if (ret < 0)
        return 0; /* not an MMU fault */
    if (ret == 0)
        return 1; /* the MMU fault was handled without causing real CPU fault */
    /* now we have a real cpu fault */
    tb = tb_find_pc(pc);
    if (tb) {
        /* the PC is inside the translated code. It means that we have
           a virtual CPU fault */
        cpu_restore_state(tb, env, pc, puc);
    }
    /* we restore the process signal mask as the sigreturn should
       do it (XXX: use sigsetjmp) */
    sigprocmask(SIG_SETMASK, old_set, NULL);
    cpu_loop_exit();
}
#elif defined (TARGET_PPC)
static inline int handle_cpu_signal(unsigned long pc, unsigned long address,
                                    int is_write, sigset_t *old_set,
                                    void *puc)
{
    TranslationBlock *tb;
    int ret;

    if (cpu_single_env)
        env = cpu_single_env; /* XXX: find a correct solution for multithread */
#if defined(DEBUG_SIGNAL)
    printf("qemu: SIGSEGV pc=0x%08lx address=%08lx w=%d oldset=0x%08lx\n",
           pc, address, is_write, *(unsigned long *)old_set);
#endif
    /* XXX: locking issue */
    if (is_write && page_unprotect(h2g(address), pc, puc)) {
        return 1;
    }

    /* see if it is an MMU fault */
    ret = cpu_ppc_handle_mmu_fault(env, address, is_write, MMU_USER_IDX, 0);
    if (ret < 0)
        return 0; /* not an MMU fault */
    if (ret == 0)
        return 1; /* the MMU fault was handled without causing real CPU fault */

    /* now we have a real cpu fault */
    tb = tb_find_pc(pc);
    if (tb) {
        /* the PC is inside the translated code. It means that we have
           a virtual CPU fault */
        cpu_restore_state(tb, env, pc, puc);
    }
    if (ret == 1) {
#if 0
        printf("PF exception: NIP=0x%08x error=0x%x %p\n",
               env->nip, env->error_code, tb);
#endif
    /* we restore the process signal mask as the sigreturn should
       do it (XXX: use sigsetjmp) */
        sigprocmask(SIG_SETMASK, old_set, NULL);
        do_raise_exception_err(env->exception_index, env->error_code);
    } else {
        /* activate soft MMU for this block */
        cpu_resume_from_signal(env, puc);
    }
    /* never comes here */
    return 1;
}

#elif defined(TARGET_M68K)
static inline int handle_cpu_signal(unsigned long pc, unsigned long address,
                                    int is_write, sigset_t *old_set,
                                    void *puc)
{
    TranslationBlock *tb;
    int ret;

    if (cpu_single_env)
        env = cpu_single_env; /* XXX: find a correct solution for multithread */
#if defined(DEBUG_SIGNAL)
    printf("qemu: SIGSEGV pc=0x%08lx address=%08lx w=%d oldset=0x%08lx\n",
           pc, address, is_write, *(unsigned long *)old_set);
#endif
    /* XXX: locking issue */
    if (is_write && page_unprotect(address, pc, puc)) {
        return 1;
    }
    /* see if it is an MMU fault */
    ret = cpu_m68k_handle_mmu_fault(env, address, is_write, MMU_USER_IDX, 0);
    if (ret < 0)
        return 0; /* not an MMU fault */
    if (ret == 0)
        return 1; /* the MMU fault was handled without causing real CPU fault */
    /* now we have a real cpu fault */
    tb = tb_find_pc(pc);
    if (tb) {
        /* the PC is inside the translated code. It means that we have
           a virtual CPU fault */
        cpu_restore_state(tb, env, pc, puc);
    }
    /* we restore the process signal mask as the sigreturn should
       do it (XXX: use sigsetjmp) */
    sigprocmask(SIG_SETMASK, old_set, NULL);
    cpu_loop_exit();
    /* never comes here */
    return 1;
}

#elif defined (TARGET_MIPS)
static inline int handle_cpu_signal(unsigned long pc, unsigned long address,
                                    int is_write, sigset_t *old_set,
                                    void *puc)
{
    TranslationBlock *tb;
    int ret;

    if (cpu_single_env)
        env = cpu_single_env; /* XXX: find a correct solution for multithread */
#if defined(DEBUG_SIGNAL)
    printf("qemu: SIGSEGV pc=0x%08lx address=%08lx w=%d oldset=0x%08lx\n",
           pc, address, is_write, *(unsigned long *)old_set);
#endif
    /* XXX: locking issue */
    if (is_write && page_unprotect(h2g(address), pc, puc)) {
        return 1;
    }

    /* see if it is an MMU fault */
    ret = cpu_mips_handle_mmu_fault(env, address, is_write, MMU_USER_IDX, 0);
    if (ret < 0)
        return 0; /* not an MMU fault */
    if (ret == 0)
        return 1; /* the MMU fault was handled without causing real CPU fault */

    /* now we have a real cpu fault */
    tb = tb_find_pc(pc);
    if (tb) {
        /* the PC is inside the translated code. It means that we have
           a virtual CPU fault */
        cpu_restore_state(tb, env, pc, puc);
    }
    if (ret == 1) {
#if 0
        printf("PF exception: PC=0x" TARGET_FMT_lx " error=0x%x %p\n",
               env->PC, env->error_code, tb);
#endif
    /* we restore the process signal mask as the sigreturn should
       do it (XXX: use sigsetjmp) */
        sigprocmask(SIG_SETMASK, old_set, NULL);
        do_raise_exception_err(env->exception_index, env->error_code);
    } else {
        /* activate soft MMU for this block */
        cpu_resume_from_signal(env, puc);
    }
    /* never comes here */
    return 1;
}

#elif defined (TARGET_SH4)
static inline int handle_cpu_signal(unsigned long pc, unsigned long address,
                                    int is_write, sigset_t *old_set,
                                    void *puc)
{
    TranslationBlock *tb;
    int ret;

    if (cpu_single_env)
        env = cpu_single_env; /* XXX: find a correct solution for multithread */
#if defined(DEBUG_SIGNAL)
    printf("qemu: SIGSEGV pc=0x%08lx address=%08lx w=%d oldset=0x%08lx\n",
           pc, address, is_write, *(unsigned long *)old_set);
#endif
    /* XXX: locking issue */
    if (is_write && page_unprotect(h2g(address), pc, puc)) {
        return 1;
    }

    /* see if it is an MMU fault */
    ret = cpu_sh4_handle_mmu_fault(env, address, is_write, MMU_USER_IDX, 0);
    if (ret < 0)
        return 0; /* not an MMU fault */
    if (ret == 0)
        return 1; /* the MMU fault was handled without causing real CPU fault */

    /* now we have a real cpu fault */
    tb = tb_find_pc(pc);
    if (tb) {
        /* the PC is inside the translated code. It means that we have
           a virtual CPU fault */
        cpu_restore_state(tb, env, pc, puc);
    }
#if 0
        printf("PF exception: NIP=0x%08x error=0x%x %p\n",
               env->nip, env->error_code, tb);
#endif
    /* we restore the process signal mask as the sigreturn should
       do it (XXX: use sigsetjmp) */
    sigprocmask(SIG_SETMASK, old_set, NULL);
    cpu_loop_exit();
    /* never comes here */
    return 1;
}

#elif defined (TARGET_ALPHA)
static inline int handle_cpu_signal(unsigned long pc, unsigned long address,
                                    int is_write, sigset_t *old_set,
                                    void *puc)
{
    TranslationBlock *tb;
    int ret;

    if (cpu_single_env)
        env = cpu_single_env; /* XXX: find a correct solution for multithread */
#if defined(DEBUG_SIGNAL)
    printf("qemu: SIGSEGV pc=0x%08lx address=%08lx w=%d oldset=0x%08lx\n",
           pc, address, is_write, *(unsigned long *)old_set);
#endif
    /* XXX: locking issue */
    if (is_write && page_unprotect(h2g(address), pc, puc)) {
        return 1;
    }

    /* see if it is an MMU fault */
    ret = cpu_alpha_handle_mmu_fault(env, address, is_write, MMU_USER_IDX, 0);
    if (ret < 0)
        return 0; /* not an MMU fault */
    if (ret == 0)
        return 1; /* the MMU fault was handled without causing real CPU fault */

    /* now we have a real cpu fault */
    tb = tb_find_pc(pc);
    if (tb) {
        /* the PC is inside the translated code. It means that we have
           a virtual CPU fault */
        cpu_restore_state(tb, env, pc, puc);
    }
#if 0
        printf("PF exception: NIP=0x%08x error=0x%x %p\n",
               env->nip, env->error_code, tb);
#endif
    /* we restore the process signal mask as the sigreturn should
       do it (XXX: use sigsetjmp) */
    sigprocmask(SIG_SETMASK, old_set, NULL);
    cpu_loop_exit();
    /* never comes here */
    return 1;
}
#elif defined (TARGET_CRIS)
static inline int handle_cpu_signal(unsigned long pc, unsigned long address,
                                    int is_write, sigset_t *old_set,
                                    void *puc)
{
    TranslationBlock *tb;
    int ret;

    if (cpu_single_env)
        env = cpu_single_env; /* XXX: find a correct solution for multithread */
#if defined(DEBUG_SIGNAL)
    printf("qemu: SIGSEGV pc=0x%08lx address=%08lx w=%d oldset=0x%08lx\n",
           pc, address, is_write, *(unsigned long *)old_set);
#endif
    /* XXX: locking issue */
    if (is_write && page_unprotect(h2g(address), pc, puc)) {
        return 1;
    }

    /* see if it is an MMU fault */
    ret = cpu_cris_handle_mmu_fault(env, address, is_write, MMU_USER_IDX, 0);
    if (ret < 0)
        return 0; /* not an MMU fault */
    if (ret == 0)
        return 1; /* the MMU fault was handled without causing real CPU fault */

    /* now we have a real cpu fault */
    tb = tb_find_pc(pc);
    if (tb) {
        /* the PC is inside the translated code. It means that we have
           a virtual CPU fault */
        cpu_restore_state(tb, env, pc, puc);
    }
#if 0
        printf("PF exception: NIP=0x%08x error=0x%x %p\n",
               env->nip, env->error_code, tb);
#endif
    /* we restore the process signal mask as the sigreturn should
       do it (XXX: use sigsetjmp) */
    sigprocmask(SIG_SETMASK, old_set, NULL);
    cpu_loop_exit();
    /* never comes here */
    return 1;
}

#else
#error unsupported target CPU
#endif

#if defined(__i386__)

#if defined(__APPLE__)
# include <sys/ucontext.h>

# define EIP_sig(context)  (*((unsigned long*)&(context)->uc_mcontext->ss.eip))
# define TRAP_sig(context)    ((context)->uc_mcontext->es.trapno)
# define ERROR_sig(context)   ((context)->uc_mcontext->es.err)
#else
# define EIP_sig(context)     ((context)->uc_mcontext.gregs[REG_EIP])
# define TRAP_sig(context)    ((context)->uc_mcontext.gregs[REG_TRAPNO])
# define ERROR_sig(context)   ((context)->uc_mcontext.gregs[REG_ERR])
#endif

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    struct ucontext *uc = puc;
    unsigned long pc;
    int trapno;

#ifndef REG_EIP
/* for glibc 2.1 */
#define REG_EIP    EIP
#define REG_ERR    ERR
#define REG_TRAPNO TRAPNO
#endif
    pc = EIP_sig(uc);
    trapno = TRAP_sig(uc);
    return handle_cpu_signal(pc, (unsigned long)info->si_addr,
                             trapno == 0xe ?
                             (ERROR_sig(uc) >> 1) & 1 : 0,
                             &uc->uc_sigmask, puc);
}

#elif defined(__x86_64__)

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    struct ucontext *uc = puc;
    unsigned long pc;

    pc = uc->uc_mcontext.gregs[REG_RIP];
    return handle_cpu_signal(pc, (unsigned long)info->si_addr,
                             uc->uc_mcontext.gregs[REG_TRAPNO] == 0xe ?
                             (uc->uc_mcontext.gregs[REG_ERR] >> 1) & 1 : 0,
                             &uc->uc_sigmask, puc);
}

#elif defined(__powerpc__)

/***********************************************************************
 * signal context platform-specific definitions
 * From Wine
 */
#ifdef linux
/* All Registers access - only for local access */
# define REG_sig(reg_name, context)		((context)->uc_mcontext.regs->reg_name)
/* Gpr Registers access  */
# define GPR_sig(reg_num, context)		REG_sig(gpr[reg_num], context)
# define IAR_sig(context)			REG_sig(nip, context)	/* Program counter */
# define MSR_sig(context)			REG_sig(msr, context)   /* Machine State Register (Supervisor) */
# define CTR_sig(context)			REG_sig(ctr, context)   /* Count register */
# define XER_sig(context)			REG_sig(xer, context) /* User's integer exception register */
# define LR_sig(context)			REG_sig(link, context) /* Link register */
# define CR_sig(context)			REG_sig(ccr, context) /* Condition register */
/* Float Registers access  */
# define FLOAT_sig(reg_num, context)		(((double*)((char*)((context)->uc_mcontext.regs+48*4)))[reg_num])
# define FPSCR_sig(context)			(*(int*)((char*)((context)->uc_mcontext.regs+(48+32*2)*4)))
/* Exception Registers access */
# define DAR_sig(context)			REG_sig(dar, context)
# define DSISR_sig(context)			REG_sig(dsisr, context)
# define TRAP_sig(context)			REG_sig(trap, context)
#endif /* linux */

#ifdef __APPLE__
# include <sys/ucontext.h>
typedef struct ucontext SIGCONTEXT;
/* All Registers access - only for local access */
# define REG_sig(reg_name, context)		((context)->uc_mcontext->ss.reg_name)
# define FLOATREG_sig(reg_name, context)	((context)->uc_mcontext->fs.reg_name)
# define EXCEPREG_sig(reg_name, context)	((context)->uc_mcontext->es.reg_name)
# define VECREG_sig(reg_name, context)		((context)->uc_mcontext->vs.reg_name)
/* Gpr Registers access */
# define GPR_sig(reg_num, context)		REG_sig(r##reg_num, context)
# define IAR_sig(context)			REG_sig(srr0, context)	/* Program counter */
# define MSR_sig(context)			REG_sig(srr1, context)  /* Machine State Register (Supervisor) */
# define CTR_sig(context)			REG_sig(ctr, context)
# define XER_sig(context)			REG_sig(xer, context) /* Link register */
# define LR_sig(context)			REG_sig(lr, context)  /* User's integer exception register */
# define CR_sig(context)			REG_sig(cr, context)  /* Condition register */
/* Float Registers access */
# define FLOAT_sig(reg_num, context)		FLOATREG_sig(fpregs[reg_num], context)
# define FPSCR_sig(context)			((double)FLOATREG_sig(fpscr, context))
/* Exception Registers access */
# define DAR_sig(context)			EXCEPREG_sig(dar, context)     /* Fault registers for coredump */
# define DSISR_sig(context)			EXCEPREG_sig(dsisr, context)
# define TRAP_sig(context)			EXCEPREG_sig(exception, context) /* number of powerpc exception taken */
#endif /* __APPLE__ */

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    struct ucontext *uc = puc;
    unsigned long pc;
    int is_write;

    pc = IAR_sig(uc);
    is_write = 0;
#if 0
    /* ppc 4xx case */
    if (DSISR_sig(uc) & 0x00800000)
        is_write = 1;
#else
    if (TRAP_sig(uc) != 0x400 && (DSISR_sig(uc) & 0x02000000))
        is_write = 1;
#endif
    return handle_cpu_signal(pc, (unsigned long)info->si_addr,
                             is_write, &uc->uc_sigmask, puc);
}

#elif defined(__alpha__)

int cpu_signal_handler(int host_signum, void *pinfo,
                           void *puc)
{
    siginfo_t *info = pinfo;
    struct ucontext *uc = puc;
    uint32_t *pc = uc->uc_mcontext.sc_pc;
    uint32_t insn = *pc;
    int is_write = 0;

    /* XXX: need kernel patch to get write flag faster */
    switch (insn >> 26) {
    case 0x0d: // stw
    case 0x0e: // stb
    case 0x0f: // stq_u
    case 0x24: // stf
    case 0x25: // stg
    case 0x26: // sts
    case 0x27: // stt
    case 0x2c: // stl
    case 0x2d: // stq
    case 0x2e: // stl_c
    case 0x2f: // stq_c
	is_write = 1;
    }

    return handle_cpu_signal(pc, (unsigned long)info->si_addr,
                             is_write, &uc->uc_sigmask, puc);
}
#elif defined(__sparc__)

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    uint32_t *regs = (uint32_t *)(info + 1);
    void *sigmask = (regs + 20);
    unsigned long pc;
    int is_write;
    uint32_t insn;

    /* XXX: is there a standard glibc define ? */
    pc = regs[1];
    /* XXX: need kernel patch to get write flag faster */
    is_write = 0;
    insn = *(uint32_t *)pc;
    if ((insn >> 30) == 3) {
      switch((insn >> 19) & 0x3f) {
      case 0x05: // stb
      case 0x06: // sth
      case 0x04: // st
      case 0x07: // std
      case 0x24: // stf
      case 0x27: // stdf
      case 0x25: // stfsr
	is_write = 1;
	break;
      }
    }
    return handle_cpu_signal(pc, (unsigned long)info->si_addr,
                             is_write, sigmask, NULL);
}

#elif defined(__arm__)

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    struct ucontext *uc = puc;
    unsigned long pc;
    int is_write;

    pc = uc->uc_mcontext.gregs[R15];
    /* XXX: compute is_write */
    is_write = 0;
    return handle_cpu_signal(pc, (unsigned long)info->si_addr,
                             is_write,
                             &uc->uc_sigmask, puc);
}

#elif defined(__mc68000)

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    struct ucontext *uc = puc;
    unsigned long pc;
    int is_write;

    pc = uc->uc_mcontext.gregs[16];
    /* XXX: compute is_write */
    is_write = 0;
    return handle_cpu_signal(pc, (unsigned long)info->si_addr,
                             is_write,
                             &uc->uc_sigmask, puc);
}

#elif defined(__ia64)

#ifndef __ISR_VALID
  /* This ought to be in <bits/siginfo.h>... */
# define __ISR_VALID	1
#endif

int cpu_signal_handler(int host_signum, void *pinfo, void *puc)
{
    siginfo_t *info = pinfo;
    struct ucontext *uc = puc;
    unsigned long ip;
    int is_write = 0;

    ip = uc->uc_mcontext.sc_ip;
    switch (host_signum) {
      case SIGILL:
      case SIGFPE:
      case SIGSEGV:
      case SIGBUS:
      case SIGTRAP:
	  if (info->si_code && (info->si_segvflags & __ISR_VALID))
	      /* ISR.W (write-access) is bit 33:  */
	      is_write = (info->si_isr >> 33) & 1;
	  break;

      default:
	  break;
    }
    return handle_cpu_signal(ip, (unsigned long)info->si_addr,
                             is_write,
                             &uc->uc_sigmask, puc);
}

#elif defined(__s390__)

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    struct ucontext *uc = puc;
    unsigned long pc;
    int is_write;

    pc = uc->uc_mcontext.psw.addr;
    /* XXX: compute is_write */
    is_write = 0;
    return handle_cpu_signal(pc, (unsigned long)info->si_addr,
                             is_write, &uc->uc_sigmask, puc);
}

#elif defined(__mips__)

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    struct ucontext *uc = puc;
    greg_t pc = uc->uc_mcontext.pc;
    int is_write;

    /* XXX: compute is_write */
    is_write = 0;
    return handle_cpu_signal(pc, (unsigned long)info->si_addr,
                             is_write, &uc->uc_sigmask, puc);
}

#else

#error host CPU specific signal handler needed

#endif

#endif /* !defined(CONFIG_SOFTMMU) */


//§§mari qemu_systemc
#include <assert.h>
#include <qemu_systemc.h>
#include <systemc_imports.h>
#include <../../components/qemu_wrapper/qemu_wrapper_cts.h>

//#define _DEBUG_READWRITE_HW_QEMU_SYSTEMC_

#ifdef _DEBUG_READWRITE_HW_QEMU_SYSTEMC_
#define DPRINTF printf
#else
#define DPRINTF if (0) printf
#endif

#define SAVE_ENV_BEFORE_CONSUME_SYSTEMC() \
    do{\
        qemu_instance   *_save_crt_qemu_instance = crt_qemu_instance; \
        CPUState        *_save_cpu_single_env = cpu_single_env; \
        CPUState        *_save_env = env; \
        crt_qemu_instance = NULL; \
        env = NULL; \
        cpu_single_env = NULL; \
        uint32_t        _save_T0 = T0; \
        uint32_t        _save_T1 = T1; \
        unsigned char   _save_b_use_backdoor = b_use_backdoor

#define RESTORE_ENV_AFTER_CONSUME_SYSTEMC() \
        crt_qemu_instance = _save_crt_qemu_instance; \
        cpu_single_env = _save_cpu_single_env; \
        env = _save_env; \
        T0 = _save_T0; \
        T1 = _save_T1; \
        b_use_backdoor = _save_b_use_backdoor; \
    }while (0)


#ifdef IMPLEMENT_LATE_CACHES
#define CACHE_LATE_SYNC_MISSES() \
do { \
    unsigned long   ns_misses = s_crt_ns_misses;\
    if (ns_misses) { \
        s_crt_ns_misses = 0; \
        _save_crt_qemu_instance->systemc.systemc_qemu_consume_ns (ns_misses); \
    } \
} while (0)
#else
#define CACHE_LATE_SYNC_MISSES()
#endif

unsigned long s_crt_nr_cycles_instr = 0;
unsigned long s_crt_ns_misses = 0; //for cache late configuration
unsigned long long g_crt_nr_instr = 0;
unsigned long long g_no_dcache_miss = 0;
unsigned long long g_no_icache_miss = 0;
unsigned long long g_no_write = 0;
unsigned long long g_no_uncached = 0;

void
qemu_get_counters (unsigned long long *no_instr,
    unsigned long long *no_dcache_miss,
    unsigned long long *no_write,
    unsigned long long *no_icache_miss,
    unsigned long long *no_uncached)
{
    *no_instr = g_crt_nr_instr;
    *no_dcache_miss = g_no_dcache_miss;
    *no_write = g_no_write;
    *no_icache_miss = g_no_icache_miss;
    *no_uncached = g_no_uncached;
}

static inline uint32_t
qemu_systemc_read_all (void *opaque, target_phys_addr_t offset,
    unsigned char nbytes, int bIO)
{
    uint32_t value = 0xFFFFFFFF;

    SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();

    int ninstr = s_crt_nr_cycles_instr;
    s_crt_nr_cycles_instr = 0;

    CACHE_LATE_SYNC_MISSES ();

    if (ninstr)
    {
        _save_crt_qemu_instance->systemc.systemc_qemu_consume_instruction_cycles (
            _save_cpu_single_env->qemu.sc_obj, ninstr);
    }

    value = _save_crt_qemu_instance->systemc.systemc_qemu_read_memory
        (_save_cpu_single_env->qemu.sc_obj, offset, nbytes, bIO, NULL);

    RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();

    return value;
}

static inline void
qemu_systemc_write_all (void *opaque, target_phys_addr_t offset, uint32_t value,
    unsigned char nbytes, int bIO)
{
    SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();

    int ninstr = s_crt_nr_cycles_instr;
    s_crt_nr_cycles_instr = 0;

    CACHE_LATE_SYNC_MISSES ();

    if (ninstr)
    {
        _save_crt_qemu_instance->systemc.systemc_qemu_consume_instruction_cycles (
            _save_cpu_single_env->qemu.sc_obj, ninstr);
    }

    _save_crt_qemu_instance->systemc.systemc_qemu_write_memory
        (_save_cpu_single_env->qemu.sc_obj, offset, value, nbytes, bIO, NULL);

    RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
}

void just_synchronize (void)
{
    SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();

    int ninstr = s_crt_nr_cycles_instr;
    s_crt_nr_cycles_instr = 0;

    CACHE_LATE_SYNC_MISSES ();

    if (ninstr)
    {
        _save_crt_qemu_instance->systemc.systemc_qemu_consume_instruction_cycles (
            _save_cpu_single_env->qemu.sc_obj, ninstr);
    }
    RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
}

void call_wait_wb_empty ()
{
    SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
    _save_crt_qemu_instance->systemc.wait_wb_empty (_save_cpu_single_env->qemu.sc_obj);
    RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
}

static uint32_t
qemu_systemc_read_b (void *opaque, target_phys_addr_t offset)
{
    return qemu_systemc_read_all (opaque, offset, 1, 1);
}

static void
qemu_systemc_write_b (void *opaque, target_phys_addr_t offset, uint32_t value)
{
     qemu_systemc_write_all (opaque, offset, value, 1, 1);
}

static uint32_t
qemu_systemc_read_w (void *opaque, target_phys_addr_t offset)
{
    return qemu_systemc_read_all (opaque, offset, 2, 1);
}

static void
qemu_systemc_write_w (void *opaque, target_phys_addr_t offset, uint32_t value)
{
    qemu_systemc_write_all (opaque, offset, value, 2, 1);
}

static uint32_t
qemu_systemc_read_dw (void *opaque, target_phys_addr_t offset)
{
    return qemu_systemc_read_all (opaque, offset, 4, 1);
}

static void
qemu_systemc_write_dw (void *opaque, target_phys_addr_t offset, uint32_t value)
{
    qemu_systemc_write_all (opaque, offset, value, 4, 1);
}

static CPUReadMemoryFunc *qemu_systemc_readfn[] =
{
    qemu_systemc_read_b,
    qemu_systemc_read_w,
    qemu_systemc_read_dw,
};

static CPUWriteMemoryFunc *qemu_systemc_writefn[] =
{
    qemu_systemc_write_b,
    qemu_systemc_write_w,
    qemu_systemc_write_dw,
};

void
qemu_add_map (qemu_instance *instance, unsigned long base, unsigned long size, int type)
{
    int iomemtype;
    qemu_instance       *save_instance;

    save_instance = crt_qemu_instance;
    crt_qemu_instance = instance;

    iomemtype = cpu_register_io_memory (0, qemu_systemc_readfn, qemu_systemc_writefn, 0);
    cpu_register_physical_memory (base, size, iomemtype);

    crt_qemu_instance = save_instance;
}

void
qemu_set_cpu_fv_percent (CPUState * penv, unsigned long fv_percent)
{
    penv->qemu.fv_percent = (fv_percent > 0) ? fv_percent : 100;
}

int irq_pending (CPUState *penv)
{
    #if defined(TARGET_ARM)
        return (penv->interrupt_request & (CPU_INTERRUPT_FIQ | CPU_INTERRUPT_HARD));
    #elif defined (TARGET_SPARC)
        return ((penv->interrupt_request & CPU_INTERRUPT_HARD) && (penv->psret != 0));
    #else
        #error CPU not implemented in irq_pending
    #endif
}

void
tb_start (TranslationBlock *tb)
{
    cpu_single_env->flush_last_tb = tb;

    if (s_crt_nr_cycles_instr > 2000)
    {
        just_synchronize ();
    }
}

static int
cpu_halted_systemc ()
{
    if (cpu_single_env->halted)
    {
        if (irq_pending (cpu_single_env))
            cpu_single_env->halted = 0;
        else
            return EXCP_HALTED;
    }

    return 0;
}

int64_t
qemu_get_clock_with_systemc ()
{
    if (cpu_single_env == NULL)
        return 0;

    SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();

    int ninstr = s_crt_nr_cycles_instr;
    s_crt_nr_cycles_instr = 0;

    CACHE_LATE_SYNC_MISSES ();

    if (ninstr > 0)
    {
        _save_crt_qemu_instance->systemc.systemc_qemu_consume_instruction_cycles (
            _save_cpu_single_env->qemu.sc_obj, ninstr);
    }
    RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();

    return crt_qemu_instance->systemc.systemc_qemu_get_time ();
}

#if defined(TARGET_ARM)
extern int get_phys_addr (CPUState *env, uint32_t address,
    int access_type, int is_user, uint32_t *phys_ptr, int *prot);

unsigned long get_phys_addr_gdb (unsigned long addr)
{
    int             prot;
    uint32_t        phys_ptr;

    if (!get_phys_addr(cpu_single_env, addr, 0, 0, &phys_ptr, &prot))
        addr = phys_ptr;

    return addr;
}

#elif defined(TARGET_SPARC)
unsigned long get_phys_addr_gdb (unsigned long addr)
{
    return addr;
}
#endif

#ifdef IMPLEMENT_FULL_CACHES

static void mem_lock(void)
{
    struct set_mutex *lock = &crt_qemu_instance->mem_lock;

    while (lock->locked) {
        if (lock->cpu == cpu_single_env->cpu_index)
            printf("BUG: recursive set_lock()\n");

        SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
        _save_crt_qemu_instance->systemc.systemc_qemu_consume_ns(10);
        RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();

        lock = &crt_qemu_instance->mem_lock;
    }
    lock->locked = 1;
    lock->cpu = cpu_single_env->cpu_index;
}

static inline void mem_unlock(void)
{
    struct set_mutex *lock = &crt_qemu_instance->mem_lock;

    if (lock->cpu != cpu_single_env->cpu_index) {
        printf("%s: BUG: attempt to release set_lock without it being held\n",
               __func__);
    }

    lock->locked = 0;
    lock->cpu = -1;
}

static inline void
__evict_line(int n, int n_ways, struct cacheline_entry (*cache)[n][n_ways],
             struct cacheline (*cache_data)[n][n_ways],
             struct cacheline_desc *desc, uint8_t *oob)
{
    struct cacheline_entry *lru_entry;
    uint8_t *data;

    desc->way = __lru_find(n, n_ways, cache, desc);
    lru_entry = &cache[desc->grp][desc->idx][desc->way];

    #ifdef DEBUG
    printf("%s: grp %d way %2d tag 0x%08lx idx 0x%x\n",
           __func__, desc->grp, desc->way, lru_entry->tag, desc->idx);
    #endif

    data = &cache_data[desc->grp][desc->idx][desc->way].data[0];

    if (lru_entry->dirty) {
        unsigned long phys = l2_build_addr(lru_entry->tag, desc->idx);
        unsigned long mem_addr;

        #ifdef DEBUG
        printf("eviction: grp %d way %2d tag 0x%08lx idx 0x%x phys %08lx\n",
               desc->grp, desc->way, lru_entry->tag, desc->idx, phys);
        #endif

        SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
        /*
         * hack: since we cannot write to memory a whole line via a proper
         * interface, we memcpy it.
         */
        mem_addr = _save_crt_qemu_instance->systemc.systemc_qemu_read_memory
           (_save_cpu_single_env->qemu.sc_obj, phys, CACHE_LINE_BYTES, 0, oob);
        RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
        memcpy((void *)mem_addr, data, CACHE_LINE_BYTES);

        lru_entry->dirty = 0;
    }
}

static inline void
l2d_evict_line(struct cacheline_entry (*cache)[L2_LPS][L2_WAYS],
               struct cacheline (*cache_data)[L2_LPS][L2_WAYS],
               struct cacheline_desc *desc, uint8_t *oob)
{
    return __evict_line(L2_LPS, L2_WAYS, cache, cache_data, desc, oob);
}

#else
static inline void mem_lock(void)
{ }
static inline void mem_unlock(void)
{ }
#endif /* IMPLEMENT_FULL_CACHES */

extern unsigned long tmp_physaddr;
#ifdef LOG_INFO_FOR_DEBUG
void log_data_cache (unsigned long addr_miss);
#endif

#ifdef L3_REMOTE
static inline void perf_l2(unsigned long addr, int perf_miss, int oob)
{
    perf_event_inc(env, perf_miss);
    if (oob == OOB_MISS)
        perf_event_inc(env, PERF_CACHE_MISS);
}
#else
static inline void perf_l2(unsigned long addr, int perf_miss, int oob)
{
    if (addr & L2M_MASK) {
        if (oob == OOB_MISS) {
            perf_event_inc(env, perf_miss);
            perf_event_inc(env, PERF_CACHE_MISS);
        }
    } else {
        perf_event_inc(env, perf_miss);
        perf_event_inc(env, PERF_CACHE_MISS);
    }
}
#endif

/* NOTE: This function can only be called from !L2M context */
static void
__l2_fetch_line(struct cacheline_desc *l2, unsigned long addr, int perf_miss)
{
    #ifdef DEBUG
    printf("fetch ");
    print_cacheline_desc(l2);
    #endif

    #ifdef IMPLEMENT_FULL_CACHES
    uint8_t oob = 0;

    l2d_evict_line(crt_qemu_instance->l2_cache,
                   crt_qemu_instance->l2_cache_data, l2, &oob);
    l2d_refresh_way(crt_qemu_instance->l2_cache, l2);
    /* do not count the eviction as a miss, even if it causes a mem access */

    #endif /* FULL */

    g_no_dcache_miss++;

    #ifdef LOG_INFO_FOR_DEBUG
    log_data_cache (addr);
    #endif
    #ifdef IMPLEMENT_LATE_CACHES
    s_crt_ns_misses += NS_DCACHE_MISS;
    #endif

    #ifdef IMPLEMENT_FULL_CACHES
    void *addr_in_mem_dev;

    SAVE_ENV_BEFORE_CONSUME_SYSTEMC();
    addr_in_mem_dev = (void *)_save_crt_qemu_instance->systemc.systemc_qemu_read_memory
        (_save_cpu_single_env->qemu.sc_obj, addr & ~CACHE_LINE_MASK,
         1 << CACHE_LINE_BITS, 0, &oob);
    memcpy(&_save_crt_qemu_instance->l2_cache_data[0][l2->idx][l2->way],
           addr_in_mem_dev, CACHE_LINE_BYTES);
    RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();

    perf_l2(addr, perf_miss, oob);
    #endif /* FULL */
}

inline void *
data_cache_access ()
{
    if (b_use_backdoor)
        return crt_qemu_instance->systemc.systemc_get_mem_addr (
                cpu_single_env->qemu.sc_obj, tmp_physaddr);

    unsigned long addr = tmp_physaddr;

    #ifdef IMPLEMENT_CACHES
    struct cacheline_desc line[1];
    struct cacheline_desc l2[1];

    line->grp = cpu_single_env->cpu_index;
    line->tag = dcache_addr_to_tag(addr);
    line->idx = dcache_addr_to_idx(addr);
    line->way = -1;

    l2->grp = 0;
    l2->tag = l2_addr_to_tag(addr);
    l2->idx = l2_addr_to_idx(addr);
    l2->way = -1;

    mem_lock();

#ifdef DEBUG
    printf("drea: ");
    print_cacheline_desc(line);
#endif
    perf_event_inc(env, PERF_CACHE_REFERENCE);
    perf_event_inc(env, PERF_DCACHE_RDACCESS);
    if (!dcache_hit(qi_dcache(crt_qemu_instance), line))
    {
        perf_event_inc(env, PERF_DCACHE_RDMISS);

        /* obviously LATE_CACHES + L2M is just wrong */
        #ifdef IMPLEMENT_FULL_CACHES
        int ninstr = s_crt_nr_cycles_instr;
        unsigned long addr_in_mem_dev;
        void *l2_addr;
        uint8_t oob = 0;

        perf_event_inc(env, PERF_L2_RDACCESS);
        dcache_refresh(qi_dcache(crt_qemu_instance), line);

        if (addr & L2M_MASK) {
            SAVE_ENV_BEFORE_CONSUME_SYSTEMC();
            if (ninstr > 0) {
                s_crt_nr_cycles_instr = 0;
                _save_crt_qemu_instance->systemc.systemc_qemu_consume_instruction_cycles
                    (_save_cpu_single_env->qemu.sc_obj, ninstr);
            }

            addr_in_mem_dev = _save_crt_qemu_instance->systemc.systemc_qemu_read_memory
                (_save_cpu_single_env->qemu.sc_obj, addr & ~CACHE_LINE_MASK,
                 1 << CACHE_LINE_BITS, 0, &oob);
            RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();

            perf_l2(addr, PERF_L2_RDMISS, oob);

            l2_addr = (void *)addr_in_mem_dev;
        } else {
            /* ! L2M */
            SAVE_ENV_BEFORE_CONSUME_SYSTEMC();
            /* model local L2 latency */
            ninstr += 10;
            if (ninstr > 0) {
                s_crt_nr_cycles_instr = 0;
                _save_crt_qemu_instance->systemc.systemc_qemu_consume_instruction_cycles
                    (_save_cpu_single_env->qemu.sc_obj, ninstr);
            }
            RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
            #endif /* FULL */

            if (!l2d_hit(crt_qemu_instance->l2_cache, l2))
                __l2_fetch_line(l2, addr, PERF_L2_RDMISS);

            #ifdef IMPLEMENT_FULL_CACHES
            l2_addr = &crt_qemu_instance->l2_cache_data[0][l2->idx][l2->way];
	} /* close else from L2M */
        #endif

        /* copy the L2 line to L1 */
        #ifdef IMPLEMENT_FULL_CACHES
        memcpy(&qi_dcache_data(crt_qemu_instance)[line->grp][line->idx][line->way],
               l2_addr, CACHE_LINE_BYTES);
        #endif /* FULL */

    }
    mem_unlock();
    #endif /* CACHES */

    #ifdef GDB_ENABLED
    {
    int                 i, nb = crt_qemu_instance->gdb->watchpoints.nb;
    struct watch_el_t   *pwatch = crt_qemu_instance->gdb->watchpoints.watch;

    for (i = 0; i < nb; i++)
        if (addr >= pwatch[i].begin_address && addr < pwatch[i].end_address &&
            (pwatch[i].type == GDB_WATCHPOINT_READ || pwatch[i].type == GDB_WATCHPOINT_ACCESS)
            )
        {
            gdb_loop (i, 0, 0);
            break;
        }
    }
    #endif

    #ifdef IMPLEMENT_FULL_CACHES
    #ifdef DEBUG
    printf("%s: addr 0x%08lx cpu %d\n", __func__, addr, line->grp);
    print_cacheline(&qi_dcache_data(crt_qemu_instance)[line->grp][line->idx][line->way]);
    #endif
        return &qi_dcache_data(crt_qemu_instance)[line->grp][line->idx][line->way].data[__addr_to_ofs(addr)];
    #else
        #ifdef ONE_MEM_MODULE
            return (void *) (addr + cpu_single_env->sc_mem_host_addr);
        #else
            return crt_qemu_instance->systemc.systemc_get_mem_addr (
                        cpu_single_env->qemu.sc_obj, addr);
        #endif
    #endif
}

unsigned long long
data_cache_accessq ()
{
    unsigned long   save_addr = tmp_physaddr;
    unsigned long   low, hi;

    low = *(unsigned long *) data_cache_access ();
    tmp_physaddr = save_addr + 4;
    hi = *(unsigned long *) data_cache_access ();

    return (((unsigned long long) hi) << 32) + low;
}

unsigned long
data_cache_accessl ()
{
    return *(unsigned long *) data_cache_access ();
}

unsigned short
data_cache_accessw ()
{
    return *(unsigned short *) data_cache_access ();
}

unsigned char
data_cache_accessb ()
{
    return *(unsigned char *) data_cache_access ();
}

signed short
data_cache_access_signed_w ()
{
    return * (signed short *) data_cache_access ();
}

signed char
data_cache_access_signed_b ()
{
    return * (signed  char *) data_cache_access ();
}

void
write_access (unsigned long addr, int nb, unsigned long val)
{
    if (nb != 1 && nb != 2 && nb != 4)
        printf ("wrong nb in %s\n", __FUNCTION__);

    if (addr >= cpu_single_env->ram_size)
        printf ("Bad write memory access in qemu, addr=%ld!\n", addr);

    g_no_write++;

    #ifndef IMPLEMENT_FULL_CACHES
    #ifdef ONE_MEM_MODULE
    void   *host_addr = (void *) (addr + cpu_single_env->sc_mem_host_addr);
    #else
    void   *host_addr = crt_qemu_instance->systemc.systemc_get_mem_addr (
                cpu_single_env->qemu.sc_obj, addr);
    #endif

    switch (nb)
    {
    case 1:
        *((unsigned char *) host_addr) = (unsigned char) (val & 0x000000FF);
    break;
    case 2:
        *((unsigned short *) host_addr) = (unsigned short) (val & 0x0000FFFF);
    break;
    case 4:
        *((unsigned long *) host_addr) = (unsigned long) (val & 0xFFFFFFFF);
    break;
    default:
        printf ("QEMU, function %s, invalid nb %d\n", __FUNCTION__, nb);
        exit (1);
    }
    #ifdef IMPLEMENT_LATE_CACHES
    s_crt_ns_misses += NS_WRITE_ACCESS;
    #endif
    #endif

    #ifdef IMPLEMENT_CACHES
    struct cacheline_desc line[1];
    struct cacheline_desc l2[1];

    line->grp = cpu_single_env->cpu_index;
    line->tag = dcache_addr_to_tag(addr);
    line->way = -1;
    line->idx = dcache_addr_to_idx(addr);

    l2->grp = 0;
    l2->tag = l2_addr_to_tag(addr);
    l2->idx = l2_addr_to_idx(addr);
    l2->way = -1;
    #endif /* CACHES */

    #ifdef IMPLEMENT_FULL_CACHES
    int ninstr = s_crt_nr_cycles_instr;

    SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
    if (ninstr > 0)
    {
        s_crt_nr_cycles_instr = 0;
        _save_crt_qemu_instance->systemc.systemc_qemu_consume_instruction_cycles (
            _save_cpu_single_env->qemu.sc_obj, ninstr);
    }
    RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();

    #ifdef GDB_ENABLED
    {
    int                 i, nb = crt_qemu_instance->gdb->watchpoints.nb;
    struct watch_el_t   *pwatch = crt_qemu_instance->gdb->watchpoints.watch;

    for (i = 0; i < nb; i++)
        if (addr >= pwatch[i].begin_address && addr < pwatch[i].end_address &&
            (pwatch[i].type == GDB_WATCHPOINT_WRITE || pwatch[i].type == GDB_WATCHPOINT_ACCESS)
            )
        {
            gdb_loop (i, 1, val);
            break;
        }
    }
    #endif /* GDB */
    #endif /* FULL */

    #ifdef IMPLEMENT_CACHES
    mem_lock();
    /*
     * Note: on a write miss we'd need to fetch the line from memory, update
     * the few bytes coming from the write, and then commit it back to memory.
     * This would gain us very little, since a subsequent read would fetch the
     * line from memory anyway.
     * Therefore we only update cache lines when there's a hit.
     */
#ifdef DEBUG
    printf("dwri: ");
    print_cacheline_desc(line);
#endif
    perf_event_inc(env, PERF_CACHE_REFERENCE);
    perf_event_inc(env, PERF_DCACHE_WRACCESS);
    if (dcache_hit(qi_dcache(crt_qemu_instance), line))
    {
        #ifdef IMPLEMENT_FULL_CACHES
        unsigned long ofs = __addr_to_ofs(addr);
        void *dest = &qi_dcache_data(crt_qemu_instance)[line->grp][line->idx][line->way].data[ofs];
        switch (nb)
        {
        case 1:
            *((unsigned char *)dest) = (unsigned char) (val & 0xff);
        break;
        case 2:
            *((unsigned short *)dest) = (unsigned short) (val & 0xffff);
        break;
        case 4:
            *((unsigned long *)dest) = (unsigned long)(val & 0xffffffff);
        break;
        default:
            printf ("QEMU, function %s, invalid nb %d\n", __FUNCTION__, nb);
            exit (1);
        }
        #endif
    }
    /* Write-through always misses */
    perf_event_inc(env, PERF_DCACHE_WRMISS);

    SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
    qemu_invalidate_address (_save_crt_qemu_instance, addr, line->grp);
    RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();

    perf_event_inc(env, PERF_L2_WRACCESS);

    #ifdef IMPLEMENT_FULL_CACHES
    if (!(addr & L2M_MASK)) {

        /* model local L2 latency */
        SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
        s_crt_nr_cycles_instr = 0;
        _save_crt_qemu_instance->systemc.systemc_qemu_consume_instruction_cycles
            (_save_cpu_single_env->qemu.sc_obj, 10);
        RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();

    #endif /* FULL */
        if (!l2d_hit(crt_qemu_instance->l2_cache, l2))
            __l2_fetch_line(l2, addr, PERF_L2_WRMISS);
        __l2_set_dirty(crt_qemu_instance->l2_cache, l2, 1);

        #ifdef IMPLEMENT_FULL_CACHES
        unsigned long ofs = __addr_to_ofs(addr);
        void *dest = &crt_qemu_instance->l2_cache_data[0][l2->idx][l2->way].data[ofs];
        switch (nb) {
        case 1:
            *((unsigned char *)dest) = (unsigned char)(val & 0xff);
            break;
        case 2:
            *((unsigned short *)dest) = (unsigned short)(val & 0xffff);
            break;
        case 4:
            *((unsigned long *)dest) = (unsigned long)(val & 0xffffffff);
            break;
        default:
            printf ("QEMU, function %s, invalid nb %d\n", __FUNCTION__, nb);
            exit(1);
        }
        #endif /* FULL */
    #ifdef IMPLEMENT_FULL_CACHES
    } else { /* if !L2M */
        uint8_t oob = 0;
        SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
        _save_crt_qemu_instance->systemc.systemc_qemu_write_memory
            (_save_cpu_single_env->qemu.sc_obj, addr, val, nb, 0, &oob);
        RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
    }
    #endif

#ifdef IMPLEMENT_FULL_CACHES
    uint8_t oob = 0;
    void *mem_addr = crt_qemu_instance->systemc.systemc_get_mem_addr
        (cpu_single_env->qemu.sc_obj, addr);
        switch (nb) {
        case 1:
            *((unsigned char *)mem_addr) = (unsigned char)(val & 0xff);
            break;
        case 2:
            *((unsigned short *)mem_addr) = (unsigned short)(val & 0xffff);
            break;
        case 4:
            *((unsigned long *)mem_addr) = (unsigned long)(val & 0xffffffff);
            break;
        default:
            printf ("QEMU, function %s, invalid nb %d\n", __FUNCTION__, nb);
            exit(1);
        }

        SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
        _save_crt_qemu_instance->systemc.systemc_qemu_write_memory_nosleep
            (_save_cpu_single_env->qemu.sc_obj, addr, val, nb, 0, &oob);
        RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
#endif
    mem_unlock();

    #endif /* CACHES */
}

void
write_accessq (unsigned long addr, unsigned long long val)
{
    write_access (addr + 0, 4, (unsigned long) (val & 0xFFFFFFFF));
    g_no_write--;
    write_access (addr + 4, 4, (unsigned long) (val >> 32));
}

void
instruction_cache_access (unsigned long addr)
{
    struct cacheline_desc line[1];
    line->grp = cpu_single_env->cpu_index;
    line->tag = icache_addr_to_tag(addr);
    line->idx = icache_addr_to_idx(addr);
    line->way = -1;

#ifdef DEBUG
    printf("irea: ");
    print_cacheline_desc(line);
#endif

    perf_event_inc(env, PERF_CACHE_REFERENCE);
    perf_event_inc(env, PERF_ICACHE_REFERENCE);
    if (!icache_hit(qi_icache(crt_qemu_instance), line))
    {
        g_no_icache_miss++;
        perf_event_inc(env, PERF_ICACHE_MISS);
        perf_event_inc(env, PERF_CACHE_MISS);
        icache_refresh(qi_icache(crt_qemu_instance), line);

        #ifdef IMPLEMENT_FULL_CACHES
        int ninstr = s_crt_nr_cycles_instr;

        SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
        if (ninstr > 0)
        {
            s_crt_nr_cycles_instr = 0;
            _save_crt_qemu_instance->systemc.systemc_qemu_consume_instruction_cycles (
                _save_cpu_single_env->qemu.sc_obj, ninstr);
        }

        unsigned long junk;
        junk = _save_crt_qemu_instance->systemc.systemc_qemu_read_memory (
            _save_cpu_single_env->qemu.sc_obj,
            addr & ~CACHE_LINE_MASK, 1 << CACHE_LINE_BITS, 0, NULL);

        RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
        #else //cache late configuration
        s_crt_ns_misses += NS_ICACHE_MISS;
        #endif
    }
}

void
instruction_cache_access_n (unsigned long addr, int n)
{
    int i;
    for (i = 0; i < n; i++)
        instruction_cache_access (addr + i * 4);
}

void
qemu_invalidate_address (qemu_instance *instance, unsigned long addr, int src_idx)
{
    struct cacheline_desc dline[1], iline[1];
    dline->tag = dcache_addr_to_tag(addr);
    dline->idx = dcache_addr_to_idx(addr);
    iline->tag = icache_addr_to_tag(addr);
    iline->idx = icache_addr_to_idx(addr);

#ifdef DEBUG
    printf("inv addr %08lx src %d\n", addr, src_idx);
#endif

    int                     i;
    for (i = 0; i < instance->NOCPUs; i++)
    {
	dline->grp = i;
	iline->grp = i;
        dline->way = -1;
        iline->way = -1;
        if (i != src_idx && dcache_hit_no_update(qi_dcache(instance), dline))
	    dcache_invalidate(qi_dcache(instance), dline);

        if (icache_hit_no_update(qi_icache(instance), iline))
	    icache_invalidate(qi_icache(instance), iline);
    }
}

static int gdb_condition (unsigned long addr)
{
    int                 gdbrs = crt_qemu_instance->gdb->running_state;
    int                 gdbcpu = crt_qemu_instance->gdb->c_cpu_index;
    int                 i, nb;
    unsigned long       *paddr;

    if (gdbrs == STATE_DETACH)
        return 0;

    if (cpu_single_env->cpu_index != gdbcpu && gdbcpu != - 1)
        return 0;

    if (gdbrs == STATE_STEP || gdbrs == STATE_INIT)
        return 1;

    nb = crt_qemu_instance->gdb->breakpoints.nb;
    paddr = crt_qemu_instance->gdb->breakpoints.addr;
    for (i = 0; i < nb; i++)
        if (addr == paddr[i])
            return 1;

    return 0;
}

void gdb_verify (unsigned long addr
    #if defined(TARGET_SPARC)
    , unsigned long npc
    #endif
)
{
    //update the unupdated registers
    #if defined(TARGET_ARM)
    cpu_single_env->gdb_pc = addr;
    #elif defined(TARGET_SPARC)
    cpu_single_env->gdb_pc = addr;
    if (npc == 1)
        cpu_single_env->gdb_npc = cpu_single_env->npc;
    else
        cpu_single_env->gdb_npc = npc;
    #endif

    #if 0
    static long cnt1 = 0;
    if (cpu_single_env->gdb_pc == 0xc0044e48 &&
        cpu_single_env->cpu_index == 0 &&
        cpu_single_env->regs[0] == 0xc008e6f4)
    {
        cnt1++;
        printf ("cnt1=%ld\n", cnt1);
        if (cnt1 == 45)
            printf ("brk\n");
    }
    #endif

    if (!gdb_condition (addr))
        return;

    #if 0
    SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();

    int             ninstr = s_crt_nr_cycles_instr;
    s_crt_nr_cycles_instr = 0;

    CACHE_LATE_SYNC_MISSES ();

    if (ninstr > 0)
    {
        _save_crt_qemu_instance->systemc.systemc_qemu_consume_instruction_cycles (
            _save_cpu_single_env->qemu.sc_obj, ninstr);
    }
    RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
    #endif

    if (!gdb_condition (addr))
        return;

    gdb_loop (-1, 0, 0);
}

