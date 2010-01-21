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
#include "config.h"
#include "exec.h"
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <string.h>
#include "qemu_encap.h"

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
#endif

int tb_invalidated_flag;

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

unsigned char b_in_translation = 0;
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

		b_in_translation = 1;

    /* spin_lock(&tb_lock); */

    tb_invalidated_flag = 0;

    regs_to_env(); /* XXX: do it just before cpu_gen_code() */

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
        tb_invalidated_flag = 1;
    }
    tc_ptr = code_gen_ptr;
    tb->tc_ptr = tc_ptr;
    tb->cs_base = cs_base;
    tb->flags = flags;
    SAVE_GLOBALS();
    cpu_gen_code(env, tb, &code_gen_size);
    RESTORE_GLOBALS();
    code_gen_ptr = (void *)(((unsigned long)code_gen_ptr + code_gen_size + CODE_GEN_ALIGN - 1) & ~(CODE_GEN_ALIGN - 1));

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

		b_in_translation = 0;

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
        if (tb_invalidated_flag) {
            /* as some TB could have been invalidated because
               of memory exceptions while generating the code, we
               must recompute the hash index here */
            T0 = 0;
        }
    }
    return tb;
}

#define BREAK_CHAIN T0 = 0

/* main execution loop */

int cpu_exec(CPUState *env1)
{
#define DECLARE_HOST_REGS 1
#include "hostregs_helper.h"

    int ret, interrupt_request;
    void (*gen_func)(void);
    TranslationBlock *tb;
    uint8_t *tc_ptr;

		env1->qemu.ns_in_cpu_exec = 0;

    cpu_single_env = env1;

  if (cpu_halted_systemc () == EXCP_HALTED)
    return EXCP_HALTED;

    /* first we save global registers */
#define SAVE_HOST_REGS 1
#include "hostregs_helper.h"
    env = env1;
    SAVE_GLOBALS();

    env_to_regs();

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

                    ret = env->exception_index;
                    break;
                } else {
                    do_interrupt(env);
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

                    if (interrupt_request & CPU_INTERRUPT_HALT) {
                        env->interrupt_request &= ~CPU_INTERRUPT_HALT;
                        env->halted = 1;
                        env->exception_index = EXCP_HLT;
                        cpu_loop_exit();
                    }
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
                    if (interrupt_request & CPU_INTERRUPT_HARD
                        && ((IS_M(env) && env->regs[15] < 0xfffffff0)
                            || !(env->uncached_cpsr & CPSR_I))) {
                        env->exception_index = EXCP_IRQ;
                        do_interrupt(env);
                        BREAK_CHAIN;
                    }
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
                {
                    if (T0 != 0 && tb->page_addr[1] == -1) {
                    /* spin_lock(&tb_lock); */
                    tb_add_jump((TranslationBlock *)(long)(T0 & ~3), T0 & 3, tb);
                    /* spin_unlock(&tb_lock); */
                }
                }
                tc_ptr = tb->tc_ptr;
                env->current_tb = tb;
                /* execute the generated code */
                gen_func = (void *)tc_ptr;
                gen_func();
                env->current_tb = NULL;
            } /* for(;;) */
        } else {
            env_to_regs();
        }
    } /* for(;;) */



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

#define SAVE_ENV_BEFORE_CONSUME_SYSTEMC() do{\
	  qemu_instance   *_save_crt_qemu_instance = crt_qemu_instance; \
		CPUState			*_save_cpu_single_env = cpu_single_env; \
		CPUState			*_save_env = env; \
		int					_save_tb_invalidated_flag = tb_invalidated_flag; \
		crt_qemu_instance = NULL;																		 \
		env = NULL; \
		cpu_single_env = NULL; \
    tb_invalidated_flag = 0

#define RESTORE_ENV_AFTER_CONSUME_SYSTEMC() \
	  crt_qemu_instance = _save_crt_qemu_instance;	\
		cpu_single_env = _save_cpu_single_env; \
		env = _save_env; \
		tb_invalidated_flag = _save_tb_invalidated_flag; \
		}while (0)

unsigned long s_crt_nr_cycles_instr = 0;
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

static uint32_t
qemu_systemc_read_all (void *opaque,
		       target_phys_addr_t offset, unsigned char nbytes)
{
  uint32_t value = 0xFFFFFFFF;

  SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();

  int ninstr = s_crt_nr_cycles_instr;
  if (ninstr)
    {
      s_crt_nr_cycles_instr = 0;
      systemc_qemu_consume_instruction_cycles (_save_cpu_single_env->qemu.
																							 sc_obj, ninstr,
																							 &_save_cpu_single_env->qemu.
																							 ns_in_cpu_exec);
    }

  value =
    systemc_qemu_read_memory (_save_cpu_single_env->qemu.sc_obj, offset,
			      nbytes,
			      &_save_cpu_single_env->qemu.ns_in_cpu_exec);

  RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();

  return value;
}

static void
qemu_systemc_write_all (void *opaque, target_phys_addr_t offset,
			uint32_t value, unsigned char nbytes)
{
  SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();

  int ninstr = s_crt_nr_cycles_instr;
  if (ninstr)
    {
      s_crt_nr_cycles_instr = 0;
      systemc_qemu_consume_instruction_cycles (_save_cpu_single_env->qemu.
																							 sc_obj, ninstr,
																							 &_save_cpu_single_env->qemu.
																							 ns_in_cpu_exec);
    }

  systemc_qemu_write_memory (_save_cpu_single_env->qemu.sc_obj, offset, value,
			     nbytes,
			     &_save_cpu_single_env->qemu.ns_in_cpu_exec);

  RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
}

static uint32_t
qemu_systemc_read_b (void *opaque, target_phys_addr_t offset)
{
  DPRINTF ("read byte from 0x%X\n", offset);

  return qemu_systemc_read_all (opaque, offset, 1);
}

static void
qemu_systemc_write_b (void *opaque, target_phys_addr_t offset, uint32_t value)
{
  DPRINTF ("write byte 0x%X to 0x%X\n", value, offset);

  qemu_systemc_write_all (opaque, offset, value, 1);
}

static uint32_t
qemu_systemc_read_w (void *opaque, target_phys_addr_t offset)
{
  DPRINTF ("read short from 0x%X\n", offset);

  return qemu_systemc_read_all (opaque, offset, 2);
}

static void
qemu_systemc_write_w (void *opaque, target_phys_addr_t offset, uint32_t value)
{
  DPRINTF ("write short 0x%X to 0x%X\n", value, offset);

  qemu_systemc_write_all (opaque, offset, value, 2);
}

static uint32_t
qemu_systemc_read_dw (void *opaque, target_phys_addr_t offset)
{
  DPRINTF ("read long from 0x%X, CPU = %d\n", offset,
	   cpu_single_env->cpu_index);

  return qemu_systemc_read_all (opaque, offset, 4);
}

static void
qemu_systemc_write_dw (void *opaque, target_phys_addr_t offset,
		       uint32_t value)
{
  DPRINTF ("write long 0x%X to 0x%X\n", value, offset);

  qemu_systemc_write_all (opaque, offset, value, 4);
}

static CPUReadMemoryFunc *qemu_systemc_readfn[] = {
  qemu_systemc_read_b,
  qemu_systemc_read_w,
  qemu_systemc_read_dw,
};

static CPUWriteMemoryFunc *qemu_systemc_writefn[] = {
  qemu_systemc_write_b,
  qemu_systemc_write_w,
  qemu_systemc_write_dw,
};

void
qemu_add_map (unsigned long base, unsigned long size, int type)
{
  int iomemtype;

  iomemtype =
    cpu_register_io_memory (0, qemu_systemc_readfn, qemu_systemc_writefn, 0);
  cpu_register_physical_memory (base, size, iomemtype);
}

void
qemu_set_cpu_fv_percent (CPUState * penv, unsigned long fv_percent)
{
  penv->qemu.fv_percent = (fv_percent > 0) ? fv_percent : 100;
}

void
tb_start ()
{
  if (cpu_single_env->qemu.ns_in_cpu_exec +
      (s_crt_nr_cycles_instr * 100) / cpu_single_env->qemu.fv_percent > 40000)
    {
//              printf ("tb_start - > 40000, sctime = %llu\n", systemc_qemu_get_time ());
      cpu_interrupt (cpu_single_env, CPU_INTERRUPT_EXIT);
    }
}

static int
cpu_halted_systemc ()
{
	CPUState *penv = (CPUState *) crt_qemu_instance->first_cpu;
  int ret = 0;

  while (penv)
    {
      if (penv->halted)
	{
	  if (penv->interrupt_request &
	      (CPU_INTERRUPT_FIQ | CPU_INTERRUPT_HARD | CPU_INTERRUPT_EXITTB))
	    {
	      penv->halted = 0;

	      if (penv != cpu_single_env)
		{
		  SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();

		  int ninstr = s_crt_nr_cycles_instr;
		  if (ninstr)
		    {
		      s_crt_nr_cycles_instr = 0;
		      systemc_qemu_consume_instruction_cycles
						(_save_cpu_single_env->qemu.sc_obj, ninstr,
						 &_save_cpu_single_env->qemu.ns_in_cpu_exec);
		    }

		  systemc_qemu_wakeup (penv->qemu.sc_obj);

		  RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
		}
	    }
	  else
	    {
	      if (penv == cpu_single_env)
		ret = EXCP_HALTED;
	    }
	}

      penv = penv->next_cpu;
    }

  return ret;
}

int64_t
qemu_get_clock_with_systemc ()
{
	if (cpu_single_env == NULL)
    return 0;

  int ninstr = s_crt_nr_cycles_instr;
  if (ninstr > 0)
    {
      SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();

      s_crt_nr_cycles_instr = 0;
      systemc_qemu_consume_instruction_cycles (_save_next_cpu_vl->qemu.sc_obj,
																							 ninstr,
																							 &_save_next_cpu_vl->qemu.
																							 ns_in_cpu_exec);

      RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
    }

  return systemc_qemu_get_time ();
}

extern unsigned long tmp_physaddr;
#ifdef LOG_PC
void log_data_cache (unsigned long addr_miss);
#endif

inline void *
data_cache_access ()
{

  int cpu = env->cpu_index;
  unsigned long addr = tmp_physaddr;
  unsigned long tag = addr >> DCACHE_LINE_BITS;
  int idx = tag & (DCACHE_LINES - 1);

	if (tag != crt_qemu_instance->cpu_dcache[cpu][idx])
    {
      g_no_dcache_miss++;
			crt_qemu_instance->cpu_dcache[cpu][idx] = tag;

#ifdef LOG_PC
      log_data_cache (addr);
#endif

      int ninstr = s_crt_nr_cycles_instr;
      SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
      if (ninstr > 0)
	{
	  s_crt_nr_cycles_instr = 0;
		systemc_qemu_consume_instruction_cycles (_save_cpu_single_env->qemu.
               sc_obj, ninstr,
               &_save_cpu_single_env->qemu.
							 ns_in_cpu_exec);

	}

      unsigned long addr_in_mem_dev;
      addr_in_mem_dev =
				systemc_qemu_read_memory (_save_cpu_single_env->qemu.sc_obj,
																	addr & ~DCACHE_LINE_MASK, 4,
																	&_save_cpu_single_env->qemu.ns_in_cpu_exec);
			memcpy (_save_crt_qemu_instance->cpu_dcache_data[cpu][idx], (void *) addr_in_mem_dev,
							DCACHE_LINE_BYTES);

      RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
    }

	return &crt_qemu_instance->cpu_dcache_data[cpu][idx][addr & DCACHE_LINE_MASK];
}

unsigned long long
data_cache_accessq ()
{
  printf
    ("8 byte access not implemented for data caches, file %s, function %s\n",
     __FILE__, __FUNCTION__);
  exit (1);
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

void
write_access (unsigned long addr, int nb, unsigned long val)
{

  g_no_write++;

  int cpu = env->cpu_index;
  unsigned long tag = addr >> DCACHE_LINE_BITS;
  unsigned long ofs = addr & DCACHE_LINE_MASK;
  int idx = tag & (DCACHE_LINES - 1);

  int ninstr = s_crt_nr_cycles_instr;
  SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
  if (ninstr > 0)
    {
      s_crt_nr_cycles_instr = 0;
			systemc_qemu_consume_instruction_cycles (_save_cpu_single_env->qemu.sc_obj,
								 ninstr,
                 &_save_cpu_single_env->qemu.
								 ns_in_cpu_exec);
    }
	
	if (tag == _save_crt_qemu_instance->cpu_dcache[cpu][idx]) // addr in cache -> update
    {
      switch (nb)
				{
				case 1:
					*((unsigned char *)  &_save_crt_qemu_instance->cpu_dcache_data[cpu][idx][ofs]) =
						(unsigned char) (val & 0x000000FF);
					break;
				case 2:
					*((unsigned short *) &_save_crt_qemu_instance->cpu_dcache_data[cpu][idx][ofs]) =
						(unsigned short) (val & 0x0000FFFF);
					break;
				case 4:
					*((unsigned long *)  &_save_crt_qemu_instance->cpu_dcache_data[cpu][idx][ofs]) =
						(unsigned long) (val & 0xFFFFFFFF);
					break;
				default:
					printf ("QEMU, function %s, invalid nb %d\n", __FUNCTION__, nb);
					exit (1);
				}
		}

	systemc_qemu_write_memory (_save_cpu_single_env->qemu.sc_obj,
														 addr, val, nb,
														 &_save_cpu_single_env->qemu.ns_in_cpu_exec);

  int i;
	for (i = 0; i < _save_crt_qemu_instance->NOCPUs; i++)
		if (i != cpu && _save_crt_qemu_instance->cpu_dcache[i][idx] == tag)
			_save_crt_qemu_instance->cpu_dcache[i][idx] = (unsigned long) -1;
	
  RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
}

void
instruction_cache_access (unsigned long addr)
{

  int cpu = env->cpu_index;
  unsigned long tag = addr >> ICACHE_LINE_BITS;
  int idx = tag & (ICACHE_LINES - 1);

	if (tag != crt_qemu_instance->cpu_icache[cpu][idx])
    {
      g_no_icache_miss++;
			crt_qemu_instance->cpu_icache[cpu][idx] = tag;


      int ninstr = s_crt_nr_cycles_instr;
      SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
      if (ninstr > 0)
	{
	  s_crt_nr_cycles_instr = 0;
		systemc_qemu_consume_instruction_cycles (_save_cpu_single_env->qemu.
							 sc_obj, ninstr,
               &_save_cpu_single_env->qemu.
							 ns_in_cpu_exec);
	}

      unsigned long junk;
			junk = systemc_qemu_read_memory (_save_cpu_single_env->qemu.sc_obj,
																			 addr & ~ICACHE_LINE_MASK, 4,
																			 &_save_cpu_single_env->qemu.
																			 ns_in_cpu_exec);

      RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();
    }
}

void
instruction_cache_access_n (unsigned long addr, int n)
{
  int i;
  for (i = 0; i < n; i++)
    instruction_cache_access (addr + i * 4);
}
