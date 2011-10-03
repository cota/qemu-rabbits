#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu.h"
#include "exec-all.h"
#include "memex.h"

#define SAVE_ENV_BEFORE_CONSUME_SYSTEMC() \
    do{\
        qemu_instance   *_save_crt_qemu_instance = crt_qemu_instance; \
        CPUState        *_save_cpu_single_env = cpu_single_env; \
        CPUState        *_save_env = env; \
        crt_qemu_instance = NULL; \
        env = NULL; \
        cpu_single_env = NULL; \
        unsigned char   _save_b_use_backdoor = b_use_backdoor

#define RESTORE_ENV_AFTER_CONSUME_SYSTEMC() \
        crt_qemu_instance = _save_crt_qemu_instance; \
        cpu_single_env = _save_cpu_single_env; \
        env = _save_env; \
        b_use_backdoor = _save_b_use_backdoor; \
    }while (0)

extern unsigned long get_phys_addr_gdb (unsigned long addr);

static uint32_t cortexa8_cp15_c0_c1[8] =
{ 0x1031, 0x11, 0x400, 0, 0x31100003, 0x20000000, 0x01202000, 0x11 };

static uint32_t cortexa8_cp15_c0_c2[8] =
{ 0x00101111, 0x12112111, 0x21232031, 0x11112131, 0x00111142, 0, 0, 0 };

static uint32_t mpcore_cp15_c0_c1[8] =
{ 0x111, 0x1, 0, 0x2, 0x01100103, 0x10020302, 0x01222000, 0 };

static uint32_t mpcore_cp15_c0_c2[8] =
{ 0x00100011, 0x12002111, 0x11221011, 0x01102131, 0x141, 0, 0, 0 };

static uint32_t arm1136_cp15_c0_c1[8] =
{ 0x111, 0x1, 0x2, 0x3, 0x01130003, 0x10030302, 0x01222110, 0 };

static uint32_t arm1136_cp15_c0_c2[8] =
{ 0x00140011, 0x12002111, 0x11231111, 0x01102131, 0x141, 0, 0, 0 };

static uint32_t cpu_arm_find_by_name(const char *name);

static inline void set_feature(CPUARMState *env, int feature)
{
    env->features |= 1u << feature;
}

static void cpu_reset_model_id(CPUARMState *env, uint32_t id)
{
    env->cp15.c0_cpuid = id;
    switch (id) {
    case ARM_CPUID_ARM926:
        set_feature(env, ARM_FEATURE_VFP);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x41011090;
        env->cp15.c0_cachetype = 0x1dd20d2;
        env->cp15.c1_sys = 0x00090078;
        break;
    case ARM_CPUID_ARM946:
        set_feature(env, ARM_FEATURE_MPU);
        env->cp15.c0_cachetype = 0x0f004006;
        env->cp15.c1_sys = 0x00000078;
        break;
    case ARM_CPUID_ARM1026:
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_AUXCR);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x410110a0;
        env->cp15.c0_cachetype = 0x1dd20d2;
        env->cp15.c1_sys = 0x00090078;
        break;
    case ARM_CPUID_ARM1136:
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_AUXCR);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x410120b4;
        env->vfp.xregs[ARM_VFP_MVFR0] = 0x11111111;
        env->vfp.xregs[ARM_VFP_MVFR1] = 0x00000000;
        memcpy(env->cp15.c0_c1, arm1136_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env->cp15.c0_c2, arm1136_cp15_c0_c2, 8 * sizeof(uint32_t));
        env->cp15.c0_cachetype = 0x1dd20d2;
        break;
    case ARM_CPUID_ARM11MPCORE:
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_AUXCR);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x410120b4;
        env->vfp.xregs[ARM_VFP_MVFR0] = 0x11111111;
        env->vfp.xregs[ARM_VFP_MVFR1] = 0x00000000;
        memcpy(env->cp15.c0_c1, mpcore_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env->cp15.c0_c2, mpcore_cp15_c0_c2, 8 * sizeof(uint32_t));
        env->cp15.c0_cachetype = 0x1ddd2dd2;
        break;
    case ARM_CPUID_CORTEXA8:
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_AUXCR);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_VFP3);
        set_feature(env, ARM_FEATURE_NEON);
        set_feature(env, ARM_FEATURE_THUMB2EE);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x410330c0;
        env->vfp.xregs[ARM_VFP_MVFR0] = 0x11110222;
        env->vfp.xregs[ARM_VFP_MVFR1] = 0x00011100;
        memcpy(env->cp15.c0_c1, cortexa8_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env->cp15.c0_c2, cortexa8_cp15_c0_c2, 8 * sizeof(uint32_t));
        env->cp15.c0_cachetype = 0x1dd20d2;
        break;
    case ARM_CPUID_CORTEXM3:
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_M);
        set_feature(env, ARM_FEATURE_DIV);
        break;
    case ARM_CPUID_ANY: /* For userspace emulation.  */
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_VFP3);
        set_feature(env, ARM_FEATURE_NEON);
        set_feature(env, ARM_FEATURE_THUMB2EE);
        set_feature(env, ARM_FEATURE_DIV);
        break;
    case ARM_CPUID_TI915T:
    case ARM_CPUID_TI925T:
        set_feature(env, ARM_FEATURE_OMAPCP);
        env->cp15.c0_cpuid = ARM_CPUID_TI925T; /* Depends on wiring.  */
        env->cp15.c0_cachetype = 0x5109149;
        env->cp15.c1_sys = 0x00000070;
        env->cp15.c15_i_max = 0x000;
        env->cp15.c15_i_min = 0xff0;
        break;
    case ARM_CPUID_PXA250:
    case ARM_CPUID_PXA255:
    case ARM_CPUID_PXA260:
    case ARM_CPUID_PXA261:
    case ARM_CPUID_PXA262:
        set_feature(env, ARM_FEATURE_XSCALE);
        /* JTAG_ID is ((id << 28) | 0x09265013) */
        env->cp15.c0_cachetype = 0xd172172;
        env->cp15.c1_sys = 0x00000078;
        break;
    case ARM_CPUID_PXA270_A0:
    case ARM_CPUID_PXA270_A1:
    case ARM_CPUID_PXA270_B0:
    case ARM_CPUID_PXA270_B1:
    case ARM_CPUID_PXA270_C0:
    case ARM_CPUID_PXA270_C5:
        set_feature(env, ARM_FEATURE_XSCALE);
        /* JTAG_ID is ((id << 28) | 0x09265013) */
        set_feature(env, ARM_FEATURE_IWMMXT);
        env->iwmmxt.cregs[ARM_IWMMXT_wCID] = 0x69051000 | 'Q';
        env->cp15.c0_cachetype = 0xd172172;
        env->cp15.c1_sys = 0x00000078;
        break;
    default:
        cpu_abort(env, "Bad CPU ID: %x\n", id);
        break;
    }
}

void cpu_reset(CPUARMState *env)
{
    uint32_t id;
    id = env->cp15.c0_cpuid;
    memset(env, 0, offsetof(CPUARMState, breakpoints));
    if (id)
        cpu_reset_model_id(env, id);
#if defined (CONFIG_USER_ONLY)
    env->uncached_cpsr = ARM_CPU_MODE_USR;
    env->vfp.xregs[ARM_VFP_FPEXC] = 1 << 30;
#else
    /* SVC mode with interrupts disabled.  */
    env->uncached_cpsr = ARM_CPU_MODE_SVC | CPSR_A | CPSR_F | CPSR_I;
    /* On ARMv7-M the CPSR_I is the value of the PRIMASK register, and is
       clear at reset.  */
    if (IS_M(env))
        env->uncached_cpsr &= ~CPSR_I;
    env->vfp.xregs[ARM_VFP_FPEXC] = 0;
    /* v7 performance monitor control register: same implementor
     * field as main ID register, and we implement no event counters.
     */
    env->cp15.c9_pmcr = (id & 0xff000000);
#endif
    env->regs[15] = 0;
    tlb_flush(env, 1);
}

CPUARMState *cpu_arm_init(const char *cpu_model)
{
    CPUARMState *env;
    uint32_t id;

    id = cpu_arm_find_by_name(cpu_model);
    if (id == 0)
        return NULL;
    env = qemu_mallocz(sizeof(CPUARMState));
    if (!env)
        return NULL;
    cpu_exec_init(env);
    env->cpu_model_str = cpu_model;
    env->cp15.c0_cpuid = id;
    cpu_reset(env);

    return env;
}

struct arm_cpu_t {
    uint32_t id;
    const char *name;
};

static const struct arm_cpu_t arm_cpu_names[] = {
    { ARM_CPUID_ARM926, "arm926"},
    { ARM_CPUID_ARM946, "arm946"},
    { ARM_CPUID_ARM1026, "arm1026"},
    { ARM_CPUID_ARM1136, "arm1136"},
    { ARM_CPUID_ARM11MPCORE, "arm11mpcore"},
    { ARM_CPUID_CORTEXM3, "cortex-m3"},
    { ARM_CPUID_CORTEXA8, "cortex-a8"},
    { ARM_CPUID_TI925T, "ti925t" },
    { ARM_CPUID_PXA250, "pxa250" },
    { ARM_CPUID_PXA255, "pxa255" },
    { ARM_CPUID_PXA260, "pxa260" },
    { ARM_CPUID_PXA261, "pxa261" },
    { ARM_CPUID_PXA262, "pxa262" },
    { ARM_CPUID_PXA270, "pxa270" },
    { ARM_CPUID_PXA270_A0, "pxa270-a0" },
    { ARM_CPUID_PXA270_A1, "pxa270-a1" },
    { ARM_CPUID_PXA270_B0, "pxa270-b0" },
    { ARM_CPUID_PXA270_B1, "pxa270-b1" },
    { ARM_CPUID_PXA270_C0, "pxa270-c0" },
    { ARM_CPUID_PXA270_C5, "pxa270-c5" },
    { ARM_CPUID_ANY, "any"},
    { 0, NULL}
};

void arm_cpu_list(FILE *f, int (*cpu_fprintf)(FILE *f, const char *fmt, ...))
{
    int i;

    (*cpu_fprintf)(f, "Available CPUs:\n");
    for (i = 0; arm_cpu_names[i].name; i++) {
        (*cpu_fprintf)(f, "  %s\n", arm_cpu_names[i].name);
    }
}

/* return 0 if not found */
static uint32_t cpu_arm_find_by_name(const char *name)
{
    int i;
    uint32_t id;

    id = 0;
    for (i = 0; arm_cpu_names[i].name; i++) {
        if (strcmp(name, arm_cpu_names[i].name) == 0) {
            id = arm_cpu_names[i].id;
            break;
        }
    }
    return id;
}

void cpu_arm_close(CPUARMState *env)
{
    free(env);
}

/* Polynomial multiplication is like integer multiplcation except the
   partial products are XORed, not added.  */
uint32_t helper_neon_mul_p8(uint32_t op1, uint32_t op2)
{
    uint32_t mask;
    uint32_t result;
    result = 0;
    while (op1) {
        mask = 0;
        if (op1 & 1)
            mask |= 0xff;
        if (op1 & (1 << 8))
            mask |= (0xff << 8);
        if (op1 & (1 << 16))
            mask |= (0xff << 16);
        if (op1 & (1 << 24))
            mask |= (0xff << 24);
        result ^= op2 & mask;
        op1 = (op1 >> 1) & 0x7f7f7f7f;
        op2 = (op2 << 1) & 0xfefefefe;
    }
    return result;
}

uint32_t cpsr_read(CPUARMState *env)
{
    int ZF;
    ZF = (env->NZF == 0);
    return env->uncached_cpsr | (env->NZF & 0x80000000) | (ZF << 30) |
        (env->CF << 29) | ((env->VF & 0x80000000) >> 3) | (env->QF << 27)
        | (env->thumb << 5) | ((env->condexec_bits & 3) << 25)
        | ((env->condexec_bits & 0xfc) << 8)
        | (env->GE << 16);
}

void cpsr_write(CPUARMState *env, uint32_t val, uint32_t mask)
{
    /* NOTE: N = 1 and Z = 1 cannot be stored currently */
    if (mask & CPSR_NZCV) {
        env->NZF = (val & 0xc0000000) ^ 0x40000000;
        env->CF = (val >> 29) & 1;
        env->VF = (val << 3) & 0x80000000;
    }
    if (mask & CPSR_Q)
        env->QF = ((val & CPSR_Q) != 0);
    if (mask & CPSR_T)
        env->thumb = ((val & CPSR_T) != 0);
    if (mask & CPSR_IT_0_1) {
        env->condexec_bits &= ~3;
        env->condexec_bits |= (val >> 25) & 3;
    }
    if (mask & CPSR_IT_2_7) {
        env->condexec_bits &= 3;
        env->condexec_bits |= (val >> 8) & 0xfc;
    }
    if (mask & CPSR_GE) {
        env->GE = (val >> 16) & 0xf;
    }

    if ((env->uncached_cpsr ^ val) & mask & CPSR_M) {
        switch_mode(env, val & CPSR_M);
    }
    mask &= ~CACHED_CPSR_BITS;
    env->uncached_cpsr = (env->uncached_cpsr & ~mask) | (val & mask);
}

#if defined(CONFIG_USER_ONLY)

void do_interrupt (CPUState *env)
{
    env->exception_index = -1;
}

/* Structure used to record exclusive memory locations.  */
typedef struct mmon_state {
    struct mmon_state *next;
    CPUARMState *cpu_env;
    uint32_t addr;
} mmon_state;

/* Chain of current locks.  */
static mmon_state* mmon_head = NULL;

int cpu_arm_handle_mmu_fault (CPUState *env, target_ulong address, int rw,
                              int mmu_idx, int is_softmmu)
{
    if (rw == 2) {
        env->exception_index = EXCP_PREFETCH_ABORT;
        env->cp15.c6_insn = address;
    } else {
        env->exception_index = EXCP_DATA_ABORT;
        env->cp15.c6_data = address;
    }
    return 1;
}

static void allocate_mmon_state(CPUState *env)
{
    env->mmon_entry = malloc(sizeof (mmon_state));
    if (!env->mmon_entry)
        abort();
    memset (env->mmon_entry, 0, sizeof (mmon_state));
    env->mmon_entry->cpu_env = env;
    mmon_head = env->mmon_entry;
}

/* Flush any monitor locks for the specified address.  */
static void flush_mmon(uint32_t addr)
{
    mmon_state *mon;

    for (mon = mmon_head; mon; mon = mon->next)
      {
        if (mon->addr != addr)
          continue;

        mon->addr = 0;
        break;
      }
}

/* Mark an address for exclusive access.  */
void helper_mark_exclusive(CPUState *env, uint32_t addr)
{
    if (!env->mmon_entry)
        allocate_mmon_state(env);
    /* Clear any previous locks.  */
    flush_mmon(addr);
    env->mmon_entry->addr = addr;
}

/* Test if an exclusive address is still exclusive.  Returns zero
   if the address is still exclusive.   */
int helper_test_exclusive(CPUState *env, uint32_t addr)
{
    int res;

    if (!env->mmon_entry)
        return 1;
    if (env->mmon_entry->addr == addr)
        res = 0;
    else
        res = 1;
    flush_mmon(addr);
    return res;
}

void helper_clrex(CPUState *env)
{
    if (!(env->mmon_entry && env->mmon_entry->addr))
        return;
    flush_mmon(env->mmon_entry->addr);
}

target_phys_addr_t cpu_get_phys_page_debug(CPUState *env, target_ulong addr)
{
    return addr;
}

/* These should probably raise undefined insn exceptions.  */
void helper_set_cp(CPUState *env, uint32_t insn, uint32_t val)
{
    int op1 = (insn >> 8) & 0xf;
    cpu_abort(env, "cp%i insn %08x\n", op1, insn);
    return;
}

uint32_t helper_get_cp(CPUState *env, uint32_t insn)
{
    int op1 = (insn >> 8) & 0xf;
    cpu_abort(env, "cp%i insn %08x\n", op1, insn);
    return 0;
}

void helper_set_cp15(CPUState *env, uint32_t insn, uint32_t val)
{
    cpu_abort(env, "cp15 insn %08x\n", insn);
}

uint32_t helper_get_cp15(CPUState *env, uint32_t insn)
{
    cpu_abort(env, "cp15 insn %08x\n", insn);
    return 0;
}

/* These should probably raise undefined insn exceptions.  */
void helper_v7m_msr(CPUState *env, int reg, uint32_t val)
{
    cpu_abort(env, "v7m_mrs %d\n", reg);
}

uint32_t helper_v7m_mrs(CPUState *env, int reg)
{
    cpu_abort(env, "v7m_mrs %d\n", reg);
    return 0;
}

void helper_set_teecr(CPUState *env, uint32_t val)
{
    cpu_abort(env, "set_teecr %d\n", val);
}

void switch_mode(CPUState *env, int mode)
{
    if (mode != ARM_CPU_MODE_USR)
        cpu_abort(env, "Tried to switch out of user mode\n");
}

void helper_set_r13_banked(CPUState *env, int mode, uint32_t val)
{
    cpu_abort(env, "banked r13 write\n");
}

uint32_t helper_get_r13_banked(CPUState *env, int mode)
{
    cpu_abort(env, "banked r13 read\n");
    return 0;
}

#else

/* Map CPU modes onto saved register banks.  */
static inline int bank_number (int mode)
{
    switch (mode) {
    case ARM_CPU_MODE_USR:
    case ARM_CPU_MODE_SYS:
        return 0;
    case ARM_CPU_MODE_SVC:
        return 1;
    case ARM_CPU_MODE_ABT:
        return 2;
    case ARM_CPU_MODE_UND:
        return 3;
    case ARM_CPU_MODE_IRQ:
        return 4;
    case ARM_CPU_MODE_FIQ:
        return 5;
    }
    cpu_abort(cpu_single_env, "Bad mode %x\n", mode);
    return -1;
}

void switch_mode(CPUState *env, int mode)
{
    int old_mode;
    int i;

    old_mode = env->uncached_cpsr & CPSR_M;
    if (mode == old_mode)
        return;

    if (old_mode == ARM_CPU_MODE_FIQ) {
        memcpy (env->fiq_regs, env->regs + 8, 5 * sizeof(uint32_t));
        memcpy (env->regs + 8, env->usr_regs, 5 * sizeof(uint32_t));
    } else if (mode == ARM_CPU_MODE_FIQ) {
        memcpy (env->usr_regs, env->regs + 8, 5 * sizeof(uint32_t));
        memcpy (env->regs + 8, env->fiq_regs, 5 * sizeof(uint32_t));
    }

    i = bank_number(old_mode);
    env->banked_r13[i] = env->regs[13];
    env->banked_r14[i] = env->regs[14];
    env->banked_spsr[i] = env->spsr;

    i = bank_number(mode);
    env->regs[13] = env->banked_r13[i];
    env->regs[14] = env->banked_r14[i];
    env->spsr = env->banked_spsr[i];
}

static void v7m_push(CPUARMState *env, uint32_t val)
{
    env->regs[13] -= 4;
    stl_phys(env->regs[13], val);
}

static uint32_t v7m_pop(CPUARMState *env)
{
    uint32_t val;
    val = ldl_phys(env->regs[13]);
    env->regs[13] += 4;
    return val;
}

/* Switch to V7M main or process stack pointer.  */
static void switch_v7m_sp(CPUARMState *env, int process)
{
    uint32_t tmp;
    if (env->v7m.current_sp != process) {
        tmp = env->v7m.other_sp;
        env->v7m.other_sp = env->regs[13];
        env->regs[13] = tmp;
        env->v7m.current_sp = process;
    }
}

static void do_v7m_exception_exit(CPUARMState *env)
{
    uint32_t type;
    uint32_t xpsr;

    type = env->regs[15];
    if (env->v7m.exception != 0)
        armv7m_nvic_complete_irq(env->v7m.nvic, env->v7m.exception);

    /* Switch to the target stack.  */
    switch_v7m_sp(env, (type & 4) != 0);
    /* Pop registers.  */
    env->regs[0] = v7m_pop(env);
    env->regs[1] = v7m_pop(env);
    env->regs[2] = v7m_pop(env);
    env->regs[3] = v7m_pop(env);
    env->regs[12] = v7m_pop(env);
    env->regs[14] = v7m_pop(env);
    env->regs[15] = v7m_pop(env);
    xpsr = v7m_pop(env);
    xpsr_write(env, xpsr, 0xfffffdff);
    /* Undo stack alignment.  */
    if (xpsr & 0x200)
        env->regs[13] |= 4;
    /* ??? The exception return type specifies Thread/Handler mode.  However
       this is also implied by the xPSR value. Not sure what to do
       if there is a mismatch.  */
    /* ??? Likewise for mismatches between the CONTROL register and the stack
       pointer.  */
}

void do_interrupt_v7m(CPUARMState *env)
{
    uint32_t xpsr = xpsr_read(env);
    uint32_t lr;
    uint32_t addr;

    lr = 0xfffffff1;
    if (env->v7m.current_sp)
        lr |= 4;
    if (env->v7m.exception == 0)
        lr |= 8;

    /* For exceptions we just mark as pending on the NVIC, and let that
       handle it.  */
    /* TODO: Need to escalate if the current priority is higher than the
       one we're raising.  */
    switch (env->exception_index) {
    case EXCP_UDEF:
        armv7m_nvic_set_pending(env->v7m.nvic, ARMV7M_EXCP_USAGE);
        return;
    case EXCP_SWI:
        env->regs[15] += 2;
        armv7m_nvic_set_pending(env->v7m.nvic, ARMV7M_EXCP_SVC);
        return;
    case EXCP_PREFETCH_ABORT:
    case EXCP_DATA_ABORT:
        armv7m_nvic_set_pending(env->v7m.nvic, ARMV7M_EXCP_MEM);
        return;
    case EXCP_IRQ:
        env->v7m.exception = armv7m_nvic_acknowledge_irq(env->v7m.nvic);
        break;
    case EXCP_EXCEPTION_EXIT:
        do_v7m_exception_exit(env);
        return;
    default:
        cpu_abort(env, "Unhandled exception 0x%x\n", env->exception_index);
        return; /* Never happens.  Keep compiler happy.  */
    }

    /* Align stack pointer.  */
    /* ??? Should only do this if Configuration Control Register
       STACKALIGN bit is set.  */
    if (env->regs[13] & 4) {
        env->regs[13] += 4;
        xpsr |= 0x200;
    }
    /* Switch to the hander mode.  */
    v7m_push(env, xpsr);
    v7m_push(env, env->regs[15]);
    v7m_push(env, env->regs[14]);
    v7m_push(env, env->regs[12]);
    v7m_push(env, env->regs[3]);
    v7m_push(env, env->regs[2]);
    v7m_push(env, env->regs[1]);
    v7m_push(env, env->regs[0]);
    switch_v7m_sp(env, 0);
    env->uncached_cpsr &= ~CPSR_IT;
    env->regs[14] = lr;
    addr = ldl_phys(env->v7m.vecbase + env->v7m.exception * 4);
    env->regs[15] = addr & 0xfffffffe;
    env->thumb = addr & 1;
}

/* Handle a CPU exception.  */
void do_interrupt(CPUARMState *env)
{
    uint32_t addr;
    uint32_t mask;
    int new_mode;
    uint32_t offset;

    if (IS_M(env)) {
        do_interrupt_v7m(env);
        return;
    }
    /* TODO: Vectored interrupt controller.  */
    switch (env->exception_index) {
    case EXCP_UDEF:
        new_mode = ARM_CPU_MODE_UND;
        addr = 0x04;
        mask = CPSR_I;
        if (env->thumb)
            offset = 2;
        else
            offset = 4;
        break;
    case EXCP_SWI:
        new_mode = ARM_CPU_MODE_SVC;
        addr = 0x08;
        mask = CPSR_I;
        /* The PC already points to the next instructon.  */
        offset = 0;
        break;
    case EXCP_PREFETCH_ABORT:
        new_mode = ARM_CPU_MODE_ABT;
        addr = 0x0c;
        mask = CPSR_A | CPSR_I;
        offset = 4;
        break;
    case EXCP_DATA_ABORT:
        new_mode = ARM_CPU_MODE_ABT;
        addr = 0x10;
        mask = CPSR_A | CPSR_I;
        offset = 8;
        break;
    case EXCP_IRQ:
        new_mode = ARM_CPU_MODE_IRQ;
        addr = 0x18;
        /* Disable IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I;
        offset = 4;
        break;
    case EXCP_FIQ:
        new_mode = ARM_CPU_MODE_FIQ;
        addr = 0x1c;
        /* Disable FIQ, IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I | CPSR_F;
        offset = 4;
        break;
    default:
        cpu_abort(env, "Unhandled exception 0x%x\n", env->exception_index);
        return; /* Never happens.  Keep compiler happy.  */
    }
    /* High vectors.  */
    if (env->cp15.c1_sys & (1 << 13)) {
        addr += 0xffff0000;
    }
    switch_mode (env, new_mode);
    env->spsr = cpsr_read(env);
    /* Clear IT bits.  */
    env->condexec_bits = 0;
    /* Switch to the new mode, and switch to Arm mode.  */
    /* ??? Thumb interrupt handlers not implemented.  */
    env->uncached_cpsr = (env->uncached_cpsr & ~CPSR_M) | new_mode;
    env->uncached_cpsr |= mask;
    env->thumb = 0;
    env->regs[14] = env->regs[15] + offset;
    env->regs[15] = addr;
    env->interrupt_request |= CPU_INTERRUPT_EXITTB;
}

/* Check section/page access permissions.
   Returns the page protection flags, or zero if the access is not
   permitted.  */
static inline int check_ap(CPUState *env, int ap, int domain, int access_type,
                           int is_user)
{
  int prot_ro;

  if (domain == 3)
    return PAGE_READ | PAGE_WRITE;

  if (access_type == 1)
      prot_ro = 0;
  else
      prot_ro = PAGE_READ;

  switch (ap) {
  case 0:
      if (access_type == 1)
          return 0;
      switch ((env->cp15.c1_sys >> 8) & 3) {
      case 1:
          return is_user ? 0 : PAGE_READ;
      case 2:
          return PAGE_READ;
      default:
          return 0;
      }
  case 1:
      return is_user ? 0 : PAGE_READ | PAGE_WRITE;
  case 2:
      if (is_user)
          return prot_ro;
      else
          return PAGE_READ | PAGE_WRITE;
  case 3:
      return PAGE_READ | PAGE_WRITE;
  case 4: case 7: /* Reserved.  */
      return 0;
  case 5:
      return is_user ? 0 : prot_ro;
  case 6:
      return prot_ro;
  default:
      abort();
  }
}

static int get_phys_addr_v5(CPUState *env, uint32_t address, int access_type,
			    int is_user, uint32_t *phys_ptr, int *prot)
{
    int code;
    uint32_t table;
    uint32_t desc;
    int type;
    int ap;
    int domain;
    uint32_t phys_addr;

    /* Pagetable walk.  */
    /* Lookup l1 descriptor.  */
    if (address & env->cp15.c2_mask)
        table = env->cp15.c2_base1;
    else
        table = env->cp15.c2_base0;
    table = (table & 0xffffc000) | ((address >> 18) & 0x3ffc);
    desc = ldl_phys(table);
    type = (desc & 3);
    domain = (env->cp15.c3 >> ((desc >> 4) & 0x1e)) & 3;
    if (type == 0) {
        /* Secton translation fault.  */
        code = 5;
        goto do_fault;
    }
    if (domain == 0 || domain == 2) {
        if (type == 2)
            code = 9; /* Section domain fault.  */
        else
            code = 11; /* Page domain fault.  */
        goto do_fault;
    }
    if (type == 2) {
        /* 1Mb section.  */
        phys_addr = (desc & 0xfff00000) | (address & 0x000fffff);
        ap = (desc >> 10) & 3;
        code = 13;
    } else {
        /* Lookup l2 entry.  */
	if (type == 1) {
	    /* Coarse pagetable.  */
	    table = (desc & 0xfffffc00) | ((address >> 10) & 0x3fc);
	} else {
	    /* Fine pagetable.  */
	    table = (desc & 0xfffff000) | ((address >> 8) & 0xffc);
	}
        desc = ldl_phys(table);
        switch (desc & 3) {
        case 0: /* Page translation fault.  */
            code = 7;
            goto do_fault;
        case 1: /* 64k page.  */
            phys_addr = (desc & 0xffff0000) | (address & 0xffff);
            ap = (desc >> (4 + ((address >> 13) & 6))) & 3;
            break;
        case 2: /* 4k page.  */
            phys_addr = (desc & 0xfffff000) | (address & 0xfff);
            ap = (desc >> (4 + ((address >> 13) & 6))) & 3;
            break;
        case 3: /* 1k page.  */
	    if (type == 1) {
		if (arm_feature(env, ARM_FEATURE_XSCALE)) {
		    phys_addr = (desc & 0xfffff000) | (address & 0xfff);
		} else {
		    /* Page translation fault.  */
		    code = 7;
		    goto do_fault;
		}
	    } else {
		phys_addr = (desc & 0xfffffc00) | (address & 0x3ff);
	    }
            ap = (desc >> 4) & 3;
            break;
        default:
            /* Never happens, but compiler isn't smart enough to tell.  */
            abort();
        }
        code = 15;
    }
    *prot = check_ap(env, ap, domain, access_type, is_user);
    if (!*prot) {
        /* Access permission fault.  */
        goto do_fault;
    }
    *phys_ptr = phys_addr;
    return 0;
do_fault:
    return code | (domain << 4);
}

static int get_phys_addr_v6(CPUState *env, uint32_t address, int access_type,
			    int is_user, uint32_t *phys_ptr, int *prot)
{
    int code;
    uint32_t table;
    uint32_t desc;
    uint32_t xn;
    int type;
    int ap;
    int domain;
    uint32_t phys_addr;

    /* Pagetable walk.  */
    /* Lookup l1 descriptor.  */
    if (address & env->cp15.c2_mask)
        table = env->cp15.c2_base1;
    else
        table = env->cp15.c2_base0;
    table = (table & 0xffffc000) | ((address >> 18) & 0x3ffc);
    desc = ldl_phys(table);
    type = (desc & 3);
    if (type == 0) {
        /* Secton translation fault.  */
        code = 5;
        domain = 0;
        goto do_fault;
    } else if (type == 2 && (desc & (1 << 18))) {
        /* Supersection.  */
        domain = 0;
    } else {
        /* Section or page.  */
        domain = (desc >> 4) & 0x1e;
    }
    domain = (env->cp15.c3 >> domain) & 3;
    if (domain == 0 || domain == 2) {
        if (type == 2)
            code = 9; /* Section domain fault.  */
        else
            code = 11; /* Page domain fault.  */
        goto do_fault;
    }
    if (type == 2) {
        if (desc & (1 << 18)) {
            /* Supersection.  */
            phys_addr = (desc & 0xff000000) | (address & 0x00ffffff);
        } else {
            /* Section.  */
            phys_addr = (desc & 0xfff00000) | (address & 0x000fffff);
        }
        ap = ((desc >> 10) & 3) | ((desc >> 13) & 4);
        xn = desc & (1 << 4);
        code = 13;
    } else {
        /* Lookup l2 entry.  */
        table = (desc & 0xfffffc00) | ((address >> 10) & 0x3fc);
        desc = ldl_phys(table);
        ap = ((desc >> 4) & 3) | ((desc >> 7) & 4);
        switch (desc & 3) {
        case 0: /* Page translation fault.  */
            code = 7;
            goto do_fault;
        case 1: /* 64k page.  */
            phys_addr = (desc & 0xffff0000) | (address & 0xffff);
            xn = desc & (1 << 15);
            break;
        case 2: case 3: /* 4k page.  */
            phys_addr = (desc & 0xfffff000) | (address & 0xfff);
            xn = desc & 1;
            break;
        default:
            /* Never happens, but compiler isn't smart enough to tell.  */
            abort();
        }
        code = 15;
    }
    if (xn && access_type == 2)
        goto do_fault;

    *prot = check_ap(env, ap, domain, access_type, is_user);
    if (!*prot) {
        /* Access permission fault.  */
        goto do_fault;
    }
    *phys_ptr = phys_addr;
    return 0;
do_fault:
    return code | (domain << 4);
}

static int get_phys_addr_mpu(CPUState *env, uint32_t address, int access_type,
			     int is_user, uint32_t *phys_ptr, int *prot)
{
    int n;
    uint32_t mask;
    uint32_t base;

    *phys_ptr = address;
    for (n = 7; n >= 0; n--) {
	base = env->cp15.c6_region[n];
	if ((base & 1) == 0)
	    continue;
	mask = 1 << ((base >> 1) & 0x1f);
	/* Keep this shift separate from the above to avoid an
	   (undefined) << 32.  */
	mask = (mask << 1) - 1;
	if (((base ^ address) & ~mask) == 0)
	    break;
    }
    if (n < 0)
	return 2;

    if (access_type == 2) {
	mask = env->cp15.c5_insn;
    } else {
	mask = env->cp15.c5_data;
    }
    mask = (mask >> (n * 4)) & 0xf;
    switch (mask) {
    case 0:
	return 1;
    case 1:
	if (is_user)
	  return 1;
	*prot = PAGE_READ | PAGE_WRITE;
	break;
    case 2:
	*prot = PAGE_READ;
	if (!is_user)
	    *prot |= PAGE_WRITE;
	break;
    case 3:
	*prot = PAGE_READ | PAGE_WRITE;
	break;
    case 5:
	if (is_user)
	    return 1;
	*prot = PAGE_READ;
	break;
    case 6:
	*prot = PAGE_READ;
	break;
    default:
	/* Bad permission.  */
	return 1;
    }
    return 0;
}

inline int get_phys_addr(CPUState *env, uint32_t address,
                                int access_type, int is_user,
                                uint32_t *phys_ptr, int *prot)
{
    /* Fast Context Switch Extension.  */
    if (address < 0x02000000)
        address += env->cp15.c13_fcse;

    if ((env->cp15.c1_sys & 1) == 0) {
        /* MMU/MPU disabled.  */
        *phys_ptr = address;
        *prot = PAGE_READ | PAGE_WRITE;
        return 0;
    } else if (arm_feature(env, ARM_FEATURE_MPU)) {
	return get_phys_addr_mpu(env, address, access_type, is_user, phys_ptr,
				 prot);
    } else if (env->cp15.c1_sys & (1 << 23)) {
        return get_phys_addr_v6(env, address, access_type, is_user, phys_ptr,
                                prot);
    } else {
        return get_phys_addr_v5(env, address, access_type, is_user, phys_ptr,
                                prot);
    }
}

int cpu_arm_handle_mmu_fault (CPUState *env, target_ulong address,
                              int access_type, int mmu_idx, int is_softmmu)
{
    uint32_t phys_addr;
    int prot;
    int ret, is_user;

    is_user = mmu_idx == MMU_USER_IDX;
    ret = get_phys_addr(env, address, access_type, is_user, &phys_addr, &prot);
    if (ret == 0) {
        /* Map a single [sub]page.  */
        phys_addr &= ~(uint32_t)0x3ff;
        address &= ~(uint32_t)0x3ff;
        return tlb_set_page (env, address, phys_addr, prot, mmu_idx,
                             is_softmmu);
    }

    if (access_type == 2) {
        env->cp15.c5_insn = ret;
        env->cp15.c6_insn = address;
        env->exception_index = EXCP_PREFETCH_ABORT;
    } else {
        env->cp15.c5_data = ret;
        if (access_type == 1 && arm_feature(env, ARM_FEATURE_V6))
            env->cp15.c5_data |= (1 << 11);
        env->cp15.c6_data = address;
        env->exception_index = EXCP_DATA_ABORT;
    }
    return 1;
}

target_phys_addr_t cpu_get_phys_page_debug(CPUState *env, target_ulong addr)
{
    uint32_t phys_addr;
    int prot;
    int ret;

    ret = get_phys_addr(env, addr, 0, 0, &phys_addr, &prot);

    if (ret != 0)
        return -1;

    return phys_addr;
}

void helper_mark_exclusive(CPUState *env, uint32_t addr)
{
    env->mmon_addr = get_phys_addr_gdb(addr);
    memex_mark(env->cpu_index, env->mmon_addr);
}

int helper_test_exclusive(CPUState *env, uint32_t addr)
{
    addr = get_phys_addr_gdb(addr);

    return (env->mmon_addr == -1) || (env->mmon_addr != addr) ||
        memex_test(env->cpu_index, addr);
}

void helper_clrex(CPUState *env)
{
    if (env->mmon_addr == -1)
        return;

    memex_clear(env->cpu_index, env->mmon_addr);
    env->mmon_addr = -1;
}

void helper_set_cp(CPUState *env, uint32_t insn, uint32_t val)
{
    int cp_num = (insn >> 8) & 0xf;
    int cp_info = (insn >> 5) & 7;
    int src = (insn >> 16) & 0xf;
    int operand = insn & 0xf;

    if (env->cp[cp_num].cp_write)
        env->cp[cp_num].cp_write(env->cp[cp_num].opaque,
                                 cp_info, src, operand, val);
}

uint32_t helper_get_cp(CPUState *env, uint32_t insn)
{
    int cp_num = (insn >> 8) & 0xf;
    int cp_info = (insn >> 5) & 7;
    int dest = (insn >> 16) & 0xf;
    int operand = insn & 0xf;

    if (env->cp[cp_num].cp_read)
        return env->cp[cp_num].cp_read(env->cp[cp_num].opaque,
                                       cp_info, dest, operand);
    return 0;
}

/* Return basic MPU access permission bits.  */
static uint32_t simple_mpu_ap_bits(uint32_t val)
{
    uint32_t ret;
    uint32_t mask;
    int i;
    ret = 0;
    mask = 3;
    for (i = 0; i < 16; i += 2) {
        ret |= (val >> i) & mask;
        mask <<= 2;
    }
    return ret;
}

/* Pad basic MPU access permission bits to extended format.  */
static uint32_t extended_mpu_ap_bits(uint32_t val)
{
    uint32_t ret;
    uint32_t mask;
    int i;
    ret = 0;
    mask = 3;
    for (i = 0; i < 16; i += 2) {
        ret |= (val & mask) << i;
        mask <<= 2;
    }
    return ret;
}

static uint64_t __qemu_get_no_cycles(CPUState *env)
{
    uint64_t cycles;

    SAVE_ENV_BEFORE_CONSUME_SYSTEMC ();
    cycles = _save_crt_qemu_instance->systemc.systemc_qemu_get_no_cycles(_save_cpu_single_env->qemu.sc_obj);
    RESTORE_ENV_AFTER_CONSUME_SYSTEMC ();

    return cycles;
}

static uint64_t qemu_get_no_cycles(CPUState *env)
{
    unsigned int rshift = env->cp15.c15_pmnc & BIT(3) ? 6 : 0;
    uint64_t cycles = __qemu_get_no_cycles(env) - env->ccnt_offset;

    return cycles >> rshift;
}

/* Reset the offset to start counting from the given value */
static inline void ccnt_offset_reset(CPUState *env, uint64_t value)
{
    env->ccnt_offset = __qemu_get_no_cycles(env) - value;
}

static inline void ccnt_update(CPUState *env)
{
    uint64_t cycles = qemu_get_no_cycles(env);

    env->cp15.c15_ccnt_lo = cycles & ((1ULL << 32) - 1);
    env->cp15.c15_ccnt_hi = cycles >> 32;
}

static void perf_update_event_source(CPUARMState *s, uint32_t val, int shift, int idx)
{
    struct perf_event *event = &s->perf_events[idx];

    event->type = (val >> shift) & 0xff;
}

static void perf_count_set_lo(struct perf_event *event, uint64_t val)
{
    event->count &= ~((1ULL << 32) - 1);
    event->count |= val & ((1ULL << 32) - 1);
}

static void perf_count_set_hi(struct perf_event *event, uint64_t val)
{
    event->count &= ~(((1ULL << 32) - 1) << 32);
    event->count |= val << 32;
}

static uint32_t perf_count_get_lo(struct perf_event *event)
{
    return lower_32_bits(event->count);
}

static uint32_t perf_count_get_hi(struct perf_event *event)
{
    return upper_32_bits(event->count);
}

static inline int counters_are_enabled(const CPUARMState *s)
{
    return s->cp15.c15_pmnc & BIT(0);
}

void perf_event_add(CPUARMState *s, enum perf_types type, int64_t val)
{
    int i;

    if (!counters_are_enabled(s))
        return;

    for (i = 0; i < ARM11MPCORE_PERF_COUNTERS; i++) {
        struct perf_event *event = &s->perf_events[i];

        if (event->type == type)
            event->count += val;
    }
}

void helper_set_cp15(CPUState *env, uint32_t insn, uint32_t val)
{
    int op1;
    int op2;
    int crm;

    op1 = (insn >> 21) & 7;
    op2 = (insn >> 5) & 7;
    crm = insn & 0xf;
    switch ((insn >> 16) & 0xf) {
    case 0:
        if (((insn >> 21) & 7) == 2) {
            /* ??? Select cache level.  Ignore.  */
            return;
        }
        /* ID codes.  */
        if (arm_feature(env, ARM_FEATURE_XSCALE))
            break;
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            break;
        goto bad_reg;
    case 1: /* System configuration.  */
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            op2 = 0;
        switch (op2) {
        case 0:
            if (!arm_feature(env, ARM_FEATURE_XSCALE) || crm == 0)
                env->cp15.c1_sys = val;
            /* ??? Lots of these bits are not implemented.  */
            /* This may enable/disable the MMU, so do a TLB flush.  */
            tlb_flush(env, 1);
            break;
        case 1: /* Auxiliary cotrol register.  */
            if (arm_feature(env, ARM_FEATURE_XSCALE)) {
                env->cp15.c1_xscaleauxcr = val;
                break;
            }
            /* Not implemented.  */
            break;
        case 2:
            if (arm_feature(env, ARM_FEATURE_XSCALE))
                goto bad_reg;
            env->cp15.c1_coproc = val;
            /* ??? Is this safe when called from within a TB?  */
            tb_flush(env);
            break;
        default:
            goto bad_reg;
        }
        break;
    case 2: /* MMU Page table control / MPU cache control.  */
        if (arm_feature(env, ARM_FEATURE_MPU)) {
            switch (op2) {
            case 0:
                env->cp15.c2_data = val;
                break;
            case 1:
                env->cp15.c2_insn = val;
                break;
            default:
                goto bad_reg;
            }
        } else {
	    switch (op2) {
	    case 0:
		env->cp15.c2_base0 = val;
		break;
	    case 1:
		env->cp15.c2_base1 = val;
		break;
	    case 2:
		env->cp15.c2_mask = ~(((uint32_t)0xffffffffu) >> val);
		break;
	    default:
		goto bad_reg;
	    }
        }
        break;
    case 3: /* MMU Domain access control / MPU write buffer control.  */
        env->cp15.c3 = val;
        tlb_flush(env, 1); /* Flush TLB as domain not tracked in TLB */
        break;
    case 4: /* Reserved.  */
        goto bad_reg;
    case 5: /* MMU Fault status / MPU access permission.  */
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            op2 = 0;
        switch (op2) {
        case 0:
            if (arm_feature(env, ARM_FEATURE_MPU))
                val = extended_mpu_ap_bits(val);
            env->cp15.c5_data = val;
            break;
        case 1:
            if (arm_feature(env, ARM_FEATURE_MPU))
                val = extended_mpu_ap_bits(val);
            env->cp15.c5_insn = val;
            break;
        case 2:
            if (!arm_feature(env, ARM_FEATURE_MPU))
                goto bad_reg;
            env->cp15.c5_data = val;
            break;
        case 3:
            if (!arm_feature(env, ARM_FEATURE_MPU))
                goto bad_reg;
            env->cp15.c5_insn = val;
            break;
        default:
            goto bad_reg;
        }
        break;
    case 6: /* MMU Fault address / MPU base/size.  */
        if (arm_feature(env, ARM_FEATURE_MPU)) {
            if (crm >= 8)
                goto bad_reg;
            env->cp15.c6_region[crm] = val;
        } else {
            if (arm_feature(env, ARM_FEATURE_OMAPCP))
                op2 = 0;
            switch (op2) {
            case 0:
                env->cp15.c6_data = val;
                break;
            case 1: /* ??? This is WFAR on armv6 */
            case 2:
                env->cp15.c6_insn = val;
                break;
            default:
                goto bad_reg;
            }
        }
        break;
    case 7: /* Cache control.  */
        env->cp15.c15_i_max = 0x000;
        env->cp15.c15_i_min = 0xff0;
        /* No cache, so nothing to do.  */
        /* ??? MPCore has VA to PA translation functions.  */
        break;
    case 8: /* MMU TLB control.  */
        switch (op2) {
        case 0: /* Invalidate all.  */
            tlb_flush(env, 0);
            break;
        case 1: /* Invalidate single TLB entry.  */
#if 0
            /* ??? This is wrong for large pages and sections.  */
            /* As an ugly hack to make linux work we always flush a 4K
               pages.  */
            val &= 0xfffff000;
            tlb_flush_page(env, val);
            tlb_flush_page(env, val + 0x400);
            tlb_flush_page(env, val + 0x800);
            tlb_flush_page(env, val + 0xc00);
#else
            tlb_flush(env, 1);
#endif
            break;
        case 2: /* Invalidate on ASID.  */
            tlb_flush(env, val == 0);
            break;
        case 3: /* Invalidate single entry on MVA.  */
            /* ??? This is like case 1, but ignores ASID.  */
            tlb_flush(env, 1);
            break;
        default:
            goto bad_reg;
        }
        break;
    case 9:
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            break;
        switch (crm) {
        case 0: /* Cache lockdown.  */
	    switch (op1) {
	    case 0: /* L1 cache.  */
		switch (op2) {
		case 0:
		    env->cp15.c9_data = val;
		    break;
		case 1:
		    env->cp15.c9_insn = val;
		    break;
		default:
		    goto bad_reg;
		}
		break;
	    case 1: /* L2 cache.  */
		/* Ignore writes to L2 lockdown/auxiliary registers.  */
		break;
	    default:
		goto bad_reg;
	    }
	    break;
        case 1: /* TCM memory region registers.  */
            /* Not implemented.  */
            goto bad_reg;
        case 12: /* Performance monitor control */
            /* Performance monitors are implementation defined in v7,
             * but with an ARM recommended set of registers, which we
             * follow (although we don't actually implement any counters)
             */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 0: /* performance monitor control register */
                /* only the DP, X, D and E bits are writable */
                env->cp15.c9_pmcr &= ~0x39;
                env->cp15.c9_pmcr |= (val & 0x39);
                break;
            case 1: /* Count enable set register */
                val &= (1 << 31);
                env->cp15.c9_pmcnten |= val;
                break;
            case 2: /* Count enable clear */
                val &= (1 << 31);
                env->cp15.c9_pmcnten &= ~val;
                break;
            case 3: /* Overflow flag status */
                env->cp15.c9_pmovsr &= ~val;
                break;
            case 4: /* Software increment */
                /* RAZ/WI since we don't implement the software-count event */
                break;
            case 5: /* Event counter selection register */
                /* Since we don't implement any events, writing to this register
                 * is actually UNPREDICTABLE. So we choose to RAZ/WI.
                 */
                break;
            default:
                goto bad_reg;
            }
            break;
        case 13: /* Performance counters */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 0: /* Cycle count register: not implemented, so RAZ/WI */
                break;
            case 1: /* Event type select */
                env->cp15.c9_pmxevtyper = val & 0xff;
                break;
            case 2: /* Event count register */
                /* Unimplemented (we have no events), RAZ/WI */
                break;
            default:
                goto bad_reg;
            }
            break;
        case 14: /* Performance monitor control */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 0: /* user enable */
                env->cp15.c9_pmuserenr = val & 1;
                /* changes access rights for cp registers, so flush tbs */
                tb_flush(env);
                break;
            case 1: /* interrupt enable set */
                /* We have no event counters so only the C bit can be changed */
                val &= (1 << 31);
                env->cp15.c9_pminten |= val;
                break;
            case 2: /* interrupt enable clear */
                val &= (1 << 31);
                env->cp15.c9_pminten &= ~val;
                break;
            }
            break;
        default:
            goto bad_reg;
        }
        break;
    case 10: /* MMU TLB lockdown.  */
        /* ??? TLB lockdown not implemented.  */
        break;
    case 12: /* Reserved.  */
        goto bad_reg;
    case 13: /* Process ID.  */
        switch (op2) {
        case 0:
            /* Unlike real hardware the qemu TLB uses virtual addresses,
               not modified virtual addresses, so this causes a TLB flush.
             */
            if (env->cp15.c13_fcse != val)
              tlb_flush(env, 1);
            env->cp15.c13_fcse = val;
            break;
        case 1:
            /* This changes the ASID, so do a TLB flush.  */
            if (env->cp15.c13_context != val
                && !arm_feature(env, ARM_FEATURE_MPU))
              tlb_flush(env, 0);
            env->cp15.c13_context = val;
            break;
        case 2:
            env->cp15.c13_tls1 = val;
            break;
        case 3:
            env->cp15.c13_tls2 = val;
            break;
        case 4:
            env->cp15.c13_tls3 = val;
            break;
        default:
            goto bad_reg;
        }
        break;
    case 14: /* Reserved.  */
        goto bad_reg;
    case 15: /* Implementation specific.  */
        if (arm_feature(env, ARM_FEATURE_XSCALE)) {
            if (op2 == 0 && crm == 1) {
                if (env->cp15.c15_cpar != (val & 0x3fff)) {
                    /* Changes cp0 to cp13 behavior, so needs a TB flush.  */
                    tb_flush(env);
                    env->cp15.c15_cpar = val & 0x3fff;
                }
                break;
            }
            goto bad_reg;
        }
        if (arm_feature(env, ARM_FEATURE_OMAPCP)) {
            switch (crm) {
            case 0:
                break;
            case 1: /* Set TI925T configuration.  */
                env->cp15.c15_ticonfig = val & 0xe7;
                env->cp15.c0_cpuid = (val & (1 << 5)) ? /* OS_TYPE bit */
                        ARM_CPUID_TI915T : ARM_CPUID_TI925T;
                break;
            case 2: /* Set I_max.  */
                env->cp15.c15_i_max = val;
                break;
            case 3: /* Set I_min.  */
                env->cp15.c15_i_min = val;
                break;
            case 4: /* Set thread-ID.  */
                env->cp15.c15_threadid = val & 0xffff;
                break;
            case 8: /* Wait-for-interrupt (deprecated).  */
                cpu_interrupt(env, CPU_INTERRUPT_HALT);
                break;
            default:
                goto bad_reg;
            }
        }
        if (ARM_CPUID(env) == ARM_CPUID_ARM11MPCORE) {
            switch (crm) {
            case 12:
                switch (op2) {
                    case 0: /* PMNC: Performance Monitor Control Register */
                    val &= 0x0ffff77f;

                    perf_update_event_source(env, val, 20, 0);
                    perf_update_event_source(env, val, 12, 1);

                    /* reset ccnt */
                    if (val & BIT(2)) {
                        env->cp15.c15_ccnt_lo = 0;
                        env->cp15.c15_ccnt_hi = 0;
                        /* if already running, update offset */
                        if (counters_are_enabled(env))
                            ccnt_offset_reset(env, 0);
                    }

                    /* enable counters --> start counting offset */
                    if ((val & BIT(0)) && !counters_are_enabled(env)) {

                        uint64_t currcount = env->cp15.c15_ccnt_hi;
                        currcount <<= 32;
                        currcount |= env->cp15.c15_ccnt_lo;

                        ccnt_offset_reset(env, currcount);
                    }

                    /* disable counters -> get a last ccnt update */
                    if (!(val & BIT(0)) && counters_are_enabled(env))
                        ccnt_update(env);

                    env->cp15.c15_pmnc = val;
                    break;
                case 1: /* CCNT: Cycle Counter Register */
                    env->cp15.c15_ccnt_lo = val;
                    break;
                case 2: /* PMN0: Count Register 0 */
                    perf_count_set_lo(&env->perf_events[0], val);
                    break;
                case 3: /* PMN1: Count Register 1 */
                    perf_count_set_lo(&env->perf_events[1], val);
                    break;
                case 4:
                    env->cp15.c15_ccnt_hi = val;
                    break;
                case 5:
                    perf_count_set_hi(&env->perf_events[0], val);
                    break;
                case 6:
                    perf_count_set_hi(&env->perf_events[1], val);
                    break;
                default:
                    goto bad_reg;
                }
                break;
            default:
                goto bad_reg;
            }
        }
        break;
    }
    return;
bad_reg:
    /* ??? For debugging only.  Should raise illegal instruction exception.  */
    cpu_abort(env, "Unimplemented cp15 register write (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
}

uint32_t helper_get_cp15(CPUState *env, uint32_t insn)
{
    int op1;
    int op2;
    int crm;

    op1 = (insn >> 21) & 7;
    op2 = (insn >> 5) & 7;
    crm = insn & 0xf;
    switch ((insn >> 16) & 0xf) {
    case 0: /* ID codes.  */
        switch (op1) {
        case 0:
            switch (crm) {
            case 0:
                switch (op2) {
                case 0: /* Device ID.  */
                    return env->cp15.c0_cpuid;
                case 1: /* Cache Type.  */
		    return env->cp15.c0_cachetype;
                case 2: /* TCM status.  */
                    return 0;
                case 3: /* TLB type register.  */
                    return 0; /* No lockable TLB entries.  */
                case 5: /* CPU ID */
					 return env->cpu_index;
                default:
                    goto bad_reg;
                }
            case 1:
                if (!arm_feature(env, ARM_FEATURE_V6))
                    goto bad_reg;
                return env->cp15.c0_c1[op2];
            case 2:
                if (!arm_feature(env, ARM_FEATURE_V6))
                    goto bad_reg;
                return env->cp15.c0_c2[op2];
            case 3: case 4: case 5: case 6: case 7:
                return 0;
            default:
                goto bad_reg;
            }
        case 1:
            /* These registers aren't documented on arm11 cores.  However
               Linux looks at them anyway.  */
            if (!arm_feature(env, ARM_FEATURE_V6))
                goto bad_reg;
            if (crm != 0)
                goto bad_reg;
            if (arm_feature(env, ARM_FEATURE_XSCALE))
                goto bad_reg;
            return 0;
        default:
            goto bad_reg;
        }
    case 1: /* System configuration.  */
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            op2 = 0;
        switch (op2) {
        case 0: /* Control register.  */
            return env->cp15.c1_sys;
        case 1: /* Auxiliary control register.  */
            if (arm_feature(env, ARM_FEATURE_XSCALE))
                return env->cp15.c1_xscaleauxcr;
            if (!arm_feature(env, ARM_FEATURE_AUXCR))
                goto bad_reg;
            switch (ARM_CPUID(env)) {
            case ARM_CPUID_ARM1026:
                return 1;
            case ARM_CPUID_ARM1136:
                return 7;
            case ARM_CPUID_ARM11MPCORE:
                return 1;
            case ARM_CPUID_CORTEXA8:
                return 0;
            default:
                goto bad_reg;
            }
        case 2: /* Coprocessor access register.  */
            if (arm_feature(env, ARM_FEATURE_XSCALE))
                goto bad_reg;
            return env->cp15.c1_coproc;
        default:
            goto bad_reg;
        }
    case 2: /* MMU Page table control / MPU cache control.  */
        if (arm_feature(env, ARM_FEATURE_MPU)) {
            switch (op2) {
            case 0:
                return env->cp15.c2_data;
                break;
            case 1:
                return env->cp15.c2_insn;
                break;
            default:
                goto bad_reg;
            }
        } else {
	    switch (op2) {
	    case 0:
		return env->cp15.c2_base0;
	    case 1:
		return env->cp15.c2_base1;
	    case 2:
		{
		    int n;
		    uint32_t mask;
		    n = 0;
		    mask = env->cp15.c2_mask;
		    while (mask) {
			n++;
			mask <<= 1;
		    }
		    return n;
		}
	    default:
		goto bad_reg;
	    }
	}
    case 3: /* MMU Domain access control / MPU write buffer control.  */
        return env->cp15.c3;
    case 4: /* Reserved.  */
        goto bad_reg;
    case 5: /* MMU Fault status / MPU access permission.  */
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            op2 = 0;
        switch (op2) {
        case 0:
            if (arm_feature(env, ARM_FEATURE_MPU))
                return simple_mpu_ap_bits(env->cp15.c5_data);
            return env->cp15.c5_data;
        case 1:
            if (arm_feature(env, ARM_FEATURE_MPU))
                return simple_mpu_ap_bits(env->cp15.c5_data);
            return env->cp15.c5_insn;
        case 2:
            if (!arm_feature(env, ARM_FEATURE_MPU))
                goto bad_reg;
            return env->cp15.c5_data;
        case 3:
            if (!arm_feature(env, ARM_FEATURE_MPU))
                goto bad_reg;
            return env->cp15.c5_insn;
        default:
            goto bad_reg;
        }
    case 6: /* MMU Fault address.  */
        if (arm_feature(env, ARM_FEATURE_MPU)) {
            if (crm >= 8)
                goto bad_reg;
            return env->cp15.c6_region[crm];
        } else {
            if (arm_feature(env, ARM_FEATURE_OMAPCP))
                op2 = 0;
	    switch (op2) {
	    case 0:
		return env->cp15.c6_data;
	    case 1:
		if (arm_feature(env, ARM_FEATURE_V6)) {
		    /* Watchpoint Fault Adrress.  */
		    return 0; /* Not implemented.  */
		} else {
		    /* Instruction Fault Adrress.  */
		    /* Arm9 doesn't have an IFAR, but implementing it anyway
		       shouldn't do any harm.  */
		    return env->cp15.c6_insn;
		}
	    case 2:
		if (arm_feature(env, ARM_FEATURE_V6)) {
		    /* Instruction Fault Adrress.  */
		    return env->cp15.c6_insn;
		} else {
		    goto bad_reg;
		}
	    default:
		goto bad_reg;
	    }
        }
    case 7: /* Cache control.  */
        /* ??? This is for test, clean and invaidate operations that set the
           Z flag.  We can't represent N = Z = 1, so it also clears
           the N flag.  Oh well.  */
        env->NZF = 0;
        return 0;
    case 8: /* MMU TLB control.  */
        goto bad_reg;
    case 9:
        switch (crm) {
        case 0: /* Cache lockdown */
            switch (op1) {
            case 0: /* L1 cache.  */
                if (arm_feature(env, ARM_FEATURE_OMAPCP)) {
                    return 0;
                }
                switch (op2) {
                case 0:
                    return env->cp15.c9_data;
                case 1:
                    return env->cp15.c9_insn;
                default:
                    goto bad_reg;
                }
            case 1: /* L2 cache */
                if (crm != 0) {
                    goto bad_reg;
                }
                /* L2 Lockdown and Auxiliary control.  */
                return 0;
            default:
                goto bad_reg;
            }
            break;
        case 12: /* Performance monitor control */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 0: /* performance monitor control register */
                return env->cp15.c9_pmcr;
            case 1: /* count enable set */
            case 2: /* count enable clear */
                return env->cp15.c9_pmcnten;
            case 3: /* overflow flag status */
                return env->cp15.c9_pmovsr;
            case 4: /* software increment */
            case 5: /* event counter selection register */
                return 0; /* Unimplemented, RAZ/WI */
            default:
                goto bad_reg;
            }
        case 13: /* Performance counters */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 1: /* Event type select */
                return env->cp15.c9_pmxevtyper;
            case 0: /* Cycle count register */
            case 2: /* Event count register */
                /* Unimplemented, so RAZ/WI */
                return 0;
            default:
                goto bad_reg;
            }
        case 14: /* Performance monitor control */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 0: /* user enable */
                return env->cp15.c9_pmuserenr;
            case 1: /* interrupt enable set */
            case 2: /* interrupt enable clear */
                return env->cp15.c9_pminten;
            default:
                goto bad_reg;
            }
        default:
            goto bad_reg;
        }
	break;
    case 10: /* MMU TLB lockdown.  */
        /* ??? TLB lockdown not implemented.  */
        return 0;
    case 11: /* TCM DMA control.  */
    case 12: /* Reserved.  */
        goto bad_reg;
    case 13: /* Process ID.  */
        switch (op2) {
        case 0:
            return env->cp15.c13_fcse;
        case 1:
            return env->cp15.c13_context;
        case 2:
            return env->cp15.c13_tls1;
        case 3:
            return env->cp15.c13_tls2;
        case 4:
            return env->cp15.c13_tls3;
        default:
            goto bad_reg;
        }
    case 14: /* Reserved.  */
        goto bad_reg;
    case 15: /* Implementation specific.  */
        if (arm_feature(env, ARM_FEATURE_XSCALE)) {
            if (op2 == 0 && crm == 1)
                return env->cp15.c15_cpar;

            goto bad_reg;
        }
        if (arm_feature(env, ARM_FEATURE_OMAPCP)) {
            switch (crm) {
            case 0:
                return 0;
            case 1: /* Read TI925T configuration.  */
                return env->cp15.c15_ticonfig;
            case 2: /* Read I_max.  */
                return env->cp15.c15_i_max;
            case 3: /* Read I_min.  */
                return env->cp15.c15_i_min;
            case 4: /* Read thread-ID.  */
                return env->cp15.c15_threadid;
            case 8: /* TI925T_status */
                return 0;
            }
            goto bad_reg;
        }
	if (ARM_CPUID(env) == ARM_CPUID_ARM11MPCORE) {
	    switch (crm) {
	    case 12:
		switch (op2) {
		case 0: /* PMNC: Performance Monitor Control Register */
		    return env->cp15.c15_pmnc;
		case 1: /* CCNT: Cycle Counter Register */
		    if (env->cp15.c15_pmnc & BIT(0))
                        ccnt_update(env);
		    return env->cp15.c15_ccnt_lo;
		case 2: /* PMN0: Count Register 0 */
                    return perf_count_get_lo(&env->perf_events[0]);
		case 3: /* PMN1: Count Register 1 */
                    return perf_count_get_lo(&env->perf_events[1]);
                case 4:
		    return env->cp15.c15_ccnt_hi;
                case 5:
                    return perf_count_get_hi(&env->perf_events[0]);
                case 6:
                    return perf_count_get_hi(&env->perf_events[1]);
		default:
		    goto bad_reg;
		}
		break;
	    default:
		goto bad_reg;
	    }
	}
        return 0;
    }
bad_reg:
    /* ??? For debugging only.  Should raise illegal instruction exception.  */
    cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
    return 0;
}

void helper_set_r13_banked(CPUState *env, int mode, uint32_t val)
{
    env->banked_r13[bank_number(mode)] = val;
}

uint32_t helper_get_r13_banked(CPUState *env, int mode)
{
    return env->banked_r13[bank_number(mode)];
}

void helper_set_teecr(CPUState *env, uint32_t val)
{
    val &= 1;
    if (env->teecr != val) {
        env->teecr = val;
        tb_flush(env);
    }
}

uint32_t helper_v7m_mrs(CPUState *env, int reg)
{
    switch (reg) {
    case 0: /* APSR */
        return xpsr_read(env) & 0xf8000000;
    case 1: /* IAPSR */
        return xpsr_read(env) & 0xf80001ff;
    case 2: /* EAPSR */
        return xpsr_read(env) & 0xff00fc00;
    case 3: /* xPSR */
        return xpsr_read(env) & 0xff00fdff;
    case 5: /* IPSR */
        return xpsr_read(env) & 0x000001ff;
    case 6: /* EPSR */
        return xpsr_read(env) & 0x0700fc00;
    case 7: /* IEPSR */
        return xpsr_read(env) & 0x0700edff;
    case 8: /* MSP */
        return env->v7m.current_sp ? env->v7m.other_sp : env->regs[13];
    case 9: /* PSP */
        return env->v7m.current_sp ? env->regs[13] : env->v7m.other_sp;
    case 16: /* PRIMASK */
        return (env->uncached_cpsr & CPSR_I) != 0;
    case 17: /* FAULTMASK */
        return (env->uncached_cpsr & CPSR_F) != 0;
    case 18: /* BASEPRI */
    case 19: /* BASEPRI_MAX */
        return env->v7m.basepri;
    case 20: /* CONTROL */
        return env->v7m.control;
    default:
        /* ??? For debugging only.  */
        cpu_abort(env, "Unimplemented system register read (%d)\n", reg);
        return 0;
    }
}

void helper_v7m_msr(CPUState *env, int reg, uint32_t val)
{
    switch (reg) {
    case 0: /* APSR */
        xpsr_write(env, val, 0xf8000000);
        break;
    case 1: /* IAPSR */
        xpsr_write(env, val, 0xf8000000);
        break;
    case 2: /* EAPSR */
        xpsr_write(env, val, 0xfe00fc00);
        break;
    case 3: /* xPSR */
        xpsr_write(env, val, 0xfe00fc00);
        break;
    case 5: /* IPSR */
        /* IPSR bits are readonly.  */
        break;
    case 6: /* EPSR */
        xpsr_write(env, val, 0x0600fc00);
        break;
    case 7: /* IEPSR */
        xpsr_write(env, val, 0x0600fc00);
        break;
    case 8: /* MSP */
        if (env->v7m.current_sp)
            env->v7m.other_sp = val;
        else
            env->regs[13] = val;
        break;
    case 9: /* PSP */
        if (env->v7m.current_sp)
            env->regs[13] = val;
        else
            env->v7m.other_sp = val;
        break;
    case 16: /* PRIMASK */
        if (val & 1)
            env->uncached_cpsr |= CPSR_I;
        else
            env->uncached_cpsr &= ~CPSR_I;
        break;
    case 17: /* FAULTMASK */
        if (val & 1)
            env->uncached_cpsr |= CPSR_F;
        else
            env->uncached_cpsr &= ~CPSR_F;
        break;
    case 18: /* BASEPRI */
        env->v7m.basepri = val & 0xff;
        break;
    case 19: /* BASEPRI_MAX */
        val &= 0xff;
        if (val != 0 && (val < env->v7m.basepri || env->v7m.basepri == 0))
            env->v7m.basepri = val;
        break;
    case 20: /* CONTROL */
        env->v7m.control = val & 3;
        switch_v7m_sp(env, (val & 2) != 0);
        break;
    default:
        /* ??? For debugging only.  */
        cpu_abort(env, "Unimplemented system register write (%d)\n", reg);
        return;
    }
}

void cpu_arm_set_cp_io(CPUARMState *env, int cpnum,
                ARMReadCPFunc *cp_read, ARMWriteCPFunc *cp_write,
                void *opaque)
{
    if (cpnum < 0 || cpnum > 14) {
        cpu_abort(env, "Bad coprocessor number: %i\n", cpnum);
        return;
    }

    env->cp[cpnum].cp_read = cp_read;
    env->cp[cpnum].cp_write = cp_write;
    env->cp[cpnum].opaque = opaque;
}

#endif
