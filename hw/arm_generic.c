#include "hw.h"
#include "qemu_encap.h"

#define ARM_PIC_CPU_IRQ 0
#define ARM_PIC_CPU_FIQ 1

static void arm_pic_cpu_handler(void *opaque, int irq, int level)
{
    CPUState *env = (CPUState *)opaque;
    switch (irq) {
    case ARM_PIC_CPU_IRQ:
        if (level)
            cpu_interrupt(env, CPU_INTERRUPT_HARD);
        else
            cpu_reset_interrupt(env, CPU_INTERRUPT_HARD);
        break;
    case ARM_PIC_CPU_FIQ:
        if (level)
            cpu_interrupt(env, CPU_INTERRUPT_FIQ);
        else
            cpu_reset_interrupt(env, CPU_INTERRUPT_FIQ);
        break;
    default:
        cpu_abort(env, "arm_pic_cpu_handler: Bad interrput line %d\n", irq);
    }
}

qemu_irq *arm_pic_init_cpu(CPUState *env)
{
    return qemu_allocate_irqs(arm_pic_cpu_handler, env, 2);
}

void
armv7m_nvic_set_pending (void *opaque, int irq)
{
  qemu_set_irq ((qemu_irq) opaque, 1);
}

int
armv7m_nvic_acknowledge_irq (void *opaque)
{
  return 0;
}

void
armv7m_nvic_complete_irq (void *opaque, int irq)
{
  qemu_set_irq ((qemu_irq) opaque, 0);
}

void
arm_generic_machine_init (int ram_size, const char *cpu_model)
{
    int i;
    CPUState *env;
    qemu_irq *pic;

    if (!cpu_model)
        cpu_model = "arm926";

    crt_qemu_instance->irqs_systemc = malloc (crt_qemu_instance->NOCPUs * sizeof (qemu_irq));

    for (i = 0; i < crt_qemu_instance->NOCPUs; i++)
    {
        env = cpu_init (cpu_model);
        if (!env)
        {
            fprintf (stderr, "Unable to find CPU definition\n");
            exit (1);
        }
		
        env->mmon_addr = -1;
        env->cpu_platform_index = i + crt_qemu_instance->firstcpuindex;
	    env->qemu.fv_percent = 100;
        env->qemu.qemu_instance = crt_qemu_instance;
        pic = arm_pic_init_cpu (env);
        env->v7m.nvic = (void *) pic[ARM_PIC_CPU_IRQ];
        crt_qemu_instance->irqs_systemc[i] = pic[ARM_PIC_CPU_IRQ];
    }

    /* RAM shoud repeat to fill physical memory space, SDRAM at address zero.  */
    cpu_register_physical_memory (0, ram_size, IO_MEM_RAM);
    cpu_register_physical_memory (0x85000000, 0x1000, 0x85000000);
}
