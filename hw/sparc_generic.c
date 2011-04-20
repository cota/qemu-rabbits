#include "hw.h"
#include "qemu_encap.h"

//#define DEBUG_IRQ

#ifdef DEBUG_IRQ
#define DPRINTF(fmt, args...)                           \
    do { printf("CPUIRQ: " fmt , ##args); } while (0)
#else
	#define DPRINTF(fmt, args...)
#endif

#define MAX_PILS 16

void cpu_check_irqs (CPUState *env)
{
    if (env->pil_in && (env->interrupt_index == 0 || (env->interrupt_index & ~15) == TT_EXTINT))
    {
        unsigned int i;

        for (i = 15; i > 0; i--)
        {
            if (env->pil_in & (1 << i))
            {
                int old_interrupt = env->interrupt_index;

                env->interrupt_index = TT_EXTINT | i;
                if (old_interrupt != env->interrupt_index)
                    cpu_interrupt (env, CPU_INTERRUPT_HARD);
                break;
            }
        }
    }
    else if (!env->pil_in && (env->interrupt_index & ~15) == TT_EXTINT)
    {
        env->interrupt_index = 0;
        cpu_reset_interrupt (env, CPU_INTERRUPT_HARD);
    }
}

static void cpu_set_irq (void *opaque, int irq, int level)
{
    CPUState *env = opaque;

    if (level)
    {
        DPRINTF ("Raise CPU IRQ %d\n", irq);
        env->halted = 0;
        env->pil_in |= 1 << irq;
        cpu_check_irqs (env);
    }
    else
    {
        DPRINTF("Lower CPU IRQ %d\n", irq);
        env->pil_in &= ~(1 << irq);
        cpu_check_irqs (env);
    }
}

void sparc_generic_machine_init (int ram_size, const char *cpu_model)
{
    int i;
    qemu_irq *pic;
    CPUState *env;

    if (!cpu_model)
        cpu_model = "TI SuperSparc II";

    crt_qemu_instance->irqs_systemc = malloc (crt_qemu_instance->NOCPUs * sizeof (qemu_irq));

    for (i = 0; i < crt_qemu_instance->NOCPUs; i++)
    {
        env = cpu_init (cpu_model);
        if (!env)
        {
            fprintf (stderr, "qemu: Unable to find Sparc CPU definition\n");
            exit (1);
        }
		cpu_sparc_set_id (env, env->cpu_index);

		env->qemu.fv_percent = 100;
        env->qemu.qemu_instance = crt_qemu_instance;
        pic = qemu_allocate_irqs (cpu_set_irq, env, MAX_PILS);
        crt_qemu_instance->irqs_systemc[i] = pic[1];
    }

    cpu_register_physical_memory (0, ram_size, IO_MEM_RAM);
}
