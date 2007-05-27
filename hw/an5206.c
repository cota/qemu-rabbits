/* 
 * Arnewsh 5206 ColdFire system emulation.
 *
 * Copyright (c) 2007 CodeSourcery.
 *
 * This code is licenced under the GPL
 */

#include "vl.h"

#define KERNEL_LOAD_ADDR 0x10000
#define AN5206_MBAR_ADDR 0x10000000
#define AN5206_RAMBAR_ADDR 0x20000000

/* Stub functions for hardware that doesn't exist.  */
void pic_info(void)
{
}

void irq_info(void)
{
}

void DMA_run (void)
{
}

/* Board init.  */

static void an5206_init(int ram_size, int vga_ram_size, int boot_device,
                     DisplayState *ds, const char **fd_filename, int snapshot,
                     const char *kernel_filename, const char *kernel_cmdline,
                     const char *initrd_filename, const char *cpu_model)
{
    CPUState *env;
    int kernel_size;
    uint64_t elf_entry;
    target_ulong entry;

    env = cpu_init();
    if (!cpu_model)
        cpu_model = "m5206";
    cpu_m68k_set_model(env, cpu_model);

    /* Initialize CPU registers.  */
    env->vbr = 0;
    /* TODO: allow changing MBAR and RAMBAR.  */
    env->mbar = AN5206_MBAR_ADDR | 1;
    env->rambar0 = AN5206_RAMBAR_ADDR | 1;

    /* DRAM at address zero */
    cpu_register_physical_memory(0, ram_size,
        qemu_ram_alloc(ram_size) | IO_MEM_RAM);

    /* Internal SRAM.  */
    cpu_register_physical_memory(AN5206_RAMBAR_ADDR, 512,
        qemu_ram_alloc(512) | IO_MEM_RAM);

    mcf5206_init(AN5206_MBAR_ADDR, env);

    /* Load kernel.  */
    if (!kernel_filename) {
        fprintf(stderr, "Kernel image must be specified\n");
        exit(1);
    }

    kernel_size = load_elf(kernel_filename, 0, &elf_entry, NULL, NULL);
    entry = elf_entry;
    if (kernel_size < 0) {
        kernel_size = load_uboot(kernel_filename, &entry, NULL);
    }
    if (kernel_size < 0) {
        kernel_size = load_image(kernel_filename,
                                 phys_ram_base + KERNEL_LOAD_ADDR);
        entry = KERNEL_LOAD_ADDR;
    }
    if (kernel_size < 0) {
        fprintf(stderr, "qemu: could not load kernel '%s'\n", kernel_filename);
        exit(1);
    }

    env->pc = entry;
}

QEMUMachine an5206_machine = {
    "an5206",
    "Arnewsh 5206",
    an5206_init,
};