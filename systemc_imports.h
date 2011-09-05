#ifndef _SYSTEMC_IMPORTS_H_
#define _SYSTEMC_IMPORTS_H_

#ifdef __cplusplus
extern "C"
{
#endif

typedef void            (*systemc_qemu_wakeup_fc_t) (void *sc_obj);
typedef void            (*systemc_qemu_consume_instruction_cycles_fc_t) (
                            void *sc_obj, int ninst);
typedef void            (*systemc_qemu_consume_ns_fc_t) (unsigned long ns);
typedef unsigned long   (*systemc_qemu_read_memory_fc_t) (void *sc_obj,
                            unsigned long address, unsigned long nbytes, int bIO);
typedef void            (*systemc_qemu_write_memory_fc_t) (void *sc_obj, 
                            unsigned long address, unsigned long data,
                            unsigned char nbytes, int bIO);
typedef unsigned long long  (*systemc_qemu_get_time_fc_t) (void);
typedef unsigned long long  (*systemc_qemu_get_no_cycles_fc_t) (void *sc_obj);
typedef unsigned char   *(*systemc_get_mem_addr_fc_t) (void *sc_obj,
                            unsigned long addr);
typedef unsigned long   (*systemc_qemu_get_crt_thread_fc_t) (void *qemu_instance);
typedef void            (*wait_wb_empty_fc_t) (void *sc_obj);

struct systemc_import_t
{
    systemc_qemu_wakeup_fc_t                        systemc_qemu_wakeup;
    systemc_qemu_consume_instruction_cycles_fc_t    systemc_qemu_consume_instruction_cycles;
    systemc_qemu_consume_ns_fc_t                    systemc_qemu_consume_ns;
    systemc_qemu_read_memory_fc_t                   systemc_qemu_read_memory;
    systemc_qemu_write_memory_fc_t                  systemc_qemu_write_memory;
    systemc_qemu_get_time_fc_t                      systemc_qemu_get_time;
    systemc_qemu_get_no_cycles_fc_t                 systemc_qemu_get_no_cycles;
    systemc_get_mem_addr_fc_t                       systemc_get_mem_addr;
    systemc_qemu_get_crt_thread_fc_t                systemc_qemu_get_crt_thread;
    wait_wb_empty_fc_t                              wait_wb_empty;

    //for log
    unsigned long                                   *no_cycles_cpu0;
};

#ifdef __cplusplus
}
#endif

#endif
