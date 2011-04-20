#ifndef _GDB_SRV_H_
#define _GDB_SRV_H_

#define MAX_PACKET_LENGTH (4096 * 4)

typedef enum
{
    RS_IDLE,
    RS_GETLINE,
    RS_CHKSUM1,
    RS_CHKSUM2
} RSState;

enum
{
    GDB_BREAKPOINT_SW,
    GDB_BREAKPOINT_HW,
    GDB_WATCHPOINT_WRITE,
    GDB_WATCHPOINT_READ,
    GDB_WATCHPOINT_ACCESS
};

enum
{
    STATE_GDB_CONTROL,
    STATE_STEP,
    STATE_CONTINUE,
    STATE_DETACH,
    STATE_INIT,
};

struct GDBState
{
    int                 fd;
    int                 srv_sock_fd;
    int                 c_cpu_index;
    int                 g_cpu_index;
    int                 query_cpu_index;
    RSState             state;  /* parsing state */
    int                 running_state;
    char                line_buf[MAX_PACKET_LENGTH];
    int                 line_buf_index;
    int                 line_csum;
    uint8_t             last_packet[MAX_PACKET_LENGTH + 4];
    int                 last_packet_len;

    struct breakpoint_t
    {
        unsigned long   addr[100];
        int             nb;
    } breakpoints;
    struct watchpoint_t
    {
        struct watch_el_t
        {
            unsigned long   begin_address;
            unsigned long   end_address;
            int             type;
        } watch [100];
        int             nb;
    } watchpoints;
};

int gdb_srv_start_and_wait (qemu_instance *pinstance, int port);
void gdb_loop (int idx_watch, int bwrite, unsigned long new_val);

#endif
