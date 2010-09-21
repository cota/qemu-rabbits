#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "config.h"
#include "hw/hw.h"
#include "exec-all.h"
#include "cpu.h"
#include "qemu_encap.h"
#include "../../components/qemu_wrapper/qemu_imported.h"
#include "gdb_srv.h"

//#define DEBUG_GDB_SRV

enum
{
    GDB_SIGNAL_0 = 0,
    GDB_SIGNAL_INT = 2,
    GDB_SIGNAL_TRAP = 5,
    GDB_SIGNAL_UNKNOWN = 143
};

enum
{
    TARGET_SIGINT = 2,
    TARGET_SIGTRAP = 5
};

GDBState                g_gdb_state;
int                     g_nb_gdb_cpus = 0;
CPUState                *g_gdb_envs[100];

static int              one_cpu = 0;
static int              saved_c_cpu_index = 0;
static int              write_watchpoint = 0;
static unsigned long    watchpoint_new_value = 0;
static unsigned long    watchpoint_address = 0;

extern unsigned long get_phys_addr_gdb (unsigned long addr);

/* The GDB remote protocol transfers values in target byte order.  This means
we can use the raw memory access routines to access the value buffer.
Conveniently, these also handle the case where the buffer is mis-aligned.
*/
#define GET_REG8(val) do { \
    stb_p(mem_buf, val); \
    return 1; \
    } while(0)
#define GET_REG16(val) do { \
    stw_p(mem_buf, val); \
    return 2; \
    } while(0)
#define GET_REG32(val) do { \
    stl_p(mem_buf, val); \
    return 4; \
    } while(0)
#define GET_REG64(val) do { \
    stq_p(mem_buf, val); \
    return 8; \
    } while(0)


#if TARGET_LONG_BITS == 64
#define GET_REGL(val) GET_REG64(val)
#define ldtul_p(addr) ldq_p(addr)
#else
#define GET_REGL(val) GET_REG32(val)
#define ldtul_p(addr) ldl_p(addr)
#endif

#if defined (TARGET_SPARC)

    #if defined(TARGET_SPARC64) && !defined(TARGET_ABI32)
    #define NUM_CORE_REGS 86
    #else
    #define NUM_CORE_REGS 72
    #endif

    #ifdef TARGET_ABI32
    #define GET_REGA(val) GET_REG32(val)
    #else
    #define GET_REGA(val) GET_REGL(val)
    #endif

static int cpu_gdb_read_register (CPUState *env, uint8_t *mem_buf, int n)
{
    if (n < 8) 
    {
        /* g0..g7 */
        GET_REGA(env->gregs[n]);
    }
    if (n < 32)
    {
        /* register window */
        GET_REGA(env->regwptr[n - 8]);
    }
    #if defined(TARGET_ABI32) || !defined(TARGET_SPARC64)
    if (n < 64)
    {
        /* fprs */
        GET_REG32(*((uint32_t *)&env->fpr[n - 32]));
    }
    /* Y, PSR, WIM, TBR, PC, NPC, FPSR, CPSR */
    switch (n)
    {
    case 64: GET_REGA(env->y);
    case 65: GET_REGA(GET_PSR(env));
    case 66: GET_REGA(env->wim);
    case 67: GET_REGA(env->tbr);
    case 68:  GET_REGA(env->gdb_pc);
    case 69: GET_REGA(env->gdb_npc);
    case 70: GET_REGA(env->fsr);
    case 71: GET_REGA(0); /* csr */
    default: GET_REGA(0);
    }
    #else
    if (n < 64)
    {
        /* f0-f31 */
        GET_REG32(*((uint32_t *)&env->fpr[n - 32]));
    }
    if (n < 80)
    {
        /* f32-f62 (double width, even numbers only) */
        uint64_t val;

        val = (uint64_t)*((uint32_t *)&env->fpr[(n - 64) * 2 + 32]) << 32;
        val |= *((uint32_t *)&env->fpr[(n - 64) * 2 + 33]);
        GET_REG64(val);
    }
    switch (n)
    {
    case 80: GET_REGL(env->gdb_pc);
    case 81: GET_REGL(env->gdb_npc);
    case 82: GET_REGL(((uint64_t)GET_CCR(env) << 32) |
                           ((env->asi & 0xff) << 24) |
                           ((env->pstate & 0xfff) << 8) |
                           GET_CWP64(env));
    case 83: GET_REGL(env->fsr);
    case 84: GET_REGL(env->fprs);
    case 85: GET_REGL(env->y);
    }
    #endif
    return 0;
}

static int cpu_gdb_write_register(CPUState *env, uint8_t *mem_buf, int n)
{
    #if defined(TARGET_ABI32)
    abi_ulong tmp;

    tmp = ldl_p (mem_buf);
    #else
    target_ulong tmp;

    tmp = ldtul_p(mem_buf);
    #endif

    if (n < 8)
    {
        /* g0..g7 */
        env->gregs[n] = tmp;
    }
    else
    if (n < 32)
    {
        /* register window */
        env->regwptr[n - 8] = tmp;
    }
    #if defined(TARGET_ABI32) || !defined(TARGET_SPARC64)
    else
    if (n < 64)
    {
        /* fprs */
        *((uint32_t *)&env->fpr[n - 32]) = tmp;
    }
    else
    {
        /* Y, PSR, WIM, TBR, PC, NPC, FPSR, CPSR */
        switch (n)
        {
        case 64: env->y = tmp; break;
        case 65: PUT_PSR(env, tmp); break;
        case 66: env->wim = tmp; break;
        case 67: env->tbr = tmp; break;
        case 68: env->pc = tmp; env->gdb_pc = tmp; break;
        case 69: env->npc = tmp; env->gdb_npc = tmp; break;
        case 70: env->fsr = tmp; break;
        default: return 0;
        }
    }
    return 4;
    #else
    else
    if (n < 64)
    {
        /* f0-f31 */
        env->fpr[n] = ldfl_p(mem_buf);
        return 4;
    }
    else
    if (n < 80)
    {
        /* f32-f62 (double width, even numbers only) */
        *((uint32_t *)&env->fpr[(n - 64) * 2 + 32]) = tmp >> 32;
        *((uint32_t *)&env->fpr[(n - 64) * 2 + 33]) = tmp;
    }
    else
    {
        switch (n)
        {
        case 80: env->pc = tmp; env->gdb_pc = tmp; break;
        case 81: env->npc = tmp; env->gdb_npc = tmp; break;
        case 82:
        PUT_CCR(env, tmp >> 32);
        env->asi = (tmp >> 24) & 0xff;
        env->pstate = (tmp >> 8) & 0xfff;
        PUT_CWP64(env, tmp & 0xff);
        break;
        case 83: env->fsr = tmp; break;
        case 84: env->fprs = tmp; break;
        case 85: env->y = tmp; break;
        default: return 0;
        }
    }
    return 8;
    #endif
}

#elif defined (TARGET_ARM)

    /* Old gdb always expect FPA registers.  Newer (xml-aware) gdb only expect
    whatever the target description contains.  Due to a historical mishap
    the FPA registers appear in between core integer regs and the CPSR.
    We hack round this by giving the FPA regs zero size when talking to a
    newer gdb.  */
    #define NUM_CORE_REGS 26

static int cpu_gdb_read_register (CPUState *env, uint8_t *mem_buf, int n)
{
    if (n < 16)
    {
        /* Core integer register.  */
        if (n != 15)
            GET_REG32 (env->regs[n]);
        else
            GET_REG32 (env->gdb_pc);
    }

    if (n < 24)
    {
        /* FPA registers.  */
        memset (mem_buf, 0, 12);
        return 12;
    }

    switch (n)
    {
    case 24:
        /* FPA status register.  */
        GET_REG32 (0);
    case 25:
        /* CPSR */
        GET_REG32 (cpsr_read(env));
    }

    /* Unknown register.  */
    return 0;
}

static int cpu_gdb_write_register (CPUState *env, uint8_t *mem_buf, int n)
{
    uint32_t tmp;

    tmp = ldl_p (mem_buf);

    /* Mask out low bit of PC to workaround gdb bugs.  This will probably
       cause problems if we ever implement the Jazelle DBX extensions.  */
    if (n == 15)
        tmp &= ~1;

    if (n < 16)
    {
        /* Core integer register.  */
        env->regs[n] = tmp;
        return 4;
    }

    if (n < 24)
    { /* 16-23 */
        /* FPA registers (ignored).  */
        return 12;
    }

    switch (n)
    {
    case 24:
        /* FPA status register (ignored).  */
        return 4;
    case 25:
        /* CPSR */
        cpsr_write (env, tmp, 0xffffffff);
        return 4;
    }

    /* Unknown register.  */
    return 0;
}
#endif

static int num_g_regs = NUM_CORE_REGS;


static int gdb_read_register (CPUState *env, uint8_t *mem_buf, int reg)
{
    if (reg < NUM_CORE_REGS)
        return cpu_gdb_read_register (env, mem_buf, reg);

    return 0;
}

static int gdb_write_register (CPUState *env, uint8_t *mem_buf, int reg)
{
    if (reg < NUM_CORE_REGS)
        return cpu_gdb_write_register (env, mem_buf, reg);

    return 0;
}


static inline int fromhex(int v)
{
    if (v >= '0' && v <= '9')
        return v - '0';
    else if (v >= 'A' && v <= 'F')
        return v - 'A' + 10;
    else if (v >= 'a' && v <= 'f')
        return v - 'a' + 10;
    else
        return 0;
}

static inline int tohex(int v)
{
    if (v < 10)
        return v + '0';
    else
        return v - 10 + 'a';
}


static void memtohex (char *buf, const uint8_t *mem, int len)
{
    int                 i, c;
    char                *q;

    q = buf;
    for (i = 0; i < len; i++)
    {
        c = mem[i];
        *q++ = tohex (c >> 4);
        *q++ = tohex (c & 0xf);
    }
    *q = '\0';
}

static void hextomem (uint8_t *mem, const char *buf, int len)
{
    int                 i;

    for (i = 0; i < len; i++)
    {
        mem[i] = (fromhex (buf[0]) << 4) | fromhex (buf[1]);
        buf += 2;
    }
}

static int get_char (GDBState *s)
{
    uint8_t             ch;
    int                 ret;

    for(;;)
    {
        ret = recv (s->fd, &ch, 1, 0);
        if (ret < 0)
        {
            if (errno == ECONNRESET)
                s->fd = -1;
            if (errno != EINTR && errno != EAGAIN)
                return -1;
        }
        else
        {
            if (ret == 0)
            {
                close  (s->fd);
                s->fd = -1;
                return -1;
            }

            break;
        }
    }

    return ch;
}

static void put_buffer (GDBState *s, const uint8_t *buf, int len)
{
    int         ret;

    while (len > 0)
    {
        ret = send (s->fd, buf, len, 0);
        if (ret < 0)
        {
            if (errno != EINTR && errno != EAGAIN)
            {
                s->running_state = STATE_DETACH;
                return;
            }
        }
        else
        {
            buf += ret;
            len -= ret;
        }
    }
}

static int put_packet_binary (GDBState *s, const char *buf, int len)
{
    int             csum, i;
    uint8_t         *p;

    for (;;)
    {
        p = s->last_packet;
        *(p++) = '$';
        memcpy (p, buf, len);
        p += len;
        csum = 0;
        for(i = 0; i < len; i++)
        {
            csum += buf[i];
        }
        *(p++) = '#';
        *(p++) = tohex ((csum >> 4) & 0xf);
        *(p++) = tohex((csum) & 0xf);

        s->last_packet_len = p - s->last_packet;
        put_buffer (s, (uint8_t *) s->last_packet, s->last_packet_len);

        i = get_char (s);
        if (i < 0)
            return -1;
        if (i == '+')
            break;
    }

    return 0;
}


static int put_packet (GDBState *s, const char *buf)
{
    #ifdef DEBUG_GDB_SRV
    printf ("response:%s\n", buf);
    #endif

    return put_packet_binary (s, buf, strlen(buf));
}


static void gdb_srv_accept (GDBState *s)
{
    struct sockaddr_in          sockaddr;
    socklen_t                   len;
    int                         fd;

    len = sizeof (sockaddr);
    fd = accept (s->srv_sock_fd, (struct sockaddr *)&sockaddr, &len);
    if (fd < 0 && errno != EINTR)
    {
        perror ("accept");
        return;
    }
    printf ("GDB connected.\n");

    /* set short latency */
//    int                       val = 1;
//    setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (char *) &val, sizeof(val));

    s->fd = fd;
}

static int gdb_srv_open (int port)
{
    struct sockaddr_in      sockaddr;
    int                     fd, ret;

    fd = socket (PF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror ("socket");
        return -1;
    }

    /* allow fast reuse */
    int                   val = 1;
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (char *) &val, sizeof (val));

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons (port);
    sockaddr.sin_addr.s_addr = 0;
    ret = bind (fd, (struct sockaddr *) &sockaddr, sizeof (sockaddr));
    if (ret < 0)
    {
        perror("bind");
        return -1;
    }

    ret = listen (fd, 0);
    if (ret < 0)
    {
        perror("listen");
        return -1;
    }

    return fd;
}

static int gdb_breakpoint_insert (unsigned long addr, unsigned long len, int type)
{
    switch (type)
    {
    case GDB_BREAKPOINT_SW:
    case GDB_BREAKPOINT_HW:
    {
        int             nb;
        unsigned long   *paddr;

        nb = g_gdb_state.breakpoints.nb;
        paddr = g_gdb_state.breakpoints.addr;
        /*
        int             i;
        for (i = 0; i < nb; i++)
            if (addr == paddr[i])
                break;
        if (i >= nb)
        {*/
            paddr[nb] = addr;
            g_gdb_state.breakpoints.nb++;
        //}
        return 0;
    }

    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_ACCESS:
    {
        int                     nb;
        struct watch_el_t       *pwatch;

        nb = g_gdb_state.watchpoints.nb;
        pwatch = g_gdb_state.watchpoints.watch;
        /*
         int                    i;
         for (i = 0; i < nb; i++)
            if (addr == pwatch[i].begin_address)
                break;
        if (i >= nb)
        {*/
            pwatch[nb].begin_address = addr;
            pwatch[nb].end_address = addr + len;
            pwatch[nb].type = type;
            g_gdb_state.watchpoints.nb++;
        //}
        return 0;
    }

    default:
        return -ENOSYS;
    }
}

static int gdb_breakpoint_remove (unsigned long addr, unsigned long len, int type)
{
    switch (type)
    {
    case GDB_BREAKPOINT_SW:
    case GDB_BREAKPOINT_HW:
    {
        int                 i, nb;
        unsigned long       *paddr;

        nb = g_gdb_state.breakpoints.nb;
        paddr = g_gdb_state.breakpoints.addr;
        for (i = 0; i < nb; i++)
            if (addr == paddr[i])
                break;
        if (i < nb)
        {
            for ( ;i < nb - 1; i++)
                paddr[i] = paddr[i + 1];
            g_gdb_state.breakpoints.nb--;
        }

        return 0;
    }

    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_ACCESS:
    {
        int                     i, nb;
        struct watch_el_t       *pwatch;

        nb = g_gdb_state.watchpoints.nb;
        pwatch = g_gdb_state.watchpoints.watch;
        for (i = 0; i < nb; i++)
            if (addr == pwatch[i].begin_address &&
                (addr + len) == pwatch[i].end_address &&
                type == pwatch[i].type)
                break;

        if (i < nb)
        {
            for ( ;i < nb - 1; i++)
                pwatch[i] = pwatch[i + 1];
            g_gdb_state.watchpoints.nb--;
        }

        return 0;
    }
    default:
        return -ENOSYS;
    }
}

static void gdb_breakpoint_remove_all ()
{
    g_gdb_state.breakpoints.nb = 0;
    g_gdb_state.watchpoints.nb = 0;
}

static void gdb_continue (GDBState *s, int running_state)
{
    s->running_state = running_state;
}

static RSState gdb_handle_packet (GDBState *s, const char *line_buf)
{
    const char              *p;
    int                     ch, type, thread, reg_size, len, res;
    char                    buf[MAX_PACKET_LENGTH];
    uint8_t                 mem_buf[MAX_PACKET_LENGTH];
    uint8_t                 *registers;
    unsigned long           addr;
    void                    *hw_addr;

    #ifdef DEBUG_GDB_SRV
    printf ("command='%s'\n", line_buf);
    #endif

    p = line_buf;
    ch = *p++;
    switch(ch)
    {
    case '?': //reason the target halted
        snprintf (buf, sizeof (buf), "T%02xthread:%x;",
            GDB_SIGNAL_TRAP, cpu_single_env->qemu.gdb_cpu_index + 1);
        put_packet (s, buf);
        /* Remove all the breakpoints when this query is issued,
         * because gdb is doing and initial connect and the state
         * should be cleaned up.
         */
        gdb_breakpoint_remove_all ();
        break;

    case 'c': //caddr - continue
        if (*p != '\0')
        {
            addr = strtoull (p, (char **) &p, 16);
            /*§§
            #if defined (TARGET_SPARC)
            s->c_cpu->pc = addr;
            s->c_cpu->npc = addr + 4;
            #elif defined (TARGET_ARM)
            s->c_cpu->regs[15] = addr;
            #endif
            */
        }
        gdb_continue (s, STATE_CONTINUE);
        break;

    case 'C': // Csig;addr - continue with signal
        gdb_continue (s, STATE_CONTINUE);
        break;

    case 'D': //D - detach
        gdb_breakpoint_remove_all ();
        gdb_continue (s, STATE_DETACH);
        put_packet (s, "OK");
        break;

    case 'g': //read registers
        len = 0;
        for (addr = 0; addr < num_g_regs; addr++)
        {
            reg_size = gdb_read_register (g_gdb_envs[s->g_cpu_index],
                mem_buf + len, addr);
            len += reg_size;
        }
        memtohex (buf, mem_buf, len);
        put_packet (s, buf);
        break;

    case 'G': //GXX... - write regs
        registers = mem_buf;
        len = strlen(p) / 2;
        hextomem ((uint8_t *) registers, p, len);

        for (addr = 0; addr < num_g_regs && len > 0; addr++)
        {
            reg_size = gdb_write_register (g_gdb_envs[s->g_cpu_index],
                registers, addr);
            len -= reg_size;
            registers += reg_size;
        }
        put_packet(s, "OK");
        break;

    case 'H': //set thread
        type = *p++;
        thread = strtoull (p, (char **) &p, 16);
        if (thread == -1 || thread == 0)
        {
            if (type == 'c')
                s->c_cpu_index = -1;
            put_packet (s, "OK");
            break;
        }

        switch (type)
        {
        case 'c':
            s->c_cpu_index = thread - 1;
            put_packet (s, "OK");
            break;

        case 'g':
            s->g_cpu_index = thread - 1;
            put_packet (s, "OK");
            break;

        default:
             put_packet (s, "E22");
             break;
        }
        break;

    case 'k': //k - kill request
        fprintf (stderr, "\nTerminated via GDB!\n");
        exit (0);

    case 'm': //read memory
        addr = strtoull (p, (char **) &p, 16);

        addr = get_phys_addr_gdb (addr);

        if (*p == ',')
            p++;
        len = strtoull (p, NULL, 16);

        if (write_watchpoint && addr == watchpoint_address)
            hw_addr = &watchpoint_new_value;
        else
            hw_addr = crt_qemu_instance->systemc.systemc_get_mem_addr (
                cpu_single_env->qemu.sc_obj, addr);
        if (hw_addr == NULL)
        {
            put_packet (s, "E14");
            break;
        }

        memcpy (mem_buf, hw_addr, len);

        memtohex (buf, mem_buf, len);
        put_packet (s, buf);

        break;

    case 'M': //write memory
        addr = strtoull (p, (char **) &p, 16);
        if (*p == ',')
            p++;
        len = strtoull (p, (char **) &p, 16);
        if (*p == ':')
            p++;
        hextomem (mem_buf, p, len);

        hw_addr = crt_qemu_instance->systemc.systemc_get_mem_addr (
            cpu_single_env->qemu.sc_obj, addr);
        if (hw_addr == NULL)
        {
            put_packet (s, "E14");
            break;
        }
        memcpy (hw_addr, mem_buf, len);

        put_packet (s, "OK");
        break;

    case 'p': //pn - read reg
        /* Older gdb are really dumb, and don't use 'g' if 'p' is avaialable.
           This works, but can be very slow.  Anything new enough to
           understand XML also knows how to use this properly.  */
        addr = strtoull (p, (char **) &p, 16);

        reg_size = gdb_read_register (cpu_single_env, mem_buf, addr);
        if (reg_size)
        {
            memtohex (buf, mem_buf, reg_size);
            put_packet (s, buf);
        } else
        {
            put_packet(s, "E14");
        }
        break;

    case 'P': //Pn...=r... - write reg
        addr = strtoull (p, (char **) &p, 16);
        if (*p == '=')
            p++;
        reg_size = strlen(p) / 2;
        hextomem (mem_buf, p, reg_size);
        gdb_write_register (cpu_single_env, mem_buf, addr);
        put_packet(s, "OK");
        break;

    case 'q': //general query
    case 'Q':
        if (strcmp(p, "C") == 0)
        {
            sprintf (buf, "QC%x", cpu_single_env->qemu.gdb_cpu_index + 1);
            put_packet (s, buf);
            break;
        }
        else
        if (strncmp(p, "Offsets", 7) == 0)
        {
            snprintf (buf, sizeof(buf), "Text=%x;Data=%x;Bss=%x",
                0x00000000, 0x00000000, 0x00000000);
            put_packet (s, buf);
            break;
        }
        else
        if (strncmp(p, "Supported", 9) == 0)
        {
            snprintf (buf, sizeof (buf), "PacketSize=%x", MAX_PACKET_LENGTH);
            put_packet (s, buf);
            break;
        }
        else
        if (strcmp (p,"fThreadInfo") == 0)
        {
            s->query_cpu_index = 0;
            goto report_cpuinfo;
        }
        else
        if (strcmp (p,"sThreadInfo") == 0)
        {
            report_cpuinfo:
            if (s->query_cpu_index < g_nb_gdb_cpus)
            {
                snprintf (buf, sizeof (buf), "m%x", s->query_cpu_index + 1);
                put_packet (s, buf);
                s->query_cpu_index++;
            }
            else
                put_packet (s, "l");

            break;
        }
        else
        if (strncmp(p,"ThreadExtraInfo,", 16) == 0)
        {
            thread = strtoull (p + 16, (char **) &p, 16);
            if (thread > g_nb_gdb_cpus)
                put_packet(s, "E14");
            else
            {
                len = snprintf ((char *) mem_buf, sizeof (mem_buf),
                    "CPU %d [%s]", thread,
                    g_gdb_envs[thread - 1]->halted ? "halted " : "running");
                memtohex (buf, mem_buf, len);
                put_packet (s, buf);
            }
            
            break;
        }
        goto unknown_command;

    case 's': //saddr - step
        
        if (*p != '\0') 
        {
            addr = strtoull (p, (char **) &p, 16);
            /*§§
            #if defined (TARGET_SPARC)
            s->c_cpu->pc = addr;
            s->c_cpu->npc = addr + 4;
            #elif defined (TARGET_ARM)
            s->c_cpu->regs[15] = addr;
            #endif
            */
        }        
        gdb_continue (s, STATE_STEP);
        break;

    case 'T': //TXX - thread alive
        thread = strtoull (p, (char **) &p, 16);
        if (thread > 0 && thread <= g_nb_gdb_cpus)
             put_packet(s, "OK");
        else
            put_packet(s, "E22");
        break;

    case 'v':
        if (!strncmp (p, "Cont", 4))
        {
            p += 4;
            if (!strcmp (p, "?"))
                put_packet (s, "vCont;c;C;s;S");
            else
            if (*p == ';')
            {
                p++;
                if (*p == 'c')
                {
                    p++;
                    if (*p == ':')
                    {
                        one_cpu = 1;
                        saved_c_cpu_index = s->c_cpu_index;
                        thread = strtoull (p + 1, (char **) &p, 16) - 1;
                        s->c_cpu_index = thread;
                    }

                    gdb_continue (s, STATE_CONTINUE);
                }
                else
                if (*p == 's')
                {
                    p++;
                    if (*p == ':')
                    {
                        if (write_watchpoint == 1)
                        {
                            put_packet (s, "S05");
                            break;
                        }
                        else
                        {
                            one_cpu = 1;
                            saved_c_cpu_index = s->c_cpu_index;
                            thread = strtoull (p + 1, (char **) &p, 16) - 1;
                            s->c_cpu_index = thread;
                        }
                    }

                    gdb_continue (s, STATE_STEP);
                }
                else
                goto unknown_command;
            }
        }
        break;

    case 'Z': //zt,addr,length - add break or watchpoint 
    case 'z': //zt,addr,length - remove break or watchpoint 
        type = strtoul (p, (char **) &p, 16);
        if (*p == ',')
            p++;
        addr = strtoull (p, (char **) &p, 16);
        if (*p == ',')
            p++;
        len = strtoull (p, (char **) &p, 16);
        res = 0;
        //if (addr > 0x10020)
        {
            if (ch == 'Z')
                res = gdb_breakpoint_insert (addr, len, type);
            else
                res = gdb_breakpoint_remove (addr, len, type);
        }

        if (res >= 0)
             put_packet(s, "OK");
        else
            if (res == -ENOSYS)
                put_packet(s, "");
            else
                put_packet(s, "E22");
        break;

    default:
    unknown_command:
        /* put empty packet */
        buf[0] = '\0';
        put_packet (s, buf);
        break;
    }

    return RS_IDLE;
}

static void gdb_read_byte (GDBState *s, int ch)
{
    int                 i, csum;
    uint8_t             reply;

    switch (s->state)
    {
    case RS_IDLE:
        if (ch == '$')
        {
            s->line_buf_index = 0;
            s->state = RS_GETLINE;
        }
        break;
    case RS_GETLINE:
        if (ch == '#')
        {
            s->state = RS_CHKSUM1;
        }
        else
        {
            if (s->line_buf_index >= sizeof(s->line_buf) - 1)
            {
                s->state = RS_IDLE;
            }
            else
            {
                s->line_buf[s->line_buf_index++] = ch;
            }
        }
        break;
    case RS_CHKSUM1:
        s->line_buf[s->line_buf_index] = '\0';
        s->line_csum = fromhex(ch) << 4;
        s->state = RS_CHKSUM2;
        break;
    case RS_CHKSUM2:
        s->line_csum |= fromhex(ch);
        csum = 0;
        for(i = 0; i < s->line_buf_index; i++)
        {
            csum += s->line_buf[i];
        }
        if (s->line_csum != (csum & 0xff))
        {
            reply = '-';
            put_buffer (s, &reply, 1);
            s->state = RS_IDLE;
        }
        else
        {
            reply = '+';
            put_buffer (s, &reply, 1);
            s->state = gdb_handle_packet (s, s->line_buf);
        }
        break;
    } //switch
}

void gdb_loop (int idx_watch, int bwrite, unsigned long new_val)
{
    char              buf[256], buf1[256];
    int               i, nb;
    GDBState          *s = &g_gdb_state;
    unsigned char     save_b_use_backdoor = b_use_backdoor;

    b_use_backdoor = 1;
    write_watchpoint = 0;

    if (s->running_state != STATE_INIT)
    {
        sprintf (buf, "T%02x", TARGET_SIGTRAP);

        #if defined TARGET_ARM
        {
        char            reg[4][20];
        unsigned long   ul;
        memtohex (reg[0], (uint8_t*) &cpu_single_env->gdb_pc, 4); // pc
        memtohex (reg[1], (uint8_t*) &cpu_single_env->regs[13], 4); //sp
        ul = cpsr_read (cpu_single_env);
        memtohex (reg[2], (uint8_t*) &ul, 4); //cpsr
        memtohex (reg[3], (uint8_t*) &cpu_single_env->regs[14], 4); //lr

        sprintf (buf1, "0f:%s;0d:%s;19:%s;0e:%s;",
            reg[0], reg[1], reg[2], reg[3]);
        strcat (buf, buf1);
        }
        #elif defined TARGET_SPARC
        char            reg[4][20];
        uint8_t         b[64];
        int             reg_size;
        reg_size = cpu_gdb_read_register (cpu_single_env, b, 0x44);
        memtohex (reg[0], (uint8_t*) b, reg_size); // pc
        reg_size = cpu_gdb_read_register (cpu_single_env, b, 0x0e);
        memtohex (reg[1], (uint8_t*) b, reg_size);
        reg_size = cpu_gdb_read_register (cpu_single_env, b, 0x0f);
        memtohex (reg[2], (uint8_t*) b, reg_size);
        reg_size = cpu_gdb_read_register (cpu_single_env, b, 0x45);
        memtohex (reg[3], (uint8_t*) b, reg_size);

        sprintf (buf1, "44:%s;0e:%s;0f:%s;45:%s;",
            reg[0], reg[1], reg[2], reg[3]);
        strcat (buf, buf1);
        #endif

        if (idx_watch != -1)
        {
            struct watch_el_t   *pwatch;
            static const char   *watch_names[] = {"watch", "rwatch", "awatch"};

            pwatch = &s->watchpoints.watch[idx_watch];
            sprintf (buf1, "%s:%lx;",
                watch_names[pwatch->type - GDB_WATCHPOINT_WRITE],
                pwatch->begin_address);
            strcat (buf, buf1);

            if (bwrite)
            {
                write_watchpoint = 1;
                watchpoint_new_value = new_val;
                watchpoint_address = pwatch->begin_address;
            }
        }

        sprintf (buf1, "thread:%x;", cpu_single_env->qemu.gdb_cpu_index + 1);
        strcat (buf, buf1);

        put_packet (s, buf);
    }

    if (s->running_state == STATE_DETACH)
    {
        b_use_backdoor = save_b_use_backdoor;
        return;
    }

    if (one_cpu)
    {
        one_cpu = 0;
        s->c_cpu_index = saved_c_cpu_index;
    }


    s->g_cpu_index = cpu_single_env->qemu.gdb_cpu_index;
    s->state = RS_IDLE;
    s->running_state = 0;
    while (s->running_state == STATE_GDB_CONTROL)
    {
        nb = read (s->fd, buf, 256);
        if (nb > 0)
        {
            for (i = 0; i < nb; i++)
                gdb_read_byte (s, buf[i]);
        }
        else
        if (nb == 0 || errno != EAGAIN)
        {
            printf ("GDB disconnected!\n");
            s->running_state = STATE_DETACH;
            b_use_backdoor = save_b_use_backdoor;
            return;
        }
    }

    b_use_backdoor = save_b_use_backdoor;
}

void close_gdb_sockets ()
{
    if (g_gdb_state.fd)
        close (g_gdb_state.fd);
    g_gdb_state.fd = 0;
    
    if (g_gdb_state.srv_sock_fd)
        close (g_gdb_state.srv_sock_fd);
    g_gdb_state.srv_sock_fd = 0;
}

int gdb_srv_start_and_wait (int port)
{
    memset (&g_gdb_state, 0, sizeof (GDBState));
    g_gdb_state.running_state = STATE_DETACH;

    g_gdb_state.srv_sock_fd = gdb_srv_open (port);
    if (g_gdb_state.srv_sock_fd < 0)
    {
        printf ("Error: Cannot open port %d in %s\n", port, __FUNCTION__);
        return -1;
    }

    printf ("Waiting for a GDB connection on port %d (arch=%s) ...\n", port, TARGET_ARCH);
    gdb_srv_accept (&g_gdb_state);

    g_gdb_state.running_state = STATE_INIT;
    g_gdb_state.c_cpu_index = -1;
    atexit (close_gdb_sockets);

    return 0;
}
