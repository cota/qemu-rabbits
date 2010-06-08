void OPPROTO
op_start_tb (void)
{
  extern void tb_start (unsigned long tb_addr);
  tb_start (PARAM1);
}

#ifdef LOG_INFO_FOR_DEBUG
void OPPROTO
op_log_pc (void)
{
  extern void log_pc (unsigned long addr);
  log_pc (PARAM1);
}
#endif

#ifdef GDB_ENABLED
void OPPROTO
op_gdb_verify (void)
{
    #if defined(TARGET_SPARC)
    extern void gdb_verify (unsigned long addr, unsigned long npc);
    gdb_verify (PARAM1, PARAM2);
    #else
    extern void gdb_verify (unsigned long addr);
    gdb_verify (PARAM1);
    #endif
}
#endif

#ifdef IMPLEMENT_CACHES
void OPPROTO
op_verify_instruction_cache (void)
{
    extern void instruction_cache_access (unsigned long addr);
    instruction_cache_access (PARAM1);
}

void OPPROTO
op_verify_instruction_cache_n (void)
{
  extern void instruction_cache_access_n (unsigned long addr, int n);
  instruction_cache_access_n (PARAM1, PARAM2);
}
#endif

void OPPROTO
op_inc_crt_nr_cycles_instr(void)
{
  extern unsigned long s_crt_nr_cycles_instr;
  s_crt_nr_cycles_instr += PARAM1;
}

#ifdef COUNT_INSTR_FOR_STATISTICS
void OPPROTO
op_inc_crt_nr_instr (void)
{
  extern unsigned long long g_crt_nr_instr;
  g_crt_nr_instr++;
}
#endif

#ifdef WRITE_PC_FOR_DEBUG
void OPPROTO
op_write_pc (void)
{
  extern unsigned long last_pc_executed;
  last_pc_executed = PARAM1;
}
#endif
