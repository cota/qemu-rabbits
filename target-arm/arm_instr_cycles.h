#ifndef _ARM_INSTR_CYCLES_H_
#define	_ARM_INSTR_CYCLES_H_

#if 0
#define NORMAL_INSTRUCTION_CYCLE_COST               1
#define JUMP_CYCLE_COST                             2
#define LOAD_CYCLE_COST                             2
#define STORE_CYCLE_COST                            1
#define SIGNED_MUL_CYCLE_COST                       1
#define REGISTER_SHIFT_CYCLE_COST                   1
#define MUL8_CYCLE_COST                             1
#define MUL16_CYCLE_COST                            2
#define MUL24_CYCLE_COST                            3
#define MUL32_CYCLE_COST                            4
#define MUL64_CYCLE_COST                            4
#define MLS_CYCLE_COST                              1
#define MLA_CYCLE_COST                              1
#define MLAA_CYCLE_COST                             2	/* ? */
#define SWP_CYCLE_COST                              3
#define MLA_CYCLE_COST                              1
#define MULTI_TRANSFER_PER_REGISTER_CYCLE_COST      1
#define MULTI_TRANSFER_LOAD_OP_CYCLE_COST           1
#define MULTI_TRANSFER_STORE_OP_CYCLE_COST          0
#define COCPU_CYCLE_COST                            1	/* ? */
#define COCPU_MRC_CYCLE_COST                        2
#endif

#if 1
#define NORMAL_INSTRUCTION_CYCLE_COST               1
#define JUMP_CYCLE_COST                             2
#define LOAD_CYCLE_COST                             0
#define STORE_CYCLE_COST                            0
#define SIGNED_MUL_CYCLE_COST                       0
#define REGISTER_SHIFT_CYCLE_COST                   0
#define MUL8_CYCLE_COST                             0
#define MUL16_CYCLE_COST                            0
#define MUL24_CYCLE_COST                            0
#define MUL32_CYCLE_COST                            0
#define MUL64_CYCLE_COST                            0
#define MLS_CYCLE_COST                              0
#define MLA_CYCLE_COST                              0
#define MLAA_CYCLE_COST                             0	/* ? */
#define SWP_CYCLE_COST                              0
#define MLA_CYCLE_COST                              0
#define MULTI_TRANSFER_PER_REGISTER_CYCLE_COST      1
#define MULTI_TRANSFER_LOAD_OP_CYCLE_COST           1
#define MULTI_TRANSFER_STORE_OP_CYCLE_COST          1
#define COCPU_CYCLE_COST                            0	/* ? */
#define COCPU_MRC_CYCLE_COST                        0
#endif

#if 0
#define NORMAL_INSTRUCTION_CYCLE_COST               1
#define JUMP_CYCLE_COST                             0
#define LOAD_CYCLE_COST                             0
#define STORE_CYCLE_COST                            0
#define SIGNED_MUL_CYCLE_COST                       0
#define REGISTER_SHIFT_CYCLE_COST                   0
#define MUL8_CYCLE_COST                             0
#define MUL16_CYCLE_COST                            0
#define MUL24_CYCLE_COST                            0
#define MUL32_CYCLE_COST                            0
#define MUL64_CYCLE_COST                            0
#define MLS_CYCLE_COST                              0
#define MLA_CYCLE_COST                              0
#define MLAA_CYCLE_COST                             0	/* ? */
#define SWP_CYCLE_COST                              0
#define MLA_CYCLE_COST                              0
#define MULTI_TRANSFER_PER_REGISTER_CYCLE_COST      0
#define MULTI_TRANSFER_LOAD_OP_CYCLE_COST           0
#define MULTI_TRANSFER_STORE_OP_CYCLE_COST          0
#define COCPU_CYCLE_COST                            0	/* ? */
#define COCPU_MRC_CYCLE_COST                        0
#endif

#endif /* _ARM_INSTR_CYCLES_H_ */
