/*
 * QEMU RISC-V SMPU (S-mode Memory Protection Unit)
 *
 * Author: Bicheng Yang, SuperYbc@outlook.com
 *         Dong Du,      Ddnirvana1@gmail.com
 *
 * This provides a RISC-V S-mode Memory Protection Unit interface
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef RISCV_SMPU_H
#define RISCV_SMPU_H

typedef enum {
    SMPU_READ  = 1 << 0,
    SMPU_WRITE = 1 << 1,
    SMPU_EXEC  = 1 << 2,
    SMPU_SMODE  = 1 << 7
} smpu_priv_t;

typedef enum {
    SMPU_AMATCH_OFF,  /* Null (off)                            */
    SMPU_AMATCH_TOR,  /* Top of Range                          */
    SMPU_AMATCH_NA4,  /* Naturally aligned four-byte region    */
    SMPU_AMATCH_NAPOT /* Naturally aligned power-of-two region */
} smpu_am_t;

typedef struct {
    target_ulong addr_reg;
    uint8_t  cfg_reg;
} smpu_entry_t;

typedef struct {
    target_ulong sa;
    target_ulong ea;
} smpu_addr_t;

typedef struct {
    smpu_entry_t smpu[MAX_RISCV_SMPUS];
    smpu_addr_t  addr[MAX_RISCV_SMPUS];
    uint32_t num_rules;
} smpu_table_t;

void smpucfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val);
target_ulong smpucfg_csr_read(CPURISCVState *env, uint32_t reg_index);

void smpuaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val);
target_ulong smpuaddr_csr_read(CPURISCVState *env, uint32_t addr_index);
bool smpu_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, smpu_priv_t privs, smpu_priv_t *allowed_privs,
    target_ulong mode);
void smpu_update_rule_addr(CPURISCVState *env, uint32_t smpu_index);
void smpu_update_rule_nums(CPURISCVState *env);
uint32_t smpu_get_num_rules(CPURISCVState *env);

#endif
