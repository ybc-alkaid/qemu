/*
 * QEMU RISC-V SPMP (S-mode Physical Memory Protection)
 *
 * Author: Bicheng Yang, SuperYbc@outlook.com
 *         Dong Du,      Ddnirvana1@gmail.com
 *
 * This provides a RISC-V S-mode Physical Memory Protection interface
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

#ifndef RISCV_SPMP_H
#define RISCV_SPMP_H

typedef enum {
    SPMP_READ  = 1 << 0,
    SPMP_WRITE = 1 << 1,
    SPMP_EXEC  = 1 << 2,
    SPMP_SMODE = 1 << 7
} spmp_priv_t;

typedef enum {
    SPMP_AMATCH_OFF,  /* Null (off)                            */
    SPMP_AMATCH_TOR,  /* Top of Range                          */
    SPMP_AMATCH_NA4,  /* Naturally aligned four-byte region    */
    SPMP_AMATCH_NAPOT /* Naturally aligned power-of-two region */
} spmp_am_t;

typedef struct {
    target_ulong addr_reg;
    uint8_t  cfg_reg;
} spmp_entry_t;

typedef struct {
    target_ulong sa;
    target_ulong ea;
} spmp_addr_t;

typedef struct {
    spmp_entry_t spmp[MAX_RISCV_SPMPS];
    spmp_addr_t  addr[MAX_RISCV_SPMPS];
    uint32_t num_rules;
} spmp_table_t;

void spmpcfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val);
target_ulong spmpcfg_csr_read(CPURISCVState *env, uint32_t reg_index);

void spmpaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val);
target_ulong spmpaddr_csr_read(CPURISCVState *env, uint32_t addr_index);
bool spmp_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, spmp_priv_t privs, spmp_priv_t *allowed_privs,
    target_ulong mode);
void spmp_update_rule_addr(CPURISCVState *env, uint32_t spmp_index);
void spmp_update_rule_nums(CPURISCVState *env);
uint32_t spmp_get_num_rules(CPURISCVState *env);
int spmp_priv_to_page_prot(spmp_priv_t spmp_priv);

#endif
