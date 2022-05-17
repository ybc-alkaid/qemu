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

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "cpu.h"
#include "cpu_bits.h"
#include "trace.h"
#include "exec/exec-all.h"

static void smpu_write_cfg(CPURISCVState *env, uint32_t addr_index,
    uint8_t val);
static uint8_t smpu_read_cfg(CPURISCVState *env, uint32_t addr_index);
static void smpu_update_rule(CPURISCVState *env, uint32_t smpu_index);

/*
 * Accessor method to extract address matching type 'a field' from cfg reg
 */
static inline uint8_t smpu_get_a_field(uint8_t cfg)
{
    uint8_t a = cfg >> 3;
    return a & 0x3;
}

/*
 * Check whether mstatus.sum is set.
 */
static inline int sum_is_set(CPURISCVState *env)
{
    if (env->mstatus & MSTATUS_SUM) {
        return 1;
    }

    return 0;
}

/*
 * Check whether an SMPU is s-mode only or not.
 */
static inline int smpu_is_smode_only(CPURISCVState *env, uint32_t smpu_index)
{

    if (env->smpu_state.smpu[smpu_index].cfg_reg & SMPU_SMODE) {
        return 1;
    }

    return 0;
}

/*
 * Count the number of active rules.
 */
uint32_t smpu_get_num_rules(CPURISCVState *env)
{
     return env->smpu_state.num_rules;
}

/*
 * Accessor to get the cfg reg for a specific SMPU/HART
 */
static inline uint8_t smpu_read_cfg(CPURISCVState *env, uint32_t smpu_index)
{
    if (smpu_index < MAX_RISCV_SMPUS) {
        return env->smpu_state.smpu[smpu_index].cfg_reg;
    }

    return 0;
}

/*
 * Accessor to set the cfg reg for a specific SMPU/HART
 * Bounds checks.
 */
static void smpu_write_cfg(CPURISCVState *env, uint32_t smpu_index, uint8_t val)
{
    if (smpu_index < MAX_RISCV_SMPUS) {
        env->smpu_state.smpu[smpu_index].cfg_reg = val;
        smpu_update_rule(env, smpu_index);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                    "ignoring smpucfg write - out of bounds\n");
    }
}

static void smpu_decode_napot(target_ulong a, target_ulong *sa, target_ulong *ea)
{
    /*
       aaaa...aaa0   8-byte NAPOT range
       aaaa...aa01   16-byte NAPOT range
       aaaa...a011   32-byte NAPOT range
       ...
       aa01...1111   2^XLEN-byte NAPOT range
       a011...1111   2^(XLEN+1)-byte NAPOT range
       0111...1111   2^(XLEN+2)-byte NAPOT range
       1111...1111   Reserved
    */
    if (a == -1) {
        *sa = 0u;
        *ea = -1;
        return;
    } else {
        target_ulong t1 = ctz64(~a);
        target_ulong base = (a & ~(((target_ulong)1 << t1) - 1)) << 2;
        target_ulong range = ((target_ulong)1 << (t1 + 3)) - 1;
        *sa = base;
        *ea = base + range;
    }
}

void smpu_update_rule_addr(CPURISCVState *env, uint32_t smpu_index)
{
    uint8_t this_cfg = env->smpu_state.smpu[smpu_index].cfg_reg;
    target_ulong this_addr = env->smpu_state.smpu[smpu_index].addr_reg;
    target_ulong prev_addr = 0u;
    target_ulong sa = 0u;
    target_ulong ea = 0u;

    if (smpu_index >= 1u) {
        prev_addr = env->smpu_state.smpu[smpu_index - 1].addr_reg;
    }

    switch (smpu_get_a_field(this_cfg)) {
    case SMPU_AMATCH_OFF:
        sa = 0u;
        ea = -1;
        break;

    case SMPU_AMATCH_TOR:
        sa = prev_addr << 2; /* shift up from [xx:0] to [xx+2:2] */
        ea = (this_addr << 2) - 1u;
        break;

    case SMPU_AMATCH_NA4:
        sa = this_addr << 2; /* shift up from [xx:0] to [xx+2:2] */
        ea = (sa + 4u) - 1u;
        break;

    case SMPU_AMATCH_NAPOT:
        smpu_decode_napot(this_addr, &sa, &ea);
        break;

    default:
        sa = 0u;
        ea = 0u;
        break;
    }

    env->smpu_state.addr[smpu_index].sa = sa;
    env->smpu_state.addr[smpu_index].ea = ea;
}

void smpu_update_rule_nums(CPURISCVState *env)
{
    int i;

    env->smpu_state.num_rules = 0;
    for (i = 0; i < MAX_RISCV_SMPUS; i++) {
        const uint8_t a_field =
            smpu_get_a_field(env->smpu_state.smpu[i].cfg_reg);
        if (SMPU_AMATCH_OFF != a_field) {
            env->smpu_state.num_rules++;
        }
    }
}

/* Convert cfg/addr reg values here into simple 'sa' --> start address and 'ea'
 *   end address values.
 *   This function is called relatively infrequently whereas the check that
 *   an address is within a smpu rule is called often, so optimise that one
 */
static void smpu_update_rule(CPURISCVState *env, uint32_t smpu_index)
{
    smpu_update_rule_addr(env, smpu_index);
    smpu_update_rule_nums(env);
}

static int smpu_is_in_range(CPURISCVState *env, int smpu_index, target_ulong addr)
{
    int result = 0;

    if ((addr >= env->smpu_state.addr[smpu_index].sa)
        && (addr <= env->smpu_state.addr[smpu_index].ea)) {
        result = 1;
    } else {
        result = 0;
    }

    return result;
}

/*
 * Check if the address has required RWX privs when no SMPU entry is matched.
 */
static bool smpu_hart_has_privs_default(CPURISCVState *env, target_ulong addr,
    target_ulong size, smpu_priv_t privs, smpu_priv_t *allowed_privs,
    target_ulong mode)
{
    bool ret;

    if ((!riscv_feature(env, RISCV_FEATURE_SMPU)) || (mode != PRV_U)) {
        /*
         * The SMPU proposal states three circumstances that the access is allowed:
         * 1. The HW does not implement any SMPU entry.
         * 2. The HW implements SMPU, but no SMPU entry matches S-Mode access.
         * 3. The access mode is M.
         */
        ret = true;
        *allowed_privs = SMPU_READ | SMPU_WRITE | SMPU_EXEC;
    } else {
        /*
         * U-mode is not allowed to succeed if they don't match a rule,
         * but there are rules. We've checked for no rule earlier in this
         * function.
         */
        ret = false;
        *allowed_privs = 0;
    }

    return ret;
}


/*
 * Public Interface
 */

/*
 * Check if the address has required RWX privs to complete desired operation
 */
bool smpu_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, smpu_priv_t privs, smpu_priv_t *allowed_privs,
    target_ulong mode)
{
    int i = 0;
    int ret = -1;
    int smpu_size = 0;
    target_ulong s = 0;
    target_ulong e = 0;

	/* Short cut for M-mode access*/
    if (mode == PRV_M) {
		*allowed_privs = SMPU_READ | SMPU_WRITE | SMPU_EXEC;
		return true;
	}

    /* Short cut if no rules */
    if (0 == smpu_get_num_rules(env)) {
        return smpu_hart_has_privs_default(env, addr, size, privs,
                                          allowed_privs, mode);
    }

    if (size == 0) {
        if (riscv_feature(env, RISCV_FEATURE_MMU)) {
            /*
             * If size is unknown (0), assume that all bytes
             * from addr to the end of the page will be accessed.
             */
            smpu_size = -(addr | TARGET_PAGE_MASK);
        } else {
            smpu_size = sizeof(target_ulong);
        }
    } else {
        smpu_size = size;
    }

    /* 1.10 draft priv spec states there is an implicit order
         from low to high */
    for (i = 0; i < MAX_RISCV_SMPUS; i++) {
        s = smpu_is_in_range(env, i, addr);
        e = smpu_is_in_range(env, i, addr + smpu_size - 1);

        /* partially inside */
        if ((s + e) == 1) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "smpu violation - access is partially inside\n");
            ret = 0;
            break;
        }

        /* fully inside */
        const uint8_t a_field =
            smpu_get_a_field(env->smpu_state.smpu[i].cfg_reg);

        /*
         * Convert the SMPU permissions to match the truth table in the
         * SMPU spec.
         */
        const uint8_t smpu_operation =
            ((env->smpu_state.smpu[i].cfg_reg & SMPU_SMODE) >> 4) |
            ((env->smpu_state.smpu[i].cfg_reg & SMPU_READ) << 2) |
            (env->smpu_state.smpu[i].cfg_reg & SMPU_WRITE) |
            ((env->smpu_state.smpu[i].cfg_reg & SMPU_EXEC) >> 2);

        if (((s + e) == 2) && (SMPU_AMATCH_OFF != a_field)) {
            /*
             * If the SMPU entry is not off and the address is in range,
             * do the priv check
             */
            if ((mode == PRV_S) && !sum_is_set(env)) {
                switch (smpu_operation) {
                case 0:
                case 1:
                case 4:
                case 5:
                case 6:
                case 7:
                    *allowed_privs = 0;
                    break;
                case 2:
                case 3:
                case 14:
                    *allowed_privs = SMPU_READ | SMPU_WRITE;
                    break;
                case 8:
                    /* Reserved region, mark it as RWX for now. */
                    *allowed_privs = SMPU_READ | SMPU_WRITE | SMPU_EXEC;
                    break;
                case 9:
                case 10:
                    *allowed_privs = SMPU_EXEC;
                    break;
                case 11:
                case 13:
                    *allowed_privs = SMPU_READ | SMPU_EXEC;
                    break;
                case 12:
                case 15:
                    *allowed_privs = SMPU_READ;
                    break;
                default:
                    g_assert_not_reached();
                }
            } else if ((mode == PRV_S) && sum_is_set(env)) {
                switch (smpu_operation) {
                case 0:
                case 1:
                    *allowed_privs = 0;
                    break;
                case 2:
                case 3:
                case 6:
                case 7:
                case 14:
                    *allowed_privs = SMPU_READ | SMPU_WRITE;
                    break;
                case 4:
                case 5:
                case 12:
                case 15:
                    *allowed_privs = SMPU_READ;
                    break;
                case 8:
                    /* Reserved region, mark it as RWX for now. */
                    *allowed_privs = SMPU_READ | SMPU_WRITE | SMPU_EXEC;
                    break;
                case 9:
                case 10:
                    *allowed_privs = SMPU_EXEC;
                    break;
                case 11:
                case 13:
                    *allowed_privs = SMPU_READ | SMPU_EXEC;
                    break;
                default:
                    g_assert_not_reached();
                }
            } else if (mode == PRV_U) {
                switch (smpu_operation) {
                case 0:
                case 8:
                    /* Reserved region, mark it as inaccessible for now. */
                case 9:
                case 12:
                case 13:
                case 14:
                    *allowed_privs = 0;
                    break;
                case 1:
                case 10:
                case 11:
                    *allowed_privs = SMPU_EXEC;
                    break;
                case 2:
                case 4:
                case 15:
                    *allowed_privs = SMPU_READ;
                    break;
                case 3:
                case 6:
                    *allowed_privs = SMPU_READ | SMPU_WRITE;
                    break;
                case 5:
                    *allowed_privs = SMPU_READ | SMPU_EXEC;
                    break;
                case 7:
                    *allowed_privs = SMPU_READ | SMPU_WRITE | SMPU_EXEC;
                    break;
                default:
                    g_assert_not_reached();
                }
            }
			ret = ((privs & *allowed_privs) == privs);
			break;
        }

    }

    /* No rule matched */
    if (ret == -1) {
        return smpu_hart_has_privs_default(env, addr, size, privs,
                                          allowed_privs, mode);
    }

    return ret == 1 ? true : false;
}

/*
 * Handle a write to a smpucfg CSR
 */
void smpucfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val)
{
    int i;
    uint8_t cfg_val;
    int smpucfg_nums = 2 << riscv_cpu_mxl(env);

    // trace_smpucfg_csr_write(env->mhartid, reg_index, val);

    for (i = 0; i < smpucfg_nums; i++) {
        cfg_val = (val >> 8 * i)  & 0xff;
        smpu_write_cfg(env, (reg_index * 4) + i, cfg_val);
    }

    /* If SMPU permission of any addr has been changed, and the HW enables MMU, flush TLB pages. */
#if 0
    if (riscv_feature(env, RISCV_FEATURE_MMU)) {
        tlb_flush(env_cpu(env));
    }
#endif
}


/*
 * Handle a read from a smpucfg CSR
 */
target_ulong smpucfg_csr_read(CPURISCVState *env, uint32_t reg_index)
{
    int i;
    target_ulong cfg_val = 0;
    target_ulong val = 0;
    int smpucfg_nums = 2 << riscv_cpu_mxl(env);

    for (i = 0; i < smpucfg_nums; i++) {
        val = smpu_read_cfg(env, (reg_index * 4) + i);
        cfg_val |= (val << (i * 8));
    }
    // trace_smpucfg_csr_read(env->mhartid, reg_index, cfg_val);


    return cfg_val;
}


/*
 * Handle a write to a smpuaddr CSR
 */
void smpuaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val)
{
    // trace_smpuaddr_csr_write(env->mhartid, addr_index, val);

    if (addr_index < MAX_RISCV_SMPUS) {
        env->smpu_state.smpu[addr_index].addr_reg = val;
        smpu_update_rule(env, addr_index);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ignoring smpuaddr write - out of bounds\n");
    }
}

/*
 * Handle a read from a smpuaddr CSR
 */
target_ulong smpuaddr_csr_read(CPURISCVState *env, uint32_t addr_index)
{
    target_ulong val = 0;

    if (addr_index < MAX_RISCV_SMPUS) {
        val = env->smpu_state.smpu[addr_index].addr_reg;
        // trace_smpuaddr_csr_read(env->mhartid, addr_index, val);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ignoring smpuaddr read - out of bounds\n");
    }

    return val;
}

/*
 * Convert SMPU privilege to TLB page privilege.
 */
int smpu_priv_to_page_prot(smpu_priv_t smpu_priv)
{
    int prot = 0;

    if (smpu_priv & SMPU_READ) {
        prot |= PAGE_READ;
    }
    if (smpu_priv & SMPU_WRITE) {
        prot |= PAGE_WRITE;
    }
    if (smpu_priv & SMPU_EXEC) {
        prot |= PAGE_EXEC;
    }

    return prot;
}

