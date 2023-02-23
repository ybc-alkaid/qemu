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

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "cpu.h"
#include "cpu_bits.h"
#include "trace.h"
#include "exec/exec-all.h"

static void spmp_write_cfg(CPURISCVState *env, uint32_t addr_index,
    uint8_t val);
static uint8_t spmp_read_cfg(CPURISCVState *env, uint32_t addr_index);
static void spmp_update_rule(CPURISCVState *env, uint32_t spmp_index);

/*
 * Accessor method to extract address matching type 'a field' from cfg reg
 */
static inline uint8_t spmp_get_a_field(uint8_t cfg)
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
 * Check whether an SPMP is s-mode only or not.
 */
static inline int spmp_is_smode_only(CPURISCVState *env, uint32_t spmp_index)
{

    if (env->spmp_state.spmp[spmp_index].cfg_reg & SPMP_SMODE) {
        return 1;
    }

    return 0;
}

/*
 * Count the number of active rules.
 */
uint32_t spmp_get_num_rules(CPURISCVState *env)
{
     return env->spmp_state.num_rules;
}

/*
 * Accessor to get the cfg reg for a specific SPMP/HART
 */
static inline uint8_t spmp_read_cfg(CPURISCVState *env, uint32_t spmp_index)
{
    if (spmp_index < MAX_RISCV_SPMPS) {
        return env->spmp_state.spmp[spmp_index].cfg_reg;
    }

    return 0;
}

/*
 * Accessor to set the cfg reg for a specific SPMP/HART
 * Bounds checks.
 */
static void spmp_write_cfg(CPURISCVState *env, uint32_t spmp_index, uint8_t val)
{
    if (spmp_index < MAX_RISCV_SPMPS) {
        env->spmp_state.spmp[spmp_index].cfg_reg = val;
        spmp_update_rule(env, spmp_index);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                    "ignoring spmpcfg write - out of bounds\n");
    }
}

static void spmp_decode_napot(target_ulong a, target_ulong *sa, target_ulong *ea)
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

void spmp_update_rule_addr(CPURISCVState *env, uint32_t spmp_index)
{
    uint8_t this_cfg = env->spmp_state.spmp[spmp_index].cfg_reg;
    target_ulong this_addr = env->spmp_state.spmp[spmp_index].addr_reg;
    target_ulong prev_addr = 0u;
    target_ulong sa = 0u;
    target_ulong ea = 0u;

    if (spmp_index >= 1u) {
        prev_addr = env->spmp_state.spmp[spmp_index - 1].addr_reg;
    }

    switch (spmp_get_a_field(this_cfg)) {
    case SPMP_AMATCH_OFF:
        sa = 0u;
        ea = -1;
        break;

    case SPMP_AMATCH_TOR:
        sa = prev_addr << 2; /* shift up from [xx:0] to [xx+2:2] */
        ea = (this_addr << 2) - 1u;
        break;

    case SPMP_AMATCH_NA4:
        sa = this_addr << 2; /* shift up from [xx:0] to [xx+2:2] */
        ea = (sa + 4u) - 1u;
        break;

    case SPMP_AMATCH_NAPOT:
        spmp_decode_napot(this_addr, &sa, &ea);
        break;

    default:
        sa = 0u;
        ea = 0u;
        break;
    }

    env->spmp_state.addr[spmp_index].sa = sa;
    env->spmp_state.addr[spmp_index].ea = ea;
}

void spmp_update_rule_nums(CPURISCVState *env)
{
    int i;

    env->spmp_state.num_rules = 0;
    for (i = 0; i < MAX_RISCV_SPMPS; i++) {
        const uint8_t a_field =
            spmp_get_a_field(env->spmp_state.spmp[i].cfg_reg);
        if (SPMP_AMATCH_OFF != a_field) {
            env->spmp_state.num_rules++;
        }
    }
}

/* Convert cfg/addr reg values here into simple 'sa' --> start address and 'ea'
 *   end address values.
 *   This function is called relatively infrequently whereas the check that
 *   an address is within a spmp rule is called often, so optimise that one
 */
static void spmp_update_rule(CPURISCVState *env, uint32_t spmp_index)
{
    spmp_update_rule_addr(env, spmp_index);
    spmp_update_rule_nums(env);
}

static int spmp_is_in_range(CPURISCVState *env, int spmp_index, target_ulong addr)
{
    int result = 0;

    if ((addr >= env->spmp_state.addr[spmp_index].sa)
        && (addr <= env->spmp_state.addr[spmp_index].ea)) {
        result = 1;
    } else {
        result = 0;
    }

    return result;
}

/*
 * Check if the address has required RWX privs when no SPMP entry is matched.
 */
static bool spmp_hart_has_privs_default(CPURISCVState *env, target_ulong addr,
    target_ulong size, spmp_priv_t privs, spmp_priv_t *allowed_privs,
    target_ulong mode)
{
    bool ret;

    if ((!riscv_feature(env, RISCV_FEATURE_SPMP)) || (mode != PRV_U)) {
        /*
         * The SPMP proposal states three circumstances that the access is allowed:
         * 1. The HW does not implement any SPMP entry.
         * 2. The HW implements SPMP, but no SPMP entry matches S-Mode access.
         * 3. The access mode is M.
         */
        ret = true;
        *allowed_privs = SPMP_READ | SPMP_WRITE | SPMP_EXEC;
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
bool spmp_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, spmp_priv_t privs, spmp_priv_t *allowed_privs,
    target_ulong mode)
{
    int i = 0;
    int ret = -1;
    int spmp_size = 0;
    target_ulong s = 0;
    target_ulong e = 0;

	/* Short cut for M-mode access*/
    if (mode == PRV_M) {
		*allowed_privs = SPMP_READ | SPMP_WRITE | SPMP_EXEC;
		return true;
	}

    /* Short cut if no rules */
    if (0 == spmp_get_num_rules(env)) {
        return spmp_hart_has_privs_default(env, addr, size, privs,
                                          allowed_privs, mode);
    }

    if (size == 0) {
        if (riscv_feature(env, RISCV_FEATURE_MMU)) {
            /*
             * If size is unknown (0), assume that all bytes
             * from addr to the end of the page will be accessed.
             */
            spmp_size = -(addr | TARGET_PAGE_MASK);
        } else {
            spmp_size = sizeof(target_ulong);
        }
    } else {
        spmp_size = size;
    }

    /* 1.10 draft priv spec states there is an implicit order
         from low to high */
    for (i = 0; i < MAX_RISCV_SPMPS; i++) {
        s = spmp_is_in_range(env, i, addr);
        e = spmp_is_in_range(env, i, addr + spmp_size - 1);

        /* partially inside */
        if ((s + e) == 1) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "spmp violation - access is partially inside\n");
            ret = 0;
            break;
        }

        /* fully inside */
        const uint8_t a_field =
            spmp_get_a_field(env->spmp_state.spmp[i].cfg_reg);

        /*
         * Convert the SPMP permissions to match the truth table in the
         * SPMP spec.
         */
        const uint8_t spmp_operation =
            ((env->spmp_state.spmp[i].cfg_reg & SPMP_SMODE) >> 4) |
            ((env->spmp_state.spmp[i].cfg_reg & SPMP_READ) << 2) |
            (env->spmp_state.spmp[i].cfg_reg & SPMP_WRITE) |
            ((env->spmp_state.spmp[i].cfg_reg & SPMP_EXEC) >> 2);

        if (((s + e) == 2) && (SPMP_AMATCH_OFF != a_field)) {
            /*
             * If the SPMP entry is not off and the address is in range,
             * do the priv check
             */
            if ((mode == PRV_S) && !sum_is_set(env)) {
                switch (spmp_operation) {
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
                    *allowed_privs = SPMP_READ | SPMP_WRITE;
                    break;
                case 8:
                    /* Reserved region, mark it as RWX for now. */
                    *allowed_privs = SPMP_READ | SPMP_WRITE | SPMP_EXEC;
                    break;
                case 9:
                case 10:
                    *allowed_privs = SPMP_EXEC;
                    break;
                case 11:
                case 13:
                    *allowed_privs = SPMP_READ | SPMP_EXEC;
                    break;
                case 12:
                case 15:
                    *allowed_privs = SPMP_READ;
                    break;
                default:
                    g_assert_not_reached();
                }
            } else if ((mode == PRV_S) && sum_is_set(env)) {
                switch (spmp_operation) {
                case 0:
                case 1:
                    *allowed_privs = 0;
                    break;
                case 2:
                case 3:
                case 6:
                case 7:
                case 14:
                    *allowed_privs = SPMP_READ | SPMP_WRITE;
                    break;
                case 4:
                case 5:
                case 12:
                case 15:
                    *allowed_privs = SPMP_READ;
                    break;
                case 8:
                    /* Reserved region, mark it as RWX for now. */
                    *allowed_privs = SPMP_READ | SPMP_WRITE | SPMP_EXEC;
                    break;
                case 9:
                case 10:
                    *allowed_privs = SPMP_EXEC;
                    break;
                case 11:
                case 13:
                    *allowed_privs = SPMP_READ | SPMP_EXEC;
                    break;
                default:
                    g_assert_not_reached();
                }
            } else if (mode == PRV_U) {
                switch (spmp_operation) {
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
                    *allowed_privs = SPMP_EXEC;
                    break;
                case 2:
                case 4:
                case 15:
                    *allowed_privs = SPMP_READ;
                    break;
                case 3:
                case 6:
                    *allowed_privs = SPMP_READ | SPMP_WRITE;
                    break;
                case 5:
                    *allowed_privs = SPMP_READ | SPMP_EXEC;
                    break;
                case 7:
                    *allowed_privs = SPMP_READ | SPMP_WRITE | SPMP_EXEC;
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
        return spmp_hart_has_privs_default(env, addr, size, privs,
                                          allowed_privs, mode);
    }

    return ret == 1 ? true : false;
}

/*
 * Handle a write to a spmpcfg CSR
 */
void spmpcfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val)
{
    int i;
    uint8_t cfg_val;
    int spmpcfg_nums = 2 << riscv_cpu_mxl(env);

    // trace_spmpcfg_csr_write(env->mhartid, reg_index, val);

    for (i = 0; i < spmpcfg_nums; i++) {
        cfg_val = (val >> 8 * i)  & 0xff;
        spmp_write_cfg(env, (reg_index * 4) + i, cfg_val);
    }

    /* If SPMP permission of any addr has been changed, and the HW enables MMU, flush TLB pages. */
#if 0
    if (riscv_feature(env, RISCV_FEATURE_MMU)) {
        tlb_flush(env_cpu(env));
    }
#endif
}


/*
 * Handle a read from a spmpcfg CSR
 */
target_ulong spmpcfg_csr_read(CPURISCVState *env, uint32_t reg_index)
{
    int i;
    target_ulong cfg_val = 0;
    target_ulong val = 0;
    int spmpcfg_nums = 2 << riscv_cpu_mxl(env);

    for (i = 0; i < spmpcfg_nums; i++) {
        val = spmp_read_cfg(env, (reg_index * 4) + i);
        cfg_val |= (val << (i * 8));
    }
    // trace_spmpcfg_csr_read(env->mhartid, reg_index, cfg_val);


    return cfg_val;
}


/*
 * Handle a write to a spmpaddr CSR
 */
void spmpaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val)
{
    // trace_spmpaddr_csr_write(env->mhartid, addr_index, val);

    if (addr_index < MAX_RISCV_SPMPS) {
        env->spmp_state.spmp[addr_index].addr_reg = val;
        spmp_update_rule(env, addr_index);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ignoring spmpaddr write - out of bounds\n");
    }
}

/*
 * Handle a read from a spmpaddr CSR
 */
target_ulong spmpaddr_csr_read(CPURISCVState *env, uint32_t addr_index)
{
    target_ulong val = 0;

    if (addr_index < MAX_RISCV_SPMPS) {
        val = env->spmp_state.spmp[addr_index].addr_reg;
        // trace_spmpaddr_csr_read(env->mhartid, addr_index, val);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ignoring spmpaddr read - out of bounds\n");
    }

    return val;
}

/*
 * Convert SPMP privilege to TLB page privilege.
 */
int spmp_priv_to_page_prot(spmp_priv_t spmp_priv)
{
    int prot = 0;

    if (spmp_priv & SPMP_READ) {
        prot |= PAGE_READ;
    }
    if (spmp_priv & SPMP_WRITE) {
        prot |= PAGE_WRITE;
    }
    if (spmp_priv & SPMP_EXEC) {
        prot |= PAGE_EXEC;
    }

    return prot;
}

