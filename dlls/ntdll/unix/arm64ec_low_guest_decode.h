/*
 * ARM64EC translated fixed-low data access decoder
 *
 * Copyright 2026 Switchyard Wine project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef __WINE_ARM64EC_LOW_GUEST_DECODE_H
#define __WINE_ARM64EC_LOW_GUEST_DECODE_H

#include <stdbool.h>
#include <stdint.h>

struct arm64ec_low_guest_access
{
    uint64_t address;
    uint64_t writeback;
    unsigned int size;
    unsigned int rn;
    unsigned int rt;
    unsigned int rt2;
    unsigned int pair_element_size;
    unsigned int simd_scalar_size;
    unsigned int sign_extend_size;
    bool write;
    bool load_32;
    bool writeback_valid;
};

static inline unsigned int arm64ec_low_guest_base_register( uint32_t instruction )
{
    return (instruction >> 5) & 0x1f;
}

static inline bool arm64ec_low_guest_offset_register( uint32_t instruction,
                                                       unsigned int *reg )
{
    if ((instruction & UINT32_C(0x3f200c00)) != UINT32_C(0x38200800)) return false;
    if (reg) *reg = (instruction >> 16) & 0x1f;
    return true;
}

static inline bool arm64ec_low_guest_add_delta( uint64_t base, bool negative,
                                                 uint64_t delta, uint64_t low_limit,
                                                 uint64_t *result )
{
    if (!result || base >= low_limit) return false;
    if (negative)
    {
        if (base < delta) return false;
        *result = base - delta;
    }
    else
    {
        if (delta > low_limit - base) return false;
        *result = base + delta;
    }
    return *result < low_limit;
}

static inline bool arm64ec_low_guest_add( uint64_t base, int32_t offset,
                                          uint64_t low_limit, uint64_t *result )
{
    uint64_t delta;

    if (offset < 0)
    {
        delta = (uint64_t)(-(int64_t)offset);
        return arm64ec_low_guest_add_delta( base, true, delta, low_limit, result );
    }
    delta = (uint32_t)offset;
    return arm64ec_low_guest_add_delta( base, false, delta, low_limit, result );
}

static inline bool arm64ec_low_guest_register_delta( uint64_t value, unsigned int option,
                                                       unsigned int shift, bool *negative,
                                                       uint64_t *delta )
{
    uint64_t magnitude;

    if (!negative || !delta || shift > 3) return false;
    switch (option)
    {
    case 2:  /* UXTW */
        *negative = false;
        magnitude = (uint32_t)value;
        break;
    case 3:  /* LSL / UXTX */
        *negative = false;
        magnitude = value;
        break;
    case 6:  /* SXTW */
    {
        uint32_t word = (uint32_t)value;

        *negative = !!(word & UINT32_C(0x80000000));
        magnitude = *negative ? (uint32_t)(~word + 1u) : word;
        break;
    }
    case 7:  /* SXTX */
        *negative = !!(value & (UINT64_C(1) << 63));
        magnitude = *negative ? ~value + 1 : value;
        break;
    default:
        return false;
    }
    if (magnitude > (UINT64_MAX >> shift)) return false;
    *delta = magnitude << shift;
    return true;
}

static inline bool arm64ec_low_guest_extend_signed_load( uint64_t value,
                                                          unsigned int source_size,
                                                          unsigned int result_size,
                                                          uint64_t *result )
{
    uint64_t sign, range, raw;
    int64_t extended;

    if (!result) return false;
    switch (source_size)
    {
    case 1:
        if (result_size != 4 && result_size != 8) return false;
        raw = (uint8_t)value;
        sign = UINT64_C(0x80);
        range = UINT64_C(0x100);
        break;
    case 2:
        if (result_size != 4 && result_size != 8) return false;
        raw = (uint16_t)value;
        sign = UINT64_C(0x8000);
        range = UINT64_C(0x10000);
        break;
    case 4:
        if (result_size != 8) return false;
        raw = (uint32_t)value;
        sign = UINT64_C(0x80000000);
        range = UINT64_C(0x100000000);
        break;
    default:
        return false;
    }

    extended = (int64_t)raw;
    if (raw & sign) extended -= (int64_t)range;
    *result = result_size == 4 ? (uint32_t)extended : (uint64_t)extended;
    return true;
}

static inline bool arm64ec_low_guest_is_translation_fault( uint64_t esr )
{
    unsigned int ec = (esr >> 26) & 0x3f;
    unsigned int dfsc = esr & 0x3f;

    if (ec != 0x24 && ec != 0x25) return false;  /* DABT_LOW / DABT_CUR */
    if ((esr & (UINT64_C(1) << 10)) ||           /* FAR not valid */
        (esr & (UINT64_C(1) << 7)))              /* stage-1 table walk */
        return false;
    return (dfsc & ~3u) == 0x04;                 /* translation level 0..3 */
}

static inline bool arm64ec_decode_low_guest_access( uint32_t instruction,
                                                     uint64_t base, uint64_t offset_register,
                                                     uint64_t fault,
                                                     bool esr_write, uint64_t low_limit,
                                                     struct arm64ec_low_guest_access *access )
{
    struct arm64ec_low_guest_access decoded = {0};
    unsigned int opc = (instruction >> 22) & 3;
    unsigned int size_shift = instruction >> 30;
    uint64_t address, writeback;
    int32_t offset;
    bool writeback_valid = false;
    bool write;

    if (!access) return false;
    *access = decoded;

    /* Non-writeback immediate LDP/STP of W/X or Q registers.  Match the
     * complete addressing-mode and register-bank prefixes so pre/post,
     * non-temporal, signed, and smaller SIMD pairs stay fail-closed. */
    if ((instruction & UINT32_C(0x7f800000)) == UINT32_C(0x29000000) ||
        (instruction & UINT32_C(0xff800000)) == UINT32_C(0xad000000))
    {
        unsigned int imm7 = (instruction >> 15) & 0x7f;
        bool vector_pair = (instruction & UINT32_C(0xff800000)) ==
                           UINT32_C(0xad000000);

        write = !(instruction & (UINT32_C(1) << 22));
        if (write != esr_write) return false;
        decoded.rn = arm64ec_low_guest_base_register( instruction );
        decoded.rt = instruction & 0x1f;
        decoded.rt2 = (instruction >> 10) & 0x1f;
        if (!write && decoded.rt == decoded.rt2) return false;
        decoded.pair_element_size = vector_pair ? 16 :
                                    (instruction & (UINT32_C(1) << 31)) ? 8 : 4;
        decoded.size = decoded.pair_element_size * 2;
        decoded.write = write;
        offset = ((int32_t)(imm7 & 0x3f) - (int32_t)(imm7 & 0x40)) *
                 (int32_t)decoded.pair_element_size;
        if (!arm64ec_low_guest_add( base, offset, low_limit, &address )) return false;
        writeback = base;
        goto validate;
    }

    /* Unsigned-offset LDR/STR of one 128-bit SIMD&FP Q register.  Match the
     * register width and addressing class completely; smaller SIMD widths,
     * writeback, register-offset, structure, and atomic accesses stay closed. */
    if ((instruction & UINT32_C(0xff800000)) == UINT32_C(0x3d800000))
    {
        unsigned int imm12 = (instruction >> 10) & 0xfff;

        write = !(instruction & (UINT32_C(1) << 22));
        if (write != esr_write) return false;
        decoded.rn = arm64ec_low_guest_base_register( instruction );
        decoded.rt = instruction & 0x1f;
        decoded.size = 16;
        decoded.simd_scalar_size = 16;
        decoded.write = write;
        offset = (int32_t)(imm12 << 4);
        if (!arm64ec_low_guest_add( base, offset, low_limit, &address )) return false;
        writeback = base;
        goto validate;
    }

    /* Post-index LDR/STR of one 64-bit SIMD&FP D register.  Match the
     * register width and addressing mode completely; unscaled, pre-index,
     * unsigned-offset, other SIMD widths, and structure accesses stay closed. */
    if ((instruction & UINT32_C(0xffa00c00)) == UINT32_C(0xfc000400))
    {
        unsigned int imm9 = (instruction >> 12) & 0x1ff;

        write = !(instruction & (UINT32_C(1) << 22));
        if (write != esr_write) return false;
        decoded.rn = arm64ec_low_guest_base_register( instruction );
        decoded.rt = instruction & 0x1f;
        decoded.size = 8;
        decoded.simd_scalar_size = 8;
        decoded.write = write;
        offset = (int32_t)(imm9 & 0xff) - (int32_t)(imm9 & 0x100);
        if (base >= low_limit ||
            !arm64ec_low_guest_add( base, offset, low_limit, &writeback ))
            return false;
        address = base;
        writeback_valid = true;
        goto validate;
    }

    if (!opc) write = true;
    else
    {
        write = false;
        if (opc == 2 && size_shift < 3) decoded.sign_extend_size = 8;
        else if (opc == 3 && size_shift < 2) decoded.sign_extend_size = 4;
        else if (opc != 1) return false;  /* reject prefetch and reserved forms */
    }
    if (write != esr_write) return false;

    decoded.rn = arm64ec_low_guest_base_register( instruction );
    decoded.rt = instruction & 0x1f;

    if ((instruction & UINT32_C(0x3f000000)) == UINT32_C(0x39000000))
    {
        /* Scalar unsigned-offset STR/LDR and signed-load variants. */
        decoded.size = 1u << size_shift;
        offset = (int32_t)(((instruction >> 10) & 0xfff) << size_shift);
        if (!arm64ec_low_guest_add( base, offset, low_limit, &address )) return false;
        writeback = base;
    }
    else if ((instruction & UINT32_C(0x3f200000)) == UINT32_C(0x38000000))
    {
        unsigned int mode = (instruction >> 10) & 3;
        unsigned int imm9 = (instruction >> 12) & 0x1ff;

        /* Scalar unscaled/pre/post STR/LDR and signed-load variants. */
        if (mode == 2) return false;
        /* Encoded 31 names SP as the base and ZR as the transfer register,
         * so that pair does not overlap despite sharing an encoding value. */
        if (mode && decoded.rn == decoded.rt && decoded.rn != 31) return false;
        decoded.size = 1u << size_shift;
        offset = (int32_t)(imm9 & 0xff) - (int32_t)(imm9 & 0x100);
        if (mode == 1)  /* post-index */
        {
            if (base >= low_limit) return false;
            address = base;
            if (!arm64ec_low_guest_add( base, offset, low_limit, &writeback )) return false;
            writeback_valid = true;
        }
        else
        {
            if (!arm64ec_low_guest_add( base, offset, low_limit, &address )) return false;
            writeback = address;
            writeback_valid = mode == 3;  /* pre-index */
        }
    }
    else if (arm64ec_low_guest_offset_register( instruction, NULL ))
    {
        unsigned int option = (instruction >> 13) & 7;
        unsigned int rm = (instruction >> 16) & 0x1f;
        unsigned int shift = (instruction & (UINT32_C(1) << 12)) ? size_shift : 0;
        uint64_t delta;
        bool negative;

        /* Scalar register-offset STR/LDR and signed-load variants.  The only architected
         * extensions for this class are UXTW, LSL, SXTW, and SXTX. */
        decoded.size = 1u << size_shift;
        if (rm == 31) offset_register = 0;  /* WZR/XZR */
        if (!arm64ec_low_guest_register_delta( offset_register, option, shift,
                                                &negative, &delta ) ||
            !arm64ec_low_guest_add_delta( base, negative, delta, low_limit, &address ))
            return false;
        writeback = base;
    }
    else return false;

validate:
    if (!address || address >= low_limit || decoded.size > low_limit - address ||
        fault < address || fault - address >= decoded.size)
        return false;

    decoded.address = address;
    decoded.writeback = writeback;
    decoded.write = write;
    decoded.load_32 = !write && !decoded.sign_extend_size && decoded.size == 4;
    decoded.writeback_valid = writeback_valid;
    *access = decoded;
    return true;
}

/* Match only a bounded, non-writeback access whose architectural base is x18.
 * This is also used to authenticate a Darwin custom-x18 recovery fault; keep it
 * as strict as the fixed-low bridge so an unrelated null dereference cannot be
 * mistaken for a lost platform-register state. */
static inline bool arm64ec_decode_lost_x18_access( uint32_t instruction,
                                                   uint64_t base,
                                                   uint64_t offset_register,
                                                   uint64_t fault, bool esr_write,
                                                   uint64_t low_limit,
                                                   struct arm64ec_low_guest_access *access )
{
    struct arm64ec_low_guest_access decoded;

    if (arm64ec_low_guest_base_register( instruction ) != 18 ||
        !arm64ec_decode_low_guest_access( instruction, base, offset_register,
                                          fault, esr_write, low_limit, &decoded ) ||
        decoded.writeback_valid)
        return false;
    if (access) *access = decoded;
    return true;
}

/* Match an access through a temporary register produced immediately beforehand
 * by a side-effect-free extended ADD from x18.  The caller must replay the ADD
 * after restoring x18; validating its result against the captured temporary
 * value proves that the low access was actually derived from the lost platform
 * register rather than from an unrelated null pointer. */
static inline bool arm64ec_decode_lost_x18_derived_access(
    uint32_t producer_instruction, uint32_t access_instruction,
    uint64_t lost_x18, uint64_t producer_offset_register,
    uint64_t access_base, uint64_t access_offset_register,
    uint64_t fault, bool esr_write, uint64_t low_limit,
    struct arm64ec_low_guest_access *access )
{
    struct arm64ec_low_guest_access decoded;
    unsigned int rd = producer_instruction & 0x1f;
    unsigned int rn = arm64ec_low_guest_base_register( producer_instruction );
    unsigned int rm = (producer_instruction >> 16) & 0x1f;
    unsigned int option = (producer_instruction >> 13) & 7;
    unsigned int shift = (producer_instruction >> 10) & 7;
    uint64_t delta, expected_base;
    bool negative;

    /* ADD Xd, Xn, Rm, extend #shift, without flag updates.  Replaying an ADD
     * that writes SP or x18 is not safe, and an overwritten Rm cannot be
     * reconstructed from the fault context. */
    if ((producer_instruction & UINT32_C(0xffe00000)) != UINT32_C(0x8b200000) ||
        rn != 18 || rd == 18 || rd == 31 || rm == 18 || rm == rd ||
        rd != arm64ec_low_guest_base_register( access_instruction ))
        return false;
    if (rm == 31) producer_offset_register = 0;
    if (!arm64ec_low_guest_register_delta( producer_offset_register, option, shift,
                                            &negative, &delta ) ||
        !arm64ec_low_guest_add_delta( lost_x18, negative, delta, low_limit,
                                      &expected_base ) ||
        expected_base != access_base ||
        !arm64ec_decode_low_guest_access( access_instruction, access_base,
                                          access_offset_register, fault, esr_write,
                                          low_limit, &decoded ) ||
        decoded.writeback_valid)
        return false;
    if (access) *access = decoded;
    return true;
}

#endif /* __WINE_ARM64EC_LOW_GUEST_DECODE_H */
