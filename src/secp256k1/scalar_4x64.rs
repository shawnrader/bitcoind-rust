/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/
 #![allow(warnings)]
 use crate::secp256k1::secp256k1_scalar;
use crate::secp256k1::modinv64::*;

 /* Limbs of the secp256k1 order. */
/*
#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
*/
const SECP256K1_N_0: u64 = 0xBFD25E8CD0364141;
const SECP256K1_N_1: u64 = 0xBAAEDCE6AF48A03B;
const SECP256K1_N_2: u64 = 0xFFFFFFFFFFFFFFFE;
const SECP256K1_N_3: u64 = 0xFFFFFFFFFFFFFFFF;

/* Limbs of 2^256 minus the secp256k1 order. */
//#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
//#define SECP256K1_N_C_1 (~SECP256K1_N_1)
//#define SECP256K1_N_C_2 (1)
const SECP256K1_N_C_0: u64 = !SECP256K1_N_0 + 1;
const SECP256K1_N_C_1: u64 = !SECP256K1_N_1;
const SECP256K1_N_C_2: u64 = 1;

/* Limbs of half the secp256k1 order. */
//#define SECP256K1_N_H_0 ((uint64_t)0xDFE92F46681B20A0ULL)
//#define SECP256K1_N_H_1 ((uint64_t)0x5D576E7357A4501DULL)
//#define SECP256K1_N_H_2 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
//#define SECP256K1_N_H_3 ((uint64_t)0x7FFFFFFFFFFFFFFFULL)
const SECP256K1_N_H_0: u64 = 0xDFE92F46681B20A0;
const SECP256K1_N_H_1: u64 = 0x5D576E7357A4501D;
const SECP256K1_N_H_2: u64 = 0xFFFFFFFFFFFFFFFF;
const SECP256K1_N_H_3: u64 = 0x7FFFFFFFFFFFFFFF;

// SECP256K1_INLINE static void secp256k1_scalar_clear(secp256k1_scalar *r) {
//     r->d[0] = 0;
//     r->d[1] = 0;
//     r->d[2] = 0;
//     r->d[3] = 0;
// }
pub fn secp256k1_scalar_clear(r: &mut secp256k1_scalar) {
    r.d[0] = 0;
    r.d[1] = 0;
    r.d[2] = 0;
    r.d[3] = 0;
}

// SECP256K1_INLINE static void secp256k1_scalar_set_int(secp256k1_scalar *r, unsigned int v) {
//     r->d[0] = v;
//     r->d[1] = 0;
//     r->d[2] = 0;
//     r->d[3] = 0;
// }
pub fn secp256k1_scalar_set_int(r: &mut secp256k1_scalar, v: u32) {
    r.d[0] = v as u64;
    r.d[1] = 0;
    r.d[2] = 0;
    r.d[3] = 0;
}

// SECP256K1_INLINE static unsigned int secp256k1_scalar_get_bits(const secp256k1_scalar *a, unsigned int offset, unsigned int count) {
//     VERIFY_CHECK((offset + count - 1) >> 6 == offset >> 6);
//     return (a->d[offset >> 6] >> (offset & 0x3F)) & ((((uint64_t)1) << count) - 1);
// }
pub fn secp256k1_scalar_get_bits(a: &secp256k1_scalar, offset: u32, count: u32) -> u32 {
    // VERIFY_CHECK((offset + count - 1) >> 6 == offset >> 6);
    (a.d[(offset >> 6) as usize] as u32 >> (offset & 0x3F)) & (((1 as u32) << count) - 1)
}

// SECP256K1_INLINE static unsigned int secp256k1_scalar_get_bits_var(const secp256k1_scalar *a, unsigned int offset, unsigned int count) {
//     VERIFY_CHECK(count < 32);
//     VERIFY_CHECK(offset + count <= 256);
//     if ((offset + count - 1) >> 6 == offset >> 6) {
//         return secp256k1_scalar_get_bits(a, offset, count);
//     } else {
//         VERIFY_CHECK((offset >> 6) + 1 < 4);
//         return ((a->d[offset >> 6] >> (offset & 0x3F)) | (a->d[(offset >> 6) + 1] << (64 - (offset & 0x3F)))) & ((((uint64_t)1) << count) - 1);
//     }
// }

pub fn secp256k1_scalar_get_bits_var(a: &secp256k1_scalar, offset: u32, count: u32) -> u32 {
    // VERIFY_CHECK(count < 32);
    // VERIFY_CHECK(offset + count <= 256);
    if (offset + count - 1) >> 6 == offset >> 6 {
        return secp256k1_scalar_get_bits(a, offset, count);
    }
    // VERIFY_CHECK((offset >> 6) + 1 < 4);
    ((a.d[offset as usize >> 6] as u32 >> (offset & 0x3F)) | ((a.d[(offset as usize >> 6) + 1] as u32) << (64 - (offset & 0x3F)))) & (((1 as u32) << count) - 1)
}

// SECP256K1_INLINE static int secp256k1_scalar_check_overflow(const secp256k1_scalar *a) {
//     int yes = 0;
//     int no = 0;
//     no |= (a->d[3] < SECP256K1_N_3); /* No need for a > check. */
//     no |= (a->d[2] < SECP256K1_N_2);
//     yes |= (a->d[2] > SECP256K1_N_2) & ~no;
//     no |= (a->d[1] < SECP256K1_N_1);
//     yes |= (a->d[1] > SECP256K1_N_1) & ~no;
//     yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
//     return yes;
// }
pub fn secp256k1_scalar_check_overflow(a: &secp256k1_scalar) -> i32 {
    let mut yes = 0;
    let mut no = 0;
    no |= (a.d[3] < SECP256K1_N_3) as i32; /* No need for a > check. */
    no |= (a.d[2] < SECP256K1_N_2) as i32;
    yes |= (a.d[2] > SECP256K1_N_2) as i32 & !no;
    no |= (a.d[1] < SECP256K1_N_1) as i32;
    yes |= (a.d[1] > SECP256K1_N_1) as i32 & !no;
    yes |= (a.d[0] >= SECP256K1_N_0) as i32 & !no;
    return yes;
}

// SECP256K1_INLINE static int secp256k1_scalar_reduce(secp256k1_scalar *r, unsigned int overflow) {
//     uint128_t t;
//     VERIFY_CHECK(overflow <= 1);
//     t = (uint128_t)r->d[0] + overflow * SECP256K1_N_C_0;
//     r->d[0] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
//     t += (uint128_t)r->d[1] + overflow * SECP256K1_N_C_1;
//     r->d[1] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
//     t += (uint128_t)r->d[2] + overflow * SECP256K1_N_C_2;
//     r->d[2] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
//     t += (uint64_t)r->d[3];
//     r->d[3] = t & 0xFFFFFFFFFFFFFFFFULL;
//     return overflow;
// }
pub fn secp256k1_scalar_reduce(r: &mut secp256k1_scalar, overflow: i32) -> i32 {
    let mut t: u128;
    // VERIFY_CHECK(overflow <= 1);
    t = (r.d[0] as u128) + (overflow as u128) * (SECP256K1_N_C_0 as u128);
    r.d[0] = (t & 0xFFFFFFFFFFFFFFFF) as u64; t >>= 64;
    t += (r.d[1] as u128) + (overflow as u128) * (SECP256K1_N_C_1 as u128);
    r.d[1] = (t & 0xFFFFFFFFFFFFFFFF) as u64; t >>= 64;
    t += (r.d[2] as u128) + (overflow as u128) * (SECP256K1_N_C_2 as u128);
    r.d[2] = (t & 0xFFFFFFFFFFFFFFFF) as u64; t >>= 64;
    t += (r.d[3] as u128);
    r.d[3] = (t & 0xFFFFFFFFFFFFFFFF) as u64;
    return overflow;
}

// static int secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
//     int overflow;
//     uint128_t t = (uint128_t)a->d[0] + b->d[0];
//     r->d[0] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
//     t += (uint128_t)a->d[1] + b->d[1];
//     r->d[1] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
//     t += (uint128_t)a->d[2] + b->d[2];
//     r->d[2] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
//     t += (uint128_t)a->d[3] + b->d[3];
//     r->d[3] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
//     overflow = t + secp256k1_scalar_check_overflow(r);
//     VERIFY_CHECK(overflow == 0 || overflow == 1);
//     secp256k1_scalar_reduce(r, overflow);
//     return overflow;
// }
pub fn secp256k1_scalar_add(r: &mut secp256k1_scalar, a: &secp256k1_scalar, b: &secp256k1_scalar) -> i32 {
    let mut overflow: i32;
    let mut t = (a.d[0] as u128) + (b.d[0] as u128);
    r.d[0] = (t & 0xFFFFFFFFFFFFFFFF) as u64; t >>= 64;
    t += (a.d[1] as u128) + (b.d[1] as u128);
    r.d[1] = (t & 0xFFFFFFFFFFFFFFFF) as u64; t >>= 64;
    t += (a.d[2] as u128) + (b.d[2] as u128);
    r.d[2] = (t & 0xFFFFFFFFFFFFFFFF) as u64; t >>= 64;
    t += (a.d[3] as u128) + (b.d[3] as u128);
    r.d[3] = (t & 0xFFFFFFFFFFFFFFFF) as u64; t >>= 64;
    overflow = (t + secp256k1_scalar_check_overflow(r) as u128) as i32;
    // VERIFY_CHECK(overflow == 0 || overflow == 1);
    secp256k1_scalar_reduce(r, overflow);
    return overflow;
}

// static void secp256k1_scalar_cadd_bit(secp256k1_scalar *r, unsigned int bit, int flag) {
//     uint128_t t;
//     VERIFY_CHECK(bit < 256);
//     bit += ((uint32_t) flag - 1) & 0x100;  /* forcing (bit >> 6) > 3 makes this a noop */
//     t = (uint128_t)r->d[0] + (((uint64_t)((bit >> 6) == 0)) << (bit & 0x3F));
//     r->d[0] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
//     t += (uint128_t)r->d[1] + (((uint64_t)((bit >> 6) == 1)) << (bit & 0x3F));
//     r->d[1] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
//     t += (uint128_t)r->d[2] + (((uint64_t)((bit >> 6) == 2)) << (bit & 0x3F));
//     r->d[2] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
//     t += (uint128_t)r->d[3] + (((uint64_t)((bit >> 6) == 3)) << (bit & 0x3F));
//     r->d[3] = t & 0xFFFFFFFFFFFFFFFFULL;
// #ifdef VERIFY
//     VERIFY_CHECK((t >> 64) == 0);
//     VERIFY_CHECK(secp256k1_scalar_check_overflow(r) == 0);
// #endif
// }
pub fn secp256k1_scalar_cadd_bit(r: &mut secp256k1_scalar, mut bit: u32, flag: i32) {
    let mut t: u128;
    // VERIFY_CHECK(bit < 256);
    bit += ((flag - 1) & 0x100) as u32;  /* forcing (bit >> 6) > 3 makes this a noop */
    t = (r.d[0] as u128) + (((((bit >> 6) == 0) as u64)) << (bit & 0x3F)) as u128;
    r.d[0] = (t & 0xFFFFFFFFFFFFFFFF) as u64; t >>= 64;
    t += (r.d[1] as u128) + (((((bit >> 6) == 1) as u64)) << (bit & 0x3F)) as u128;
    r.d[1] = (t & 0xFFFFFFFFFFFFFFFF) as u64; t >>= 64;
    t += (r.d[2] as u128) + (((((bit >> 6) == 2) as u64)) << (bit & 0x3F)) as u128;
    r.d[2] = (t & 0xFFFFFFFFFFFFFFFF) as u64; t >>= 64;
    t += (r.d[3] as u128) + (((((bit >> 6) == 3) as u64)) << (bit & 0x3F)) as u128;
    r.d[3] = (t & 0xFFFFFFFFFFFFFFFF) as u64;
    // #ifdef VERIFY
    // VERIFY_CHECK((t >> 64) == 0);
    // VERIFY_CHECK(secp256k1_scalar_check_overflow(r) == 0);
    // #endif
}


// static void secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
//     int over;
//     r->d[0] = (uint64_t)b32[31] | (uint64_t)b32[30] << 8 | (uint64_t)b32[29] << 16 | (uint64_t)b32[28] << 24 | (uint64_t)b32[27] << 32 | (uint64_t)b32[26] << 40 | (uint64_t)b32[25] << 48 | (uint64_t)b32[24] << 56;
//     r->d[1] = (uint64_t)b32[23] | (uint64_t)b32[22] << 8 | (uint64_t)b32[21] << 16 | (uint64_t)b32[20] << 24 | (uint64_t)b32[19] << 32 | (uint64_t)b32[18] << 40 | (uint64_t)b32[17] << 48 | (uint64_t)b32[16] << 56;
//     r->d[2] = (uint64_t)b32[15] | (uint64_t)b32[14] << 8 | (uint64_t)b32[13] << 16 | (uint64_t)b32[12] << 24 | (uint64_t)b32[11] << 32 | (uint64_t)b32[10] << 40 | (uint64_t)b32[9] << 48 | (uint64_t)b32[8] << 56;
//     r->d[3] = (uint64_t)b32[7] | (uint64_t)b32[6] << 8 | (uint64_t)b32[5] << 16 | (uint64_t)b32[4] << 24 | (uint64_t)b32[3] << 32 | (uint64_t)b32[2] << 40 | (uint64_t)b32[1] << 48 | (uint64_t)b32[0] << 56;
//     over = secp256k1_scalar_reduce(r, secp256k1_scalar_check_overflow(r));
//     if (overflow) {
//         *overflow = over;
//     }
// }
fn secp256k1_scalar_set_b32 (r: &mut secp256k1_scalar, b32: &[u8], overflow: &i32) {
    let mut over: i32;
    r.d[0] = (b32[31] as u64) | (b32[30] as u64) << 8 | (b32[29] as u64) << 16 | (b32[28] as u64) << 24 | (b32[27] as u64) << 32 | (b32[26] as u64) << 40 | (b32[25] as u64) << 48 | (b32[24] as u64) << 56;
    r.d[1] = (b32[23] as u64) | (b32[22] as u64) << 8 | (b32[21] as u64) << 16 | (b32[20] as u64) << 24 | (b32[19] as u64) << 32 | (b32[18] as u64) << 40 | (b32[17] as u64) << 48 | (b32[16] as u64) << 56;
    r.d[2] = (b32[15] as u64) | (b32[14] as u64) << 8 | (b32[13] as u64) << 16 | (b32[12] as u64) << 24 | (b32[11] as u64) << 32 | (b32[10] as u64) << 40 | (b32[9] as u64) << 48 | (b32[8] as u64) << 56;
    r.d[3] = (b32[7] as u64) | (b32[6] as u64) << 8 | (b32[5] as u64) << 16 | (b32[4] as u64) << 24 | (b32[3] as u64) << 32 | (b32[2] as u64) << 40 | (b32[1] as u64) << 48 | (b32[0] as u64) << 56;
    over = secp256k1_scalar_reduce(r, secp256k1_scalar_check_overflow(r));
    if *overflow != 0 {
        *overflow = over;
    }
}

// static void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar* a) {
//     bin[0] = a->d[3] >> 56; bin[1] = a->d[3] >> 48; bin[2] = a->d[3] >> 40; bin[3] = a->d[3] >> 32; bin[4] = a->d[3] >> 24; bin[5] = a->d[3] >> 16; bin[6] = a->d[3] >> 8; bin[7] = a->d[3];
//     bin[8] = a->d[2] >> 56; bin[9] = a->d[2] >> 48; bin[10] = a->d[2] >> 40; bin[11] = a->d[2] >> 32; bin[12] = a->d[2] >> 24; bin[13] = a->d[2] >> 16; bin[14] = a->d[2] >> 8; bin[15] = a->d[2];
//     bin[16] = a->d[1] >> 56; bin[17] = a->d[1] >> 48; bin[18] = a->d[1] >> 40; bin[19] = a->d[1] >> 32; bin[20] = a->d[1] >> 24; bin[21] = a->d[1] >> 16; bin[22] = a->d[1] >> 8; bin[23] = a->d[1];
//     bin[24] = a->d[0] >> 56; bin[25] = a->d[0] >> 48; bin[26] = a->d[0] >> 40; bin[27] = a->d[0] >> 32; bin[28] = a->d[0] >> 24; bin[29] = a->d[0] >> 16; bin[30] = a->d[0] >> 8; bin[31] = a->d[0];
// }
fn secp256k1_scalar_get_b32(bin: &[u8], a: &mut secp256k1_scalar) {
    bin[0] = (a.d[3] >> 56) as u8; bin[1] = (a.d[3] >> 48) as u8; bin[2] = (a.d[3] >> 40) as u8; bin[3] = (a.d[3] >> 32) as u8; bin[4] = (a.d[3] >> 24) as u8; bin[5] = (a.d[3] >> 16) as u8; bin[6] = (a.d[3] >> 8) as u8; bin[7] = a.d[3] as u8;
    bin[8] = (a.d[2] >> 56) as u8; bin[9] = (a.d[2] >> 48) as u8; bin[10] = (a.d[2] >> 40) as u8; bin[11] = (a.d[2] >> 32) as u8; bin[12] = (a.d[2] >> 24) as u8; bin[13] = (a.d[2] >> 16) as u8; bin[14] = (a.d[2] >> 8) as u8; bin[15] = a.d[2] as u8;
    bin[16] = (a.d[1] >> 56) as u8; bin[17] = (a.d[1] >> 48) as u8; bin[18] = (a.d[1] >> 40) as u8; bin[19] = (a.d[1] >> 32) as u8; bin[20] = (a.d[1] >> 24) as u8; bin[21] = (a.d[1] >> 16) as u8; bin[22] = (a.d[1] >> 8) as u8; bin[23] = a.d[1] as u8;
    bin[24] = (a.d[0] >> 56) as u8; bin[25] = (a.d[0] >> 48) as u8; bin[26] = (a.d[0] >> 40) as u8; bin[27] = (a.d[0] >> 32) as u8; bin[28] = (a.d[0] >> 24) as u8; bin[29] = (a.d[0] >> 16) as u8; bin[30] = (a.d[0] >> 8) as u8; bin[31] = a.d[0] as u8;
}


// SECP256K1_INLINE static int secp256k1_scalar_is_zero(const secp256k1_scalar *a) {
//     return (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0;
// }
fn secp256k1_scalar_is_zero(a: &secp256k1_scalar) -> i32 {
    ((a.d[0] | a.d[1] | a.d[2] | a.d[3]) == 0) as i32
}

// static void secp256k1_scalar_negate(secp256k1_scalar *r, const secp256k1_scalar *a) {
//     uint64_t nonzero = 0xFFFFFFFFFFFFFFFFULL * (secp256k1_scalar_is_zero(a) == 0);
//     uint128_t t = (uint128_t)(~a->d[0]) + SECP256K1_N_0 + 1;
//     r->d[0] = t & nonzero; t >>= 64;
//     t += (uint128_t)(~a->d[1]) + SECP256K1_N_1;
//     r->d[1] = t & nonzero; t >>= 64;
//     t += (uint128_t)(~a->d[2]) + SECP256K1_N_2;
//     r->d[2] = t & nonzero; t >>= 64;
//     t += (uint128_t)(~a->d[3]) + SECP256K1_N_3;
//     r->d[3] = t & nonzero;
// }
pub fn secp256k1_scalar_negate(r: &mut secp256k1_scalar, a: &secp256k1_scalar) {
    let mut nonzero = 0xFFFFFFFFFFFFFFFF * (secp256k1_scalar_is_zero(a) == 0) as u64;
    let mut t = (!a.d[0]) + SECP256K1_N_0 + 1;
    r.d[0] = t & nonzero; t >>= 64;
    t += (!a.d[1]) + SECP256K1_N_1;
    r.d[1] = t & nonzero; t >>= 64;
    t += (!a.d[2]) + SECP256K1_N_2;
    r.d[2] = t & nonzero; t >>= 64;
    t += (!a.d[3]) + SECP256K1_N_3;
    r.d[3] = t & nonzero;
}

// SECP256K1_INLINE static int secp256k1_scalar_is_one(const secp256k1_scalar *a) {
//     return ((a->d[0] ^ 1) | a->d[1] | a->d[2] | a->d[3]) == 0;
// }
fn secp256k1_scalar_is_one(a: &secp256k1_scalar) -> i32 {
    (((a.d[0] ^ 1) | a.d[1] | a.d[2] | a.d[3]) == 0) as i32
}

// static int secp256k1_scalar_is_high(const secp256k1_scalar *a) {
//     int yes = 0;
//     int no = 0;
//     no |= (a->d[3] < SECP256K1_N_H_3);
//     yes |= (a->d[3] > SECP256K1_N_H_3) & ~no;
//     no |= (a->d[2] < SECP256K1_N_H_2) & ~yes; /* No need for a > check. */
//     no |= (a->d[1] < SECP256K1_N_H_1) & ~yes;
//     yes |= (a->d[1] > SECP256K1_N_H_1) & ~no;
//     yes |= (a->d[0] > SECP256K1_N_H_0) & ~no;
//     return yes;
// }
pub fn secp256k1_scalar_is_high(a: &secp256k1_scalar) -> i32 {
    let mut yes = 0;
    let mut no = 0;
    no |= (a.d[3] < SECP256K1_N_H_3) as i32;
    yes |= (a.d[3] > SECP256K1_N_H_3) as i32 & !no;
    no |= (a.d[2] < SECP256K1_N_H_2) as i32 & !yes; /* No need for a > check. */
    no |= (a.d[1] < SECP256K1_N_H_1) as i32 & !yes;
    yes |= (a.d[1] > SECP256K1_N_H_1) as i32 & !no;
    yes |= (a.d[0] > SECP256K1_N_H_0) as i32 & !no;
    return yes;
}


// static int secp256k1_scalar_cond_negate(secp256k1_scalar *r, int flag) {
//     /* If we are flag = 0, mask = 00...00 and this is a no-op;
//      * if we are flag = 1, mask = 11...11 and this is identical to secp256k1_scalar_negate */
//     uint64_t mask = !flag - 1;
//     uint64_t nonzero = (secp256k1_scalar_is_zero(r) != 0) - 1;
//     uint128_t t = (uint128_t)(r->d[0] ^ mask) + ((SECP256K1_N_0 + 1) & mask);
//     r->d[0] = t & nonzero; t >>= 64;
//     t += (uint128_t)(r->d[1] ^ mask) + (SECP256K1_N_1 & mask);
//     r->d[1] = t & nonzero; t >>= 64;
//     t += (uint128_t)(r->d[2] ^ mask) + (SECP256K1_N_2 & mask);
//     r->d[2] = t & nonzero; t >>= 64;
//     t += (uint128_t)(r->d[3] ^ mask) + (SECP256K1_N_3 & mask);
//     r->d[3] = t & nonzero;
//     return 2 * (mask == 0) - 1;
// }
fn secp256k1_scalar_cond_negate(r: &mut secp256k1_scalar, flag: i32) -> i32 {
    /* If we are flag = 0, mask = 00...00 and this is a no-op;
     * if we are flag = 1, mask = 11...11 and this is identical to secp256k1_scalar_negate */
    let mut mask: u64 = !flag as u64 - 1;
    let mut nonzero: u64 = (secp256k1_scalar_is_zero(r) != 0) as u64 - 1;
    let mut t: u128 = ((r.d[0] as u128) ^ mask as u128) + ((SECP256K1_N_0 as u128 + 1) & mask as u128);
    r.d[0] = t as u64 & nonzero; t >>= 64;
    t += (r.d[1] ^ mask) as u128 + (SECP256K1_N_1 & mask) as u128;
    r.d[1] = t as u64 & nonzero; t >>= 64;
    t += (r.d[2] ^ mask) as u128 + (SECP256K1_N_2 & mask) as u128;
    r.d[2] = t as u64 & nonzero; t >>= 64;
    t += (r.d[3] ^ mask) as u128 + (SECP256K1_N_3 & mask) as u128;
    r.d[3] = t as u64 & nonzero;
    2 * (mask == 0) as i32 - 1
}


/* Inspired by the macros in OpenSSL's crypto/bn/asm/x86_64-gcc.c. */

/** Add a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
// #define muladd(a,b) { \
//     uint64_t tl, th; \
//     { \
//         uint128_t t = (uint128_t)a * b; \
//         th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
//         tl = t; \
//     } \
//     c0 += tl;                 /* overflow is handled on the next line */ \
//     th += (c0 < tl);          /* at most 0xFFFFFFFFFFFFFFFF */ \
//     c1 += th;                 /* overflow is handled on the next line */ \
//     c2 += (c1 < th);          /* never overflows by contract (verified in the next line) */ \
//     VERIFY_CHECK((c1 >= th) || (c2 != 0)); \
// }

macro_rules! muladd {
    ($a:expr, $b:expr, $c0:expr, $c1:expr, $c2:expr) => {{
        let mut tl: u64;
        let mut th: u64;
        {
            let t = ($a as u128) * ($b as u128);
            th = (t >> 64) as u64;
            tl = t as u64;
        }
        $c0 += tl;
        th += ($c0 < tl) as u64;
        $c1 += th;
        todo!();
        //$c2 += ($c1 < th);
        //VERIFY_CHECK(($c1 >= th) || ($c2 != 0));
    }}
}

/** Add a*b to the number defined by (c0,c1). c1 must never overflow. */
// #define muladd_fast(a,b) { \
//     uint64_t tl, th; \
//     { \
//         uint128_t t = (uint128_t)a * b; \
//         th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
//         tl = t; \
//     } \
//     c0 += tl;                 /* overflow is handled on the next line */ \
//     th += (c0 < tl);          /* at most 0xFFFFFFFFFFFFFFFF */ \
//     c1 += th;                 /* never overflows by contract (verified in the next line) */ \
//     VERIFY_CHECK(c1 >= th); \
// }
macro_rules! muladd_fast {
    ($a:expr, $b:expr, $c0:expr, $c1:expr) => {{
        let mut tl: u64;
        let mut th: u64;
        {
            let t = ($a as u128) * ($b as u128);
            th = (t >> 64) as u64;
            tl = t as u64;
        }
        $c0 += tl;
        th += ($c0 < tl) as u64;
        $c1 += th;
        //VERIFY_CHECK($c1 >= th);
    }}
}


/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
// #define sumadd(a) { \
//     unsigned int over; \
//     c0 += (a);                  /* overflow is handled on the next line */ \
//     over = (c0 < (a));         \
//     c1 += over;                 /* overflow is handled on the next line */ \
//     c2 += (c1 < over);          /* never overflows by contract */ \
// }
macro_rules! sumadd {
    ($a:expr, $c0:expr, $c1:expr, $c2:expr) => {{
        $c0 += ($a);
        let over = ($c0 < ($a)) as u64;
        $c1 += over;
        $c2 += ($c1 < over) as u64;
    }}
}


/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
// #define sumadd_fast(a) { \
//     c0 += (a);                 /* overflow is handled on the next line */ \
//     c1 += (c0 < (a));          /* never overflows by contract (verified the next line) */ \
//     VERIFY_CHECK((c1 != 0) | (c0 >= (a))); \
//     VERIFY_CHECK(c2 == 0); \
// }
macro_rules! sumadd_fast {
    ($a:expr, $c0:expr, $c1:expr, $c2:expr) => {{
        $c0 += ($a) as u64;
        $c1 += ($c0 < ($a)) as u64;
        //VERIFY_CHECK(($c1 != 0) | ($c0 >= ($a)));
        //VERIFY_CHECK($c2 == 0);
    }}
}


/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. */
// #define extract(n) { \
//     (n) = c0; \
//     c0 = c1; \
//     c1 = c2; \
//     c2 = 0; \
// }
macro_rules! extract {
    ($n:expr, $c0:expr, $c1:expr, $c2:expr) => {{
        $n = $c0;
        $c0 = $c1;
        $c1 = $c2;
        $c2 = 0;
    }}
}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. c2 is required to be zero. */
// #define extract_fast(n) { \
//     (n) = c0; \
//     c0 = c1; \
//     c1 = 0; \
//     VERIFY_CHECK(c2 == 0); \
// }
macro_rules! extract_fast {
    ($n:expr, $c0:expr, $c1:expr, $c2:expr) => {{
        $n = $c0;
        $c0 = $c1;
        $c1 = 0;
        //VERIFY_CHECK($c2 == 0);
    }}
}

// static void secp256k1_scalar_reduce_512(secp256k1_scalar *r, const uint64_t *l) {
//     uint128_t c;
//     uint64_t c0, c1, c2;
//     uint64_t n0 = l[4], n1 = l[5], n2 = l[6], n3 = l[7];
//     uint64_t m0, m1, m2, m3, m4, m5;
//     uint32_t m6;
//     uint64_t p0, p1, p2, p3;
//     uint32_t p4;

//     /* Reduce 512 bits into 385. */
//     /* m[0..6] = l[0..3] + n[0..3] * SECP256K1_N_C. */
//     c0 = l[0]; c1 = 0; c2 = 0;
//     muladd_fast(n0, SECP256K1_N_C_0);
//     extract_fast(m0);
//     sumadd_fast(l[1]);
//     muladd(n1, SECP256K1_N_C_0);
//     muladd(n0, SECP256K1_N_C_1);
//     extract(m1);
//     sumadd(l[2]);
//     muladd(n2, SECP256K1_N_C_0);
//     muladd(n1, SECP256K1_N_C_1);
//     sumadd(n0);
//     extract(m2);
//     sumadd(l[3]);
//     muladd(n3, SECP256K1_N_C_0);
//     muladd(n2, SECP256K1_N_C_1);
//     sumadd(n1);
//     extract(m3);
//     muladd(n3, SECP256K1_N_C_1);
//     sumadd(n2);
//     extract(m4);
//     sumadd_fast(n3);
//     extract_fast(m5);
//     VERIFY_CHECK(c0 <= 1);
//     m6 = c0;

//     /* Reduce 385 bits into 258. */
//     /* p[0..4] = m[0..3] + m[4..6] * SECP256K1_N_C. */
//     c0 = m0; c1 = 0; c2 = 0;
//     muladd_fast(m4, SECP256K1_N_C_0);
//     extract_fast(p0);
//     sumadd_fast(m1);
//     muladd(m5, SECP256K1_N_C_0);
//     muladd(m4, SECP256K1_N_C_1);
//     extract(p1);
//     sumadd(m2);
//     muladd(m6, SECP256K1_N_C_0);
//     muladd(m5, SECP256K1_N_C_1);
//     sumadd(m4);
//     extract(p2);
//     sumadd_fast(m3);
//     muladd_fast(m6, SECP256K1_N_C_1);
//     sumadd_fast(m5);
//     extract_fast(p3);
//     p4 = c0 + m6;
//     VERIFY_CHECK(p4 <= 2);

//     /* Reduce 258 bits into 256. */
//     /* r[0..3] = p[0..3] + p[4] * SECP256K1_N_C. */
//     c = p0 + (uint128_t)SECP256K1_N_C_0 * p4;
//     r->d[0] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
//     c += p1 + (uint128_t)SECP256K1_N_C_1 * p4;
//     r->d[1] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
//     c += p2 + (uint128_t)p4;
//     r->d[2] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
//     c += p3;
//     r->d[3] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
//
//     /* Final reduction of r. */
//     secp256k1_scalar_reduce(r, c + secp256k1_scalar_check_overflow(r));
// }
fn secp256k1_scalar_reduce_512(r: &mut secp256k1_scalar, l: &[u64; 8]) {
    let mut c: u128;
    let mut c0: u64;
    let mut c1: u64;
    let mut c2: u64;
    let mut n0: u64 = l[4];
    let mut n1: u64 = l[5];
    let mut n2: u64 = l[6];
    let mut n3: u64 = l[7];
    let mut m0: u64;
    let mut m1: u64;
    let mut m2: u64;
    let mut m3: u64;
    let mut m4: u64;
    let mut m5: u64;
    let mut m6: u64;
    let mut p0: u64;
    let mut p1: u64;
    let mut p2: u64;
    let mut p3: u64;
    let mut p4: u32;

    /* Reduce 512 bits into 385. */
    /* m[0..6] = l[0..3] + n[0..3] * SECP256K1_N_C. */
    c0 = l[0]; c1 = 0; c2 = 0;
    muladd_fast!(n0, SECP256K1_N_C_0, c0, c1);
    extract_fast!(m0, c0, c1, c2);
    sumadd_fast!(l[1], c0, c1, c2);
    muladd!(n1, SECP256K1_N_C_0, c0, c1, c2);
    muladd!(n0, SECP256K1_N_C_1, c0, c1, c2);
    extract!(m1, c0, c1, c2);
    sumadd!(l[2], c0, c1, c2);
    muladd!(n2, SECP256K1_N_C_0, c0, c1, c2);
    muladd!(n1, SECP256K1_N_C_1, c0, c1, c2);
    sumadd!(n0, c0, c1, c2);
    extract!(m2, c0, c1, c2);
    sumadd!(l[3], c0, c1, c2);
    muladd!(n3, SECP256K1_N_C_0, c0, c1, c2);
    muladd!(n2, SECP256K1_N_C_1, c0, c1, c2);
    sumadd!(n1, c0, c1, c2);
    extract!(m3, c0, c1, c2);
    muladd!(n3, SECP256K1_N_C_1, c0, c1, c2);
    sumadd!(n2, c0, c1, c2);
    extract!(m4, c0, c1, c2);
    sumadd_fast!(n3, c0, c1, c2);
    extract_fast!(m5, c0, c1, c2);
    //VERIFY_CHECK(c0 <= 1);
    m6 = c0;

    /* Reduce 385 bits into 258. */
    /* p[0..4] = m[0..3] + m[4..6] * SECP256K1_N_C. */
    c0 = m0; c1 = 0; c2 = 0;
    muladd_fast!(m4, SECP256K1_N_C_0, c0, c1);
    extract_fast!(p0, c0, c1, c2);
    sumadd_fast!(m1, c0, c1, c2);
    muladd!(m5, SECP256K1_N_C_0, c0, c1, c2);
    muladd!(m4, SECP256K1_N_C_1, c0, c1, c2);
    extract!(p1, c0, c1, c2);
    sumadd!(m2, c0, c1, c2);
    muladd!(m6, SECP256K1_N_C_0, c0, c1, c2);
    muladd!(m5, SECP256K1_N_C_1, c0, c1, c2);
    sumadd!(m4, c0, c1, c2);
    extract!(p2, c0, c1, c2);
    sumadd_fast!(m3, c0, c1, c2);
    muladd_fast!(m6, SECP256K1_N_C_1, c0, c1);
    sumadd_fast!(m5 as u64, c0, c1, c2);
    extract_fast!(p3, c0, c1, c2);
    p4 = (c0 + m6) as u32;
    //VERIFY_CHECK(p4 <= 2);

    /* Reduce 258 bits into 256. */
    /* r[0..3] = p[0..3] + p[4] * SECP256K1_N_C. */
    c = p0 as u128 + (SECP256K1_N_C_0 as u128) * (p4 as u128);
    r.d[0] = c as u64; c >>= 64;
    c += p1 as u128 + (SECP256K1_N_C_1 as u128) * (p4 as u128);
    r.d[1] = c as u64; c >>= 64;
    c += p2 as u128 + p4 as u128;
    r.d[2] = c as u64; c >>= 64;
    c += p3 as u128;
    r.d[3] = c as u64; c >>= 64;

    /* Final reduction of r. */
    secp256k1_scalar_reduce(r, (c as i32 + secp256k1_scalar_check_overflow(r)) as i32);
}


// static void secp256k1_scalar_mul_512(uint64_t l[8], const secp256k1_scalar *a, const secp256k1_scalar *b) {

//     /* 160 bit accumulator. */
//     uint64_t c0 = 0, c1 = 0;
//     uint32_t c2 = 0;

//     /* l[0..7] = a[0..3] * b[0..3]. */
//     muladd_fast(a->d[0], b->d[0]);
//     extract_fast(l[0]);
//     muladd(a->d[0], b->d[1]);
//     muladd(a->d[1], b->d[0]);
//     extract(l[1]);
//     muladd(a->d[0], b->d[2]);
//     muladd(a->d[1], b->d[1]);
//     muladd(a->d[2], b->d[0]);
//     extract(l[2]);
//     muladd(a->d[0], b->d[3]);
//     muladd(a->d[1], b->d[2]);
//     muladd(a->d[2], b->d[1]);
//     muladd(a->d[3], b->d[0]);
//     extract(l[3]);
//     muladd(a->d[1], b->d[3]);
//     muladd(a->d[2], b->d[2]);
//     muladd(a->d[3], b->d[1]);
//     extract(l[4]);
//     muladd(a->d[2], b->d[3]);
//     muladd(a->d[3], b->d[2]);
//     extract(l[5]);
//     muladd_fast(a->d[3], b->d[3]);
//     extract_fast(l[6]);
//     VERIFY_CHECK(c1 == 0);
//     l[7] = c0;
// }

fn secp256k1_scalar_mul_512(l: &mut [u64; 8], a: &secp256k1_scalar, b: &secp256k1_scalar) {
    /* 160 bit accumulator. */
    let mut c0: u64 = 0;
    let mut c1: u64 = 0;
    let mut c2: u64 = 0;

    /* l[0..7] = a[0..3] * b[0..3]. */
    muladd_fast!(a.d[0], b.d[0], c0, c1);
    extract_fast!(l[0], c0, c1, c2);
    muladd!(a.d[0], b.d[1], c0, c1, c2);
    muladd!(a.d[1], b.d[0], c0, c1, c2);
    extract!(l[1], c0, c1, c2);
    muladd!(a.d[0], b.d[2], c0, c1, c2);
    muladd!(a.d[1], b.d[1], c0, c1, c2);
    muladd!(a.d[2], b.d[0], c0, c1, c2);
    extract!(l[2], c0, c1, c2);
    muladd!(a.d[0], b.d[3], c0, c1, c2);
    muladd!(a.d[1], b.d[2], c0, c1, c2);
    muladd!(a.d[2], b.d[1], c0, c1, c2);
    muladd!(a.d[3], b.d[0], c0, c1, c2);
    extract!(l[3], c0, c1, c2);
    muladd!(a.d[1], b.d[3], c0, c1, c2);
    muladd!(a.d[2], b.d[2], c0, c1, c2);
    muladd!(a.d[3], b.d[1], c0, c1, c2);
    extract!(l[4], c0, c1, c2);
    muladd!(a.d[2], b.d[3], c0, c1, c2);
    muladd!(a.d[3], b.d[2], c0, c1, c2);
    extract!(l[5], c0, c1, c2);
    muladd_fast!(a.d[3], b.d[3], c0, c1);
    extract_fast!(l[6], c0, c1, c2);
    //VERIFY_CHECK(c1 == 0);
    l[7] = c0;
}


// #undef sumadd
// #undef sumadd_fast
// #undef muladd
// #undef muladd_fast
// #undef extract
// #undef extract_fast

// static void secp256k1_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
//     uint64_t l[8];
//     secp256k1_scalar_mul_512(l, a, b);
//     secp256k1_scalar_reduce_512(r, l);
// }
pub fn secp256k1_scalar_mul(r: &mut secp256k1_scalar, a: &secp256k1_scalar, b: &secp256k1_scalar) {
    let mut l: [u64; 8] = [0; 8];
    secp256k1_scalar_mul_512(&mut l, a, b);
    secp256k1_scalar_reduce_512(r, &l);
}


// static int secp256k1_scalar_shr_int(secp256k1_scalar *r, int n) {
//     int ret;
//     VERIFY_CHECK(n > 0);
//     VERIFY_CHECK(n < 16);
//     ret = r->d[0] & ((1 << n) - 1);
//     r->d[0] = (r->d[0] >> n) + (r->d[1] << (64 - n));
//     r->d[1] = (r->d[1] >> n) + (r->d[2] << (64 - n));
//     r->d[2] = (r->d[2] >> n) + (r->d[3] << (64 - n));
//     r->d[3] = (r->d[3] >> n);
//     return ret;
// }
fn secp256k1_scalar_shr_int(r: &mut secp256k1_scalar, n: i32) -> i32 {
    let mut ret: i32;
    //VERIFY_CHECK(n > 0);
    //VERIFY_CHECK(n < 16);
    ret = (r.d[0] & ((1 << n) - 1)) as i32;
    r.d[0] = (r.d[0] >> n) + (r.d[1] << (64 - n));
    r.d[1] = (r.d[1] >> n) + (r.d[2] << (64 - n));
    r.d[2] = (r.d[2] >> n) + (r.d[3] << (64 - n));
    r.d[3] = (r.d[3] >> n);
    return ret;
}

// static void secp256k1_scalar_split_128(secp256k1_scalar *r1, secp256k1_scalar *r2, const secp256k1_scalar *k) {
//     r1->d[0] = k->d[0];
//     r1->d[1] = k->d[1];
//     r1->d[2] = 0;
//     r1->d[3] = 0;
//     r2->d[0] = k->d[2];
//     r2->d[1] = k->d[3];
//     r2->d[2] = 0;
//     r2->d[3] = 0;
// }
pub fn secp256k1_scalar_split_128(r1: &mut secp256k1_scalar, r2: &mut secp256k1_scalar, k: &secp256k1_scalar) {
    r1.d[0] = k.d[0];
    r1.d[1] = k.d[1];
    r1.d[2] = 0;
    r1.d[3] = 0;
    r2.d[0] = k.d[2];
    r2.d[1] = k.d[3];
    r2.d[2] = 0;
    r2.d[3] = 0;
}

// SECP256K1_INLINE static int secp256k1_scalar_eq(const secp256k1_scalar *a, const secp256k1_scalar *b) {
//     return ((a->d[0] ^ b->d[0]) | (a->d[1] ^ b->d[1]) | (a->d[2] ^ b->d[2]) | (a->d[3] ^ b->d[3])) == 0;
// }
fn secp256k1_scalar_eq(a: &secp256k1_scalar, b: &secp256k1_scalar) -> i32 {
    (((a.d[0] ^ b.d[0]) | (a.d[1] ^ b.d[1]) | (a.d[2] ^ b.d[2]) | (a.d[3] ^ b.d[3])) == 0) as i32
}

// SECP256K1_INLINE static void secp256k1_scalar_mul_shift_var(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b, unsigned int shift) {
//     uint64_t l[8];
//     unsigned int shiftlimbs;
//     unsigned int shiftlow;
//     unsigned int shifthigh;
//     VERIFY_CHECK(shift >= 256);
//     secp256k1_scalar_mul_512(l, a, b);
//     shiftlimbs = shift >> 6;
//     shiftlow = shift & 0x3F;
//     shifthigh = 64 - shiftlow;
//     r->d[0] = shift < 512 ? (l[0 + shiftlimbs] >> shiftlow | (shift < 448 && shiftlow ? (l[1 + shiftlimbs] << shifthigh) : 0)) : 0;
//     r->d[1] = shift < 448 ? (l[1 + shiftlimbs] >> shiftlow | (shift < 384 && shiftlow ? (l[2 + shiftlimbs] << shifthigh) : 0)) : 0;
//     r->d[2] = shift < 384 ? (l[2 + shiftlimbs] >> shiftlow | (shift < 320 && shiftlow ? (l[3 + shiftlimbs] << shifthigh) : 0)) : 0;
//     r->d[3] = shift < 320 ? (l[3 + shiftlimbs] >> shiftlow) : 0;
//     secp256k1_scalar_cadd_bit(r, 0, (l[(shift - 1) >> 6] >> ((shift - 1) & 0x3f)) & 1);
// }
pub fn secp256k1_scalar_mul_shift_var(r: &mut secp256k1_scalar, a: &secp256k1_scalar, b: &secp256k1_scalar, shift: u32) {
    let mut l: [u64; 8] = [0; 8];
    let mut shiftlimbs: u32;
    let mut shiftlow: u32;
    let mut shifthigh: u32;
    //VERIFY_CHECK(shift >= 256);
    secp256k1_scalar_mul_512(&mut l, a, b);
    shiftlimbs = shift >> 6;
    shiftlow = shift & 0x3F;
    shifthigh = 64 - shiftlow;
    r.d[0] = if shift < 512 { (l[0 + shiftlimbs as usize] >> shiftlow | (shift < 448 && shiftlow != 0) as u64 * (l[1 + shiftlimbs as usize] << shifthigh)) } else { 0 };
    r.d[1] = if shift < 448 { (l[1 + shiftlimbs as usize] >> shiftlow | (shift < 384 && shiftlow != 0) as u64 * (l[2 + shiftlimbs as usize] << shifthigh)) } else { 0 };
    r.d[2] = if shift < 384 { (l[2 + shiftlimbs as usize] >> shiftlow | (shift < 320 && shiftlow != 0) as u64 * (l[3 + shiftlimbs as usize] << shifthigh)) } else { 0 };
    r.d[3] = if shift < 320 { (l[3 + shiftlimbs as usize] >> shiftlow) } else { 0 };
    secp256k1_scalar_cadd_bit(r, 0, (l[((shift - 1) >> 6) as usize] >> ((shift - 1) & 0x3f)) as i32 & 1);
}

// static SECP256K1_INLINE void secp256k1_scalar_cmov(secp256k1_scalar *r, const secp256k1_scalar *a, int flag) {
//     uint64_t mask0, mask1;
//     VG_CHECK_VERIFY(r->d, sizeof(r->d));
//     mask0 = flag + ~((uint64_t)0);
//     mask1 = ~mask0;
//     r->d[0] = (r->d[0] & mask0) | (a->d[0] & mask1);
//     r->d[1] = (r->d[1] & mask0) | (a->d[1] & mask1);
//     r->d[2] = (r->d[2] & mask0) | (a->d[2] & mask1);
//     r->d[3] = (r->d[3] & mask0) | (a->d[3] & mask1);
// }
pub fn secp256k1_scalar_cmov(r: &mut secp256k1_scalar, a: &secp256k1_scalar, flag: i32) {
    let mut mask0: u64;
    let mut mask1: u64;
    //VG_CHECK_VERIFY(r.d, std::mem::size_of_val(&r.d));
    mask0 = flag as u64 + !((0 as u64) as u64);
    mask1 = !mask0;
    r.d[0] = (r.d[0] & mask0) | (a.d[0] & mask1);
    r.d[1] = (r.d[1] & mask0) | (a.d[1] & mask1);
    r.d[2] = (r.d[2] & mask0) | (a.d[2] & mask1);
    r.d[3] = (r.d[3] & mask0) | (a.d[3] & mask1);
}


// static void secp256k1_scalar_from_signed62(secp256k1_scalar *r, const secp256k1_modinv64_signed62 *a) {
//     const uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];

//     /* The output from secp256k1_modinv64{_var} should be normalized to range [0,modulus), and
//      * have limbs in [0,2^62). The modulus is < 2^256, so the top limb must be below 2^(256-62*4).
//      */
//     VERIFY_CHECK(a0 >> 62 == 0);
//     VERIFY_CHECK(a1 >> 62 == 0);
//     VERIFY_CHECK(a2 >> 62 == 0);
//     VERIFY_CHECK(a3 >> 62 == 0);
//     VERIFY_CHECK(a4 >> 8 == 0);

//     r->d[0] = a0      | a1 << 62;
//     r->d[1] = a1 >> 2 | a2 << 60;
//     r->d[2] = a2 >> 4 | a3 << 58;
//     r->d[3] = a3 >> 6 | a4 << 56;

// #ifdef VERIFY
//     VERIFY_CHECK(secp256k1_scalar_check_overflow(r) == 0);
// #endif
// }
fn secp256k1_scalar_from_signed62(r: &mut secp256k1_scalar, a: &secp256k1_modinv64_signed62) {
    let a0: u64 = a.v[0] as u64;
    let a1: u64 = a.v[1] as u64;
    let a2: u64 = a.v[2] as u64;
    let a3: u64 = a.v[3] as u64;
    let a4: u64 = a.v[4] as u64;

    /* The output from secp256k1_modinv64{_var} should be normalized to range [0,modulus), and
     * have limbs in [0,2^62). The modulus is < 2^256, so the top limb must be below 2^(256-62*4).
     */
    // VERIFY_CHECK(a0 >> 62 == 0);
    // VERIFY_CHECK(a1 >> 62 == 0);
    // VERIFY_CHECK(a2 >> 62 == 0);
    // VERIFY_CHECK(a3 >> 62 == 0);
    // VERIFY_CHECK(a4 >> 8 == 0);

    r.d[0] = a0      | a1 << 62;
    r.d[1] = a1 >> 2 | a2 << 60;
    r.d[2] = a2 >> 4 | a3 << 58;
    r.d[3] = a3 >> 6 | a4 << 56;

    //VERIFY_CHECK(secp256k1_scalar_check_overflow(r) == 0);
}


// static void secp256k1_scalar_to_signed62(secp256k1_modinv64_signed62 *r, const secp256k1_scalar *a) {
//     const uint64_t M62 = UINT64_MAX >> 2;
//     const uint64_t a0 = a->d[0], a1 = a->d[1], a2 = a->d[2], a3 = a->d[3];

// #ifdef VERIFY
//     VERIFY_CHECK(secp256k1_scalar_check_overflow(a) == 0);
// #endif

//     r->v[0] =  a0                   & M62;
//     r->v[1] = (a0 >> 62 | a1 <<  2) & M62;
//     r->v[2] = (a1 >> 60 | a2 <<  4) & M62;
//     r->v[3] = (a2 >> 58 | a3 <<  6) & M62;
//     r->v[4] =  a3 >> 56;
// }
fn secp256k1_scalar_to_signed62(r: &mut secp256k1_modinv64_signed62, a: &secp256k1_scalar) {
    let M62: u64 = (0 as u64) >> 2;
    let a0: u64 = a.d[0];
    let a1: u64 = a.d[1];
    let a2: u64 = a.d[2];
    let a3: u64 = a.d[3];

    //VERIFY_CHECK(secp256k1_scalar_check_overflow(a) == 0);

    r.v[0] =  (a0                   & M62) as i64;
    r.v[1] = ((a0 >> 62 | a1 <<  2) & M62) as i64;
    r.v[2] = ((a1 >> 60 | a2 <<  4) & M62) as i64;
    r.v[3] = ((a2 >> 58 | a3 <<  6) & M62) as i64;
    r.v[4] =  (a3 >> 56) as i64;
}


// static const secp256k1_modinv64_modinfo secp256k1_const_modinfo_scalar = {
//     {{0x3FD25E8CD0364141LL, 0x2ABB739ABD2280EELL, -0x15LL, 0, 256}},
//     0x34F20099AA774EC1LL
// };
const secp256k1_const_modinfo_scalar: secp256k1_modinv64_modinfo = secp256k1_modinv64_modinfo {
    modulus: secp256k1_modinv64_signed62 {
        v: [0x3FD25E8CD0364141, 0x2ABB739ABD2280EE, -0x15, 0, 256]
    },
    modulus_inv62: 0x34F20099AA774EC1
};

// static void secp256k1_scalar_inverse(secp256k1_scalar *r, const secp256k1_scalar *x) {
//     secp256k1_modinv64_signed62 s;
// #ifdef VERIFY
//     int zero_in = secp256k1_scalar_is_zero(x);
// #endif
//     secp256k1_scalar_to_signed62(&s, x);
//     secp256k1_modinv64(&s, &secp256k1_const_modinfo_scalar);
//     secp256k1_scalar_from_signed62(r, &s);

// #ifdef VERIFY
//     VERIFY_CHECK(secp256k1_scalar_is_zero(r) == zero_in);
// #endif
// }
fn secp256k1_scalar_inverse(r: &mut secp256k1_scalar, x: &secp256k1_scalar) {
    let mut s: secp256k1_modinv64_signed62;
    let zero_in: i32;
    secp256k1_scalar_to_signed62(&mut s, x);
    secp256k1_modinv64(&mut s, &secp256k1_const_modinfo_scalar);
    secp256k1_scalar_from_signed62(r, &s);

    //VERIFY_CHECK(secp256k1_scalar_is_zero(r) == zero_in);
}

// static void secp256k1_scalar_inverse_var(secp256k1_scalar *r, const secp256k1_scalar *x) {
//     secp256k1_modinv64_signed62 s;
// #ifdef VERIFY
//     int zero_in = secp256k1_scalar_is_zero(x);
// #endif
//     secp256k1_scalar_to_signed62(&s, x);
//     secp256k1_modinv64_var(&s, &secp256k1_const_modinfo_scalar);
//     secp256k1_scalar_from_signed62(r, &s);

// #ifdef VERIFY
//     VERIFY_CHECK(secp256k1_scalar_is_zero(r) == zero_in);
// #endif
// }
fn secp256k1_scalar_inverse_var(r: &mut secp256k1_scalar, x: &secp256k1_scalar) {
    let mut s: secp256k1_modinv64_signed62;
    let zero_in: i32;
    secp256k1_scalar_to_signed62(&mut s, x);
    secp256k1_modinv64_var(&mut s, &secp256k1_const_modinfo_scalar);
    secp256k1_scalar_from_signed62(r, &s);

    //VERIFY_CHECK(secp256k1_scalar_is_zero(r) == zero_in);
}

// SECP256K1_INLINE static int secp256k1_scalar_is_even(const secp256k1_scalar *a) {
//     return !(a->d[0] & 1);
// }
pub fn secp256k1_scalar_is_even(a: &secp256k1_scalar) -> i32 {
    !(a.d[0] & 1) as i32
}
