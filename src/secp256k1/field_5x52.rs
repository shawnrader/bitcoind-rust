/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/
 #![allow(warnings)]
//use std::arch::x86_64::_MM_MANT_NORM_P5_2;

//use super::SECP256K1_FLAGS_TYPE_COMPRESSION;

use super::field_5x52_int128::{secp256k1_fe_mul_inner, secp256k1_fe_sqr_inner};
use crate::secp256k1::modinv64::*;

pub struct secp256k1_fe {
     /* X = sum(i=0..4, n[i]*2^(i*52)) mod p
      * where p = 2^256 - 0x1000003D1
      */
    pub n : [u64; 5],

#[cfg(feature = "verify")]
    magnitude: i32,
#[cfg(feature = "verify")]
    normalized: i32,
}

impl secp256k1_fe {
    pub fn new() -> secp256k1_fe {
        secp256k1_fe {
            n: [0, 0, 0, 0, 0],
            #[cfg(feature = "verify")]
            magnitude: 0,
            #[cfg(feature = "verify")]
            normalized: 0,
        }
    }
}
 
 /* Unpacks a constant into a overlapping multi-limbed FE element. */
 fn SECP256K1_FE_CONST_INNER(d7: u64, d6: u64, d5: u64, d4: u64, d3: u64, d2: u64, d1: u64, d0: u64) -> [u64; 5] {
    [(d0) | ((d1 & 0xFFFFF_u64) << 32), 
    (d1 >> 20) | (d2 << 12) | ((d3 & 0xFFu64) << 44),
    (d3 >> 8) | ((d4 & 0xFFFFFFF_u64) << 24),
    (d4 >> 28) | (d5 << 4) | ((d6 & 0xFFFF_u64) << 36),
    (d6 >> 16) | (d7 << 16)]
 }
 
#[cfg(feature = "verify")]
pub fn SECP256K1_FE_CONST(d7: u64, d6: u64, d5: u64, d4: u64, d3: u64, d2: u64, d1: u64, d0: u64) -> secp256k1_fe {
    secp256k1_fe { 
        n: SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)),
        magnitude: 1,
        normalized: 1
    }
}
 
#[cfg(not (feature = "verify"))]
pub fn SECP256K1_FE_CONST(d7: u32, d6: u32, d5: u32, d4: u32, d3: u32, d2: u32, d1: u32, d0: u32) -> secp256k1_fe {
    secp256k1_fe { 
        n: SECP256K1_FE_CONST_INNER(d7 as u64, d6 as u64, d5 as u64, d4 as u64, d3 as u64, d2 as u64, d1 as u64, d0 as u64)
    }
}

pub struct secp256k1_fe_storage {
    pub n: [u64; 4],
}

impl secp256k1_fe_storage {
    pub fn copy_from_u8slice(&mut self, slice: &[u8]) {
        self.n[0] = slice[0] as u64
            | ((slice[1] as u64) << 8)
            | ((slice[2] as u64) << 16)
            | ((slice[3] as u64) << 24)
            | ((slice[4] as u64) << 32)
            | ((slice[5] as u64) << 40)
            | ((slice[6] as u64) << 48)
            | ((slice[7]) as u64) << 56;
        self.n[1] = slice[8] as u64
            | ((slice[9] as u64) << 8)
            | ((slice[10] as u64) << 16)
            | ((slice[11] as u64) << 24)
            | ((slice[12] as u64) << 32)
            | ((slice[13] as u64) << 40)
            | ((slice[14] as u64) << 48)
            | ((slice[15] as u64) << 56);
        self.n[2] = slice[16] as u64
            | ((slice[17] as u64) << 8)
            | ((slice[18] as u64) << 16)
            | ((slice[19] as u64) << 24)
            | ((slice[20] as u64) << 32)
            | ((slice[21] as u64) << 40)
            | ((slice[22] as u64) << 48)
            | ((slice[23] as u64) << 56);
        self.n[3] = slice[24] as u64
            | ((slice[25] as u64) << 8)
            | ((slice[26] as u64) << 16)
            | ((slice[27] as u64) << 24)
            | ((slice[28] as u64) << 32)
            | ((slice[29] as u64) << 40)
            | ((slice[30] as u64) << 48)
            | ((slice[31] as u64) << 56);
    }

    pub fn to_slice(self) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = self.n[0] as u8 & 0xFF;
        r[1] = (self.n[0] >> 8) as u8 & 0xFF;
        r[2] = (self.n[0] >> 16) as u8 & 0xFF;
        r[3] = (self.n[0] >> 24) as u8 & 0xFF;
        r[4] = (self.n[0] >> 32) as u8 & 0xFF;
        r[5] = (self.n[0] >> 40) as u8 & 0xFF;
        r[6] = (self.n[0] >> 48) as u8 & 0xFF;
        r[7] = (self.n[0] >> 56) as u8 & 0xFF;
        r[8] = self.n[1] as u8 & 0xFF;
        r[9] = (self.n[1] >> 8) as u8 & 0xFF;
        r[10] = (self.n[1] >> 16) as u8 & 0xFF;
        r[11] = (self.n[1] >> 24) as u8 & 0xFF;
        r[12] = (self.n[1] >> 32) as u8 & 0xFF;
        r[13] = (self.n[1] >> 40) as u8 & 0xFF;
        r[14] = (self.n[1] >> 48) as u8 & 0xFF;
        r[15] = (self.n[1] >> 56) as u8 & 0xFF;
        r[16] = self.n[2] as u8 & 0xFF;
        r[17] = (self.n[2] >> 8) as u8 & 0xFF;
        r[18] = (self.n[2] >> 16) as u8 & 0xFF;
        r[19] = (self.n[2] >> 24) as u8 & 0xFF;
        r[20] = (self.n[2] >> 32) as u8 & 0xFF;
        r[21] = (self.n[2] >> 40) as u8 & 0xFF;
        r[22] = (self.n[2] >> 48) as u8 & 0xFF;
        r[23] = (self.n[2] >> 56) as u8 & 0xFF;
        r[24] = self.n[3] as u8 & 0xFF;
        r[25] = (self.n[3] >> 8) as u8 & 0xFF;
        r[26] = (self.n[3] >> 16) as u8 & 0xFF;
        r[27] = (self.n[3] >> 24) as u8 & 0xFF;
        r[28] = (self.n[3] >> 32) as u8 & 0xFF;
        r[29] = (self.n[3] >> 40) as u8 & 0xFF;
        r[30] = (self.n[3] >> 48) as u8 & 0xFF;
        r[31] = (self.n[3] >> 56) as u8 & 0xFF;
        r
    }
}
 
pub fn SECP256K1_FE_STORAGE_CONST(d7: u64, d6: u64, d5: u64, d4: u64, d3: u64, d2: u64, d1: u64, d0: u64) -> secp256k1_fe_storage {
    secp256k1_fe_storage {
        n : [(d0) | ((d1 as u64) << 32),
             (d2) | ((d3 as u64) << 32),
             (d4) | ((d5 as u64) << 32),
             (d6) | ((d7 as u64) << 32),
        ]
    }
}

// #[macro_export] 
// macro_rules! SECP256K1_FE_STORAGE_CONST {
//     ($d0:expr, $d1:expr, $d2:expr, $d3:expr, $d4:expr, $d5:expr, $d6:expr, $d7:expr) => {
//         secp256k1_fe_storage {
//             n : [($d0) | (($d1 as u64) << 32),
//                  ($d2) | (($d3 as u64) << 32),
//                  ($d4) | (($d5 as u64) << 32),
//                  ($d6) | (($d7 as u64) << 32),
//             ]
//         }
//     }
// }


#[macro_export] 
macro_rules! SECP256K1_FE_STORAGE_CONST_GET {
    ($d:expr) => {
        (($d.n[3] >> 32) as u32, $d.n[3] as u32,
         ($d.n[2] >> 32) as u32, $d.n[2] as u32,
         ($d.n[1] >> 32) as u32, $d.n[1] as u32,
         ($d.n[0] >> 32) as u32, $d.n[0] as u32)
    }
}

/** Implements arithmetic modulo FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F,
 *  represented as 5 uint64_t's in base 2^52, least significant first. Note that the limbs are allowed to
 *  contain >52 bits each.
 *
 *  Each field element has a 'magnitude' associated with it. Internally, a magnitude M means:
 *  - 2*M*(2^48-1) is the max (inclusive) of the most significant limb
 *  - 2*M*(2^52-1) is the max (inclusive) of the remaining limbs
 *
 *  Operations have different rules for propagating magnitude to their outputs. If an operation takes a
 *  magnitude M as a parameter, that means the magnitude of input field elements can be at most M (inclusive).
 *
 *  Each field element also has a 'normalized' flag. A field element is normalized if its magnitude is either
 *  0 or 1, and its value is already reduced modulo the order of the field.
 */

//#ifdef VERIFY
#[cfg(feature = "verify")]
//static void secp256k1_fe_verify(const secp256k1_fe *a) {
pub fn secp256k1_fe_verify(a: &secp256k1_fe) {
    let d = &a.n;
    let m = if a.normalized { 1 } else { 2 * a.magnitude };

    /* secp256k1 'p' value defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    r &= (d[0] <= 0xFFFFFFFFFFFFF_u64 * m);
    r &= (d[1] <= 0xFFFFFFFFFFFFF_u64 * m);
    r &= (d[2] <= 0xFFFFFFFFFFFFF_u64 * m);
    r &= (d[3] <= 0xFFFFFFFFFFFFF_u64 * m);
    r &= (d[4] <= 0x0FFFFFFFFFFFF_u64 * m);
    r &= (a.magnitude >= 0);
    r &= (a.magnitude <= 2048);
    if (a.normalized) {
        r &= (a.magnitude <= 1);
        if (r && (d[4] == 0x0FFFFFFFFFFFF_u64) && ((d[3] & d[2] & d[1]) == 0xFFFFFFFFFFFFF_u64)) {
            r &= (d[0] < 0xFFFFEFFFFFC2F_u64);
        }
    }
    VERIFY_CHECK(r == 1);
}
 
//static void secp256k1_fe_get_bounds(secp256k1_fe *r, int m) {
fn secp256k1_fe_get_bounds(r: &mut secp256k1_fe, m: i32) {
    //VERIFY_CHECK(m >= 0);
    //VERIFY_CHECK(m <= 2048);
    r.n[0] = 0xFFFFFFFFFFFFF_u64 * 2 * m as u64;
    r.n[1] = 0xFFFFFFFFFFFFF_u64 * 2 * m as u64;
    r.n[2] = 0xFFFFFFFFFFFFF_u64 * 2 * m as u64;
    r.n[3] = 0xFFFFFFFFFFFFF_u64 * 2 * m as u64;
    r.n[4] = 0x0FFFFFFFFFFFF_u64 * 2 * m as u64;
    #[cfg(feature = "verify")]
    {
        r.magnitude = m;
        r.normalized = (m == 0);
        secp256k1_fe_verify(r);
    }
}
 
//static void secp256k1_fe_normalize(secp256k1_fe *r) {
pub fn secp256k1_fe_normalize(r: &mut secp256k1_fe) {
    //uint64_t t0 = r.n[0], t1 = r.n[1], t2 = r.n[2], t3 = r.n[3], t4 = r.n[4];
    let mut t0 = r.n[0];
    let mut t1 = r.n[1];
    let mut t2 = r.n[2];
    let mut t3 = r.n[3];
    let mut t4 = r.n[4];    

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    let mut m: u64;
    let mut x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFF_u64;
 
    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1_u64;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFF_u64;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFF_u64; m = t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFF_u64; m &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFF_u64; m &= t3;
 
    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    //VERIFY_CHECK(t4 >> 49 == 0);
 
    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFF_u64) & (m == 0xFFFFFFFFFFFFF_u64)
         & (t0 >= 0xFFFFEFFFFFC2F_u64)) as u64;
 
    /* Apply the final reduction (for constant-time behaviour, we do it always) */
    t0 += x * 0x1000003D1_u64;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFF_u64;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFF_u64;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFF_u64;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFF_u64;
 
    /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */
    //VERIFY_CHECK(t4 >> 48 == x);
 
    /* Mask off the possible multiple of 2^256 from the final reduction */
    t4 &= 0x0FFFFFFFFFFFF_u64;
 
    r.n[0] = t0; r.n[1] = t1; r.n[2] = t2; r.n[3] = t3; r.n[4] = t4;
 
    #[cfg(feature = "verify")]
    {
       r.magnitude = 1;
       r.normalized = 1;
       secp256k1_fe_verify(r);
    }
}
 
// static void secp256k1_fe_normalize_weak(secp256k1_fe *r) {
pub fn secp256k1_fe_normalize_weak(r: &mut secp256k1_fe) {
    // uint64_t t0 = r.n[0], t1 = r.n[1], t2 = r.n[2], t3 = r.n[3], t4 = r.n[4];
    let (mut t0, mut t1, mut t2, mut t3, mut t4) = (r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]);

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    let mut x: u64 = t4 >> 48; t4 &= 0x0FFFFFFFFFFFF_u64;
 
    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1_u64;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFF_u64;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFF_u64;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFF_u64;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFF_u64;
 
    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    //VERIFY_CHECK(t4 >> 49 == 0);
 
    r.n[0] = t0; r.n[1] = t1; r.n[2] = t2; r.n[3] = t3; r.n[4] = t4;
 
    #[cfg(feature = "verify")]
    {
        r.magnitude = 1;
        secp256k1_fe_verify(r);
    }
 }
 
// static void secp256k1_fe_normalize_var(secp256k1_fe *r) {
pub fn secp256k1_fe_normalize_var(r: &mut secp256k1_fe) {
    let (mut t0, mut t1, mut t2, mut t3, mut t4) = (r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]);
 
    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    let mut m: u64;
    let mut x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFF_u64;
 
    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1_u64;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFF_u64;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFF_u64; m = t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFF_u64; m &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFF_u64; m &= t3;
 
    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    //VERIFY_CHECK(t4 >> 49 == 0);
 
    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFF_u64) & (m == 0xFFFFFFFFFFFFF_u64)
        & (t0 >= 0xFFFFEFFFFFC2F_u64)) as u64;
 
    if (x != 0) {
        t0 += 0x1000003D1_u64;
        t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFF_u64;
        t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFF_u64;
        t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFF_u64;
        t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFF_u64;
 
        /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */
        //VERIFY_CHECK(t4 >> 48 == x);
 
        /* Mask off the possible multiple of 2^256 from the final reduction */
        t4 &= 0x0FFFFFFFFFFFF_u64;
    }
 
    r.n[0] = t0; r.n[1] = t1; r.n[2] = t2; r.n[3] = t3; r.n[4] = t4;
 
    #[cfg(feature = "verify")]
    {
        r.magnitude = 1;
        r.normalized = 1;
        secp256k1_fe_verify(r);
    }
}


// static int secp256k1_fe_normalizes_to_zero(const secp256k1_fe *r) {
pub fn secp256k1_fe_normalizes_to_zero(r: &secp256k1_fe) -> i32 {
    let (mut t0, mut t1, mut t2, mut t3, mut t4) = (r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]);
 
    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    let mut z0: u64;
    let mut z1: u64;
 
    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    let mut x: u64 = t4 >> 48; t4 &= 0x0FFFFFFFFFFFF_u64;
 
     /* The first pass ensures the magnitude is 1, ... */
     t0 += x * 0x1000003D1_u64;
     t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFF_u64; z0  = t0; z1  = t0 ^ 0x1000003D0_u64;
     t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFF_u64; z0 |= t1; z1 &= t1;
     t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFF_u64; z0 |= t2; z1 &= t2;
     t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFF_u64; z0 |= t3; z1 &= t3;
                                                 z0 |= t4; z1 &= t4 ^ 0xF000000000000_u64;
 
    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    //VERIFY_CHECK(t4 >> 49 == 0);
 
    return ((z0 == 0) | (z1 == 0xFFFFFFFFFFFFF_u64)) as i32;
 }
 
// static int secp256k1_fe_normalizes_to_zero_var(const secp256k1_fe *r) {
pub fn secp256k1_fe_normalizes_to_zero_var(r: &secp256k1_fe) -> i32 {
    let mut t0: u64;
    let mut t1: u64;
    let mut t2: u64;
    let mut t3: u64;
    let mut t4: u64; 
    let mut z0: u64;
    let mut z1: u64;
    let mut x: u64;
 
    t0 = r.n[0];
    t4 = r.n[4];
 
    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    x = t4 >> 48;
 
    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1_u64;
 
    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    z0 = t0 & 0xFFFFFFFFFFFFF_u64;
    z1 = z0 ^ 0x1000003D0_u64;
 
    /* Fast return path should catch the majority of cases */
    if ((z0 != 0_u64) & (z1 != 0xFFFFFFFFFFFFF_u64)) {
        return 0;
    }
 
    t1 = r.n[1];
    t2 = r.n[2];
    t3 = r.n[3];
 
    t4 &= 0x0FFFFFFFFFFFF_u64;
 
    t1 += (t0 >> 52);
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFF_u64; z0 |= t1; z1 &= t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFF_u64; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFF_u64; z0 |= t3; z1 &= t3;
                                                 z0 |= t4; z1 &= t4 ^ 0xF000000000000_u64;
 
    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    //VERIFY_CHECK(t4 >> 49 == 0);
 
    return ((z0 == 0) | (z1 == 0xFFFFFFFFFFFFF_u64)) as i32;
}
 
pub fn secp256k1_fe_set_int(r: &mut secp256k1_fe, a: i32) {
    //VERIFY_CHECK(0 <= a && a <= 0x7FFF);
    r.n = [a as u64, 0, 0, 0, 0];
#[cfg(feature = "verify")]
    {
        r.magnitude = (a != 0);
        r.normalized = 1;
        secp256k1_fe_verify(r);
    }
}
 
// SECP256K1_INLINE static int secp256k1_fe_is_zero(const secp256k1_fe *a) {
pub fn secp256k1_fe_is_zero(a: &secp256k1_fe) -> i32 {
    let t = &a.n;
    #[cfg(feature = "verify")]
    {
        VERIFY_CHECK(a.normalized);
        secp256k1_fe_verify(a);
    }
     return ((t[0] | t[1] | t[2] | t[3] | t[4]) == 0) as i32;
 }
 
// SECP256K1_INLINE static int secp256k1_fe_is_odd(const secp256k1_fe *a) {
pub fn secp256k1_fe_is_odd(a: &secp256k1_fe) -> i32 {
    #[cfg(feature = "verify")]
    {
        VERIFY_CHECK(a.normalized);
        secp256k1_fe_verify(a);
    }
    return a.n[0] as i32 & 1;
}
 
// SECP256K1_INLINE static void secp256k1_fe_clear(secp256k1_fe *a) {
pub fn secp256k1_fe_clear(a: &mut secp256k1_fe) {
    #[cfg(feature = "verify")] {
        a.magnitude = 0;
        a.normalized = 1;
    }
    for i in 0..5 {
         a.n[i] = 0;
    }
}
 
// static int secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b) {
fn secp256k1_fe_cmp_var(a: &secp256k1_fe, b: &secp256k1_fe) -> i32 {
    // int i;
    let mut i: i32;
    #[cfg(feature = "verify")] {
        VERIFY_CHECK(a.normalized);
        VERIFY_CHECK(b.normalized);
        secp256k1_fe_verify(a);
        secp256k1_fe_verify(b);
    }
    
    for i in (0..5).rev() {
         if (a.n[i] > b.n[i]) {
             return 1;
         }
         if (a.n[i] < b.n[i]) {
             return -1;
         }
     }
     return 0;
 }
 
// static int secp256k1_fe_set_b32(secp256k1_fe *r, const unsigned char *a) {
pub fn secp256k1_fe_set_b32(r: &mut secp256k1_fe, a: &[u8]) -> i32 {
    // int ret;
    let mut ret: i32;
    r.n[0] = a[31] as u64
            | ((a[30] as u64) << 8)
            | ((a[29] as u64) << 16)
            | ((a[28] as u64) << 24)
            | ((a[27] as u64) << 32)
            | ((a[26] as u64) << 40)
            | (((a[25] as u64) & 0xF)  << 48);
    r.n[1] = (((a[25] as u64) >> 4) & 0xF)
            | ((a[24] as u64) << 4)
            | ((a[23] as u64) << 12)
            | ((a[22] as u64) << 20)
            | ((a[21] as u64) << 28)
            | ((a[20] as u64) << 36)
            | ((a[19] as u64) << 44);
    r.n[2] = a[18] as u64
            | ((a[17] as u64) << 8)
            | ((a[16] as u64) << 16)
            | ((a[15] as u64) << 24)
            | ((a[14] as u64) << 32)
            | ((a[13] as u64) << 40)
            | (((a[12] as u64) & 0xF) << 48);
    r.n[3] = (((a[12] as u64) >> 4) & 0xF)
            | ((a[11] as u64) << 4)
            | ((a[10] as u64) << 12)
            | ((a[9] as u64) << 20)
            | ((a[8] as u64) << 28)
            | ((a[7] as u64) << 36)
            | ((a[6] as u64) << 44);
    r.n[4] = a[5] as u64
            | ((a[4] as u64) << 8)
            | ((a[3] as u64) << 16)
            | ((a[2] as u64) << 24)
            | ((a[1] as u64) << 32)
            | ((a[0] as u64) << 40);
     ret = !((r.n[4] == 0x0FFFFFFFFFFFF_u64) & ((r.n[3] & r.n[2] & r.n[1]) == 0xFFFFFFFFFFFFF_u64) & (r.n[0] >= 0xFFFFEFFFFFC2F_u64)) as i32;
    #[cfg(feature = "verify")] {
        r.magnitude = 1;
        if (ret) {
            r.normalized = 1;
            secp256k1_fe_verify(r);
        } else {
            r.normalized = 0;
        }
    }
    return ret;
 }
 
 /** Convert a field element to a 32-byte big endian value. Requires the input to be normalized */
pub fn secp256k1_fe_get_b32(r: &[u8], a: &secp256k1_fe) {

#[cfg(feature = "verify")] {
     VERIFY_CHECK(a.normalized);
     secp256k1_fe_verify(a);
}
    r[0] = ((a.n[4] >> 40) & 0xFF) as u8;
    r[1] = ((a.n[4] >> 32) & 0xFF) as u8;
    r[2] = ((a.n[4] >> 24) & 0xFF) as u8;
    r[3] = ((a.n[4] >> 16) & 0xFF) as u8;
    r[4] = ((a.n[4] >> 8) & 0xFF) as u8;
    r[5] = (a.n[4] & 0xFF) as u8;
    r[6] = ((a.n[3] >> 44) & 0xFF) as u8;
    r[7] = ((a.n[3] >> 36) & 0xFF) as u8;
    r[8] = ((a.n[3] >> 28) & 0xFF) as u8;
    r[9] = ((a.n[3] >> 20) & 0xFF) as u8;
    r[10] = ((a.n[3] >> 12) & 0xFF) as u8;
    r[11] = ((a.n[3] >> 4) & 0xFF) as u8;
    r[12] = (((a.n[2] >> 48) & 0xF) | ((a.n[3] & 0xF) << 4)) as u8;
    r[13] = ((a.n[2] >> 40) & 0xFF) as u8;
    r[14] = ((a.n[2] >> 32) & 0xFF) as u8;
    r[15] = ((a.n[2] >> 24) & 0xFF) as u8;
    r[16] = ((a.n[2] >> 16) & 0xFF) as u8;
    r[17] = ((a.n[2] >> 8) & 0xFF) as u8;
    r[18] = (a.n[2] & 0xFF) as u8;
    r[19] = ((a.n[1] >> 44) & 0xFF) as u8;
    r[20] = ((a.n[1] >> 36) & 0xFF) as u8;
    r[21] = ((a.n[1] >> 28) & 0xFF) as u8;
    r[22] = ((a.n[1] >> 20) & 0xFF) as u8;
    r[23] = ((a.n[1] >> 12) & 0xFF) as u8;
    r[24] = ((a.n[1] >> 4) & 0xFF) as u8;
    r[25] = (((a.n[0] >> 48) & 0xF) | ((a.n[1] & 0xF) << 4)) as u8;
    r[26] = ((a.n[0] >> 40) & 0xFF) as u8;
    r[27] = ((a.n[0] >> 32) & 0xFF) as u8;
    r[28] = ((a.n[0] >> 24) & 0xFF) as u8;
    r[29] = ((a.n[0] >> 16) & 0xFF) as u8;
    r[30] = ((a.n[0] >> 8) & 0xFF) as u8;
    r[31] = (a.n[0] & 0xFF) as u8;
}
 
// SECP256K1_INLINE static void secp256k1_fe_negate(secp256k1_fe *r, const secp256k1_fe *a, int m) {
pub fn secp256k1_fe_negate(r: &mut secp256k1_fe, a: &secp256k1_fe, m: i32) {
    #[cfg(feature = "verify")] {
    VERIFY_CHECK(a.magnitude <= m);
    secp256k1_fe_verify(a);
    VERIFY_CHECK(0xFFFFEFFFFFC2F_u64 * 2 * (m + 1) >= 0xFFFFFFFFFFFFF_u64 * 2 * m);
    VERIFY_CHECK(0xFFFFFFFFFFFFF_u64 * 2 * (m + 1) >= 0xFFFFFFFFFFFFF_u64 * 2 * m);
    VERIFY_CHECK(0x0FFFFFFFFFFFF_u64 * 2 * (m + 1) >= 0x0FFFFFFFFFFFF_u64 * 2 * m);
    }
    r.n[0] = 0xFFFFEFFFFFC2F_u64 * 2 * (m as u64 + 1) - a.n[0];
    r.n[1] = 0xFFFFFFFFFFFFF_u64 * 2 * (m as u64 + 1) - a.n[1];
    r.n[2] = 0xFFFFFFFFFFFFF_u64 * 2 * (m as u64 + 1) - a.n[2];
    r.n[3] = 0xFFFFFFFFFFFFF_u64 * 2 * (m as u64 + 1) - a.n[3];
    r.n[4] = 0x0FFFFFFFFFFFF_u64 * 2 * (m as u64 + 1) - a.n[4];
    #[cfg(feature = "verify")] {
        r.magnitude = m + 1;
        r.normalized = 0;
        secp256k1_fe_verify(r);
    }
}
 
pub fn secp256k1_fe_mul_int(r: &mut secp256k1_fe, a: i32) {
     r.n[0] *= a as u64;
     r.n[1] *= a as u64;
     r.n[2] *= a as u64;
     r.n[3] *= a as u64;
     r.n[4] *= a as u64;
     #[cfg(feature = "verify")] {
        r.magnitude *= a;
        r.normalized = 0;
        secp256k1_fe_verify(r);
    }
}
 
// SECP256K1_INLINE static void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a) {
pub fn secp256k1_fe_add(r: &mut secp256k1_fe, a: &secp256k1_fe) {
    #[cfg(feature = "verify")] {
        secp256k1_fe_verify(a);
    }
    r.n[0] += a.n[0];
    r.n[1] += a.n[1];
    r.n[2] += a.n[2];
    r.n[3] += a.n[3];
    r.n[4] += a.n[4];
    #[cfg(feature = "verify")] {
        r.magnitude += a.magnitude;
        r.normalized = 0;
        secp256k1_fe_verify(r);
    }
 }
 
// static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b) {
pub fn secp256k1_fe_mul(r: &mut secp256k1_fe, a: &secp256k1_fe, b: &secp256k1_fe) {
    #[cfg(feature = "verify")] {
        VERIFY_CHECK(a.magnitude <= 8);
        VERIFY_CHECK(b.magnitude <= 8);
        secp256k1_fe_verify(a);
        secp256k1_fe_verify(b);
        VERIFY_CHECK(r != b);
        VERIFY_CHECK(a != b);
    }
    secp256k1_fe_mul_inner(r.n.as_mut_slice(), a.n.as_mut_slice(), b.n.as_mut_slice());
    #[cfg(feature = "verify")] {
        r.magnitude = 1;
        r.normalized = 0;
        secp256k1_fe_verify(r);
    }
}
 
// static void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) {
pub fn secp256k1_fe_sqr(r: &mut secp256k1_fe, a: &secp256k1_fe) {
    #[cfg(feature = "verify")] {
        VERIFY_CHECK(a.magnitude <= 8);
        secp256k1_fe_verify(a);
    }
    secp256k1_fe_sqr_inner(r.n.as_mut_slice(), a.n.as_mut_slice());
    #[cfg(feature = "verify")] {
        r.magnitude = 1;
        r.normalized = 0;
         secp256k1_fe_verify(r);
    }
 }
 
// static SECP256K1_INLINE void secp256k1_fe_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag) {
pub fn secp256k1_fe_cmov(r: &mut secp256k1_fe, a: &secp256k1_fe, flag: i32) {
    let mut mask0: u64;
    let mut mask1: u64;
    // VG_CHECK_VERIFY(r.n, sizeof(r.n));

    mask0 = flag as u64 + !(0 as u64);
    mask1 = !mask0;
    r.n[0] = (r.n[0] & mask0) | (a.n[0] & mask1);
    r.n[1] = (r.n[1] & mask0) | (a.n[1] & mask1);
    r.n[2] = (r.n[2] & mask0) | (a.n[2] & mask1);
    r.n[3] = (r.n[3] & mask0) | (a.n[3] & mask1);
    r.n[4] = (r.n[4] & mask0) | (a.n[4] & mask1);
    #[cfg(feature = "verify")] {
        if (flag) {
            r.magnitude = a.magnitude;
            r.normalized = a.normalized;
        }
    }
}
 
pub fn secp256k1_fe_half(r: &mut secp256k1_fe) {
    let (mut t0, mut t1, mut t2, mut t3, mut t4) = (r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]);
    let one: u64 = 1;
    let mask: u64 = -(((t0 & one) >> 12) as i64) as u64;
 
    #[cfg(feature = "verify")] {
        secp256k1_fe_verify(r);
        VERIFY_CHECK(r.magnitude < 32);
    }
 
    /* Bounds analysis (over the rationals).
     *
     * Let m = r.magnitude
     *     C = 0xFFFFFFFFFFFFF_u64 * 2
     *     D = 0x0FFFFFFFFFFFF_u64 * 2
     *
     * Initial bounds: t0..t3 <= C * m
     *                     t4 <= D * m
     */
 
    t0 += 0xFFFFEFFFFFC2F_u64 & mask;
    t1 += mask;
    t2 += mask;
    t3 += mask;
    t4 += mask >> 4;
 
    #[cfg(feature = "verify")] VERIFY_CHECK((t0 & one) == 0);

    /* t0..t3: added <= C/2
    *     t4: added <= D/2
    *
    * Current bounds: t0..t3 <= C * (m + 1/2)
    *                     t4 <= D * (m + 1/2)
    */

    r.n[0] = (t0 >> 1) + ((t1 & one) << 51);
    r.n[1] = (t1 >> 1) + ((t2 & one) << 51);
    r.n[2] = (t2 >> 1) + ((t3 & one) << 51);
    r.n[3] = (t3 >> 1) + ((t4 & one) << 51);
    r.n[4] = (t4 >> 1);

    /* t0..t3: shifted right and added <= C/4 + 1/2
    *     t4: shifted right
    *
    * Current bounds: t0..t3 <= C * (m/2 + 1/2)
    *                     t4 <= D * (m/2 + 1/4)
    */
 
    #[cfg(feature = "verify")] {
    /* Therefore the output magnitude (M) has to be set such that:
     *     t0..t3: C * M >= C * (m/2 + 1/2)
     *         t4: D * M >= D * (m/2 + 1/4)
     *
     * It suffices for all limbs that, for any input magnitude m:
     *     M >= m/2 + 1/2
     *
     * and since we want the smallest such integer value for M:
     *     M == floor(m/2) + 1
     */
        r.magnitude = (r.magnitude >> 1) + 1;
        r.normalized = 0;
        secp256k1_fe_verify(r);
    }
}
 
// static SECP256K1_INLINE void secp256k1_fe_storage_cmov(secp256k1_fe_storage *r, const secp256k1_fe_storage *a, int flag) {
pub fn secp256k1_fe_storage_cmov(r: &mut secp256k1_fe_storage, a: &secp256k1_fe_storage, flag: i32) {
    let mut mask0: u64;
    let mut mask1: u64;
    #[cfg(feature = "verify")] VG_CHECK_VERIFY(r.n, sizeof(r.n));
    mask0 = flag as u64 + !(0 as u64);
    mask1 = !mask0;
    r.n[0] = (r.n[0] & mask0) | (a.n[0] & mask1);
    r.n[1] = (r.n[1] & mask0) | (a.n[1] & mask1);
    r.n[2] = (r.n[2] & mask0) | (a.n[2] & mask1);
    r.n[3] = (r.n[3] & mask0) | (a.n[3] & mask1);
}

pub fn secp256k1_fe_to_storage(r: &mut secp256k1_fe_storage, a: &secp256k1_fe) {
    #[cfg(feature = "verify")] {
        VERIFY_CHECK(a.normalized);
    }
    r.n[0] = a.n[0] | a.n[1] << 52;
    r.n[1] = a.n[1] >> 12 | a.n[2] << 40;
    r.n[2] = a.n[2] >> 24 | a.n[3] << 28;
    r.n[3] = a.n[3] >> 36 | a.n[4] << 16;
 }
 
// static SECP256K1_INLINE void secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a) {
pub fn secp256k1_fe_from_storage(r: &mut secp256k1_fe, a: &secp256k1_fe_storage) {
    r.n[0] = a.n[0] & 0xFFFFFFFFFFFFF_u64;
    r.n[1] = a.n[0] >> 52 | ((a.n[1] << 12) & 0xFFFFFFFFFFFFF_u64);
    r.n[2] = a.n[1] >> 40 | ((a.n[2] << 24) & 0xFFFFFFFFFFFFF_u64);
    r.n[3] = a.n[2] >> 28 | ((a.n[3] << 36) & 0xFFFFFFFFFFFFF_u64);
    r.n[4] = a.n[3] >> 16;
    #[cfg(feature = "verify")] {
        r.magnitude = 1;
        r.normalized = 1;
        secp256k1_fe_verify(r);
    }
}
 
// static void secp256k1_fe_from_signed62(secp256k1_fe *r, const secp256k1_modinv64_signed62 *a) {
fn secp256k1_fe_from_signed62(r: &mut secp256k1_fe, a: &secp256k1_modinv64_signed62) {
    let M52: u64 = u64::MAX >> 12;
    // const uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];
    let (a0, a1, a2, a3, a4) = (a.v[0] as u64, a.v[1] as u64, a.v[2] as u64, a.v[3] as u64, a.v[4] as u64);

     /* The output from secp256k1_modinv64{_var} should be normalized to range [0,modulus), and
      * have limbs in [0,2^62). The modulus is < 2^256, so the top limb must be below 2^(256-62*4).
      */
    #[cfg(feature = "verify")] {
        VERIFY_CHECK(a0 >> 62 == 0);
        VERIFY_CHECK(a1 >> 62 == 0);
        VERIFY_CHECK(a2 >> 62 == 0);
        VERIFY_CHECK(a3 >> 62 == 0);
        VERIFY_CHECK(a4 >> 8 == 0);
    }

    r.n[0] = a0 & M52;
    r.n[1] = (a0 >> 52 | a1 << 10) & M52;
    r.n[2] = (a1 >> 42 | a2 << 20) & M52;
    r.n[3] = (a2 >> 32 | a3 << 30) & M52;
    r.n[4] = (a3 >> 22 | a4 << 40);
 
    #[cfg(feature = "verify")] {
        r.magnitude = 1;
        r.normalized = 1;
        secp256k1_fe_verify(r);
    }
}
 
// static void secp256k1_fe_to_signed62(secp256k1_modinv64_signed62 *r, const secp256k1_fe *a) {
fn secp256k1_fe_to_signed62(r: &mut secp256k1_modinv64_signed62, a: &secp256k1_fe) {
    let M62: u64 = u64::MAX >> 2;
    //const uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3], a4 = a->n[4];
    let (a0, a1, a2, a3, a4) = (a.n[0] as u64, a.n[1] as u64, a.n[2] as u64, a.n[3] as u64, a.n[4] as u64);

    #[cfg(feature = "verify")] {
        VERIFY_CHECK(a.normalized);
    }
 
    r.v[0] = ((a0 | a1 << 52) & M62) as i64;
    r.v[1] = ((a1 >> 10 | a2 << 42) & M62) as i64;
    r.v[2] = ((a2 >> 20 | a3 << 32) & M62) as i64;
    r.v[3] = ((a3 >> 30 | a4 << 22) & M62) as i64;
    r.v[4] =  (a4 >> 40) as i64;
 }
 
// static const secp256k1_modinv64_modinfo secp256k1_const_modinfo_fe = {
//     {{-0x1000003D1LL, 0, 0, 0, 256}},
//     0x27C7F6E22DDACACFLL
// };
const secp256k1_const_modinfo_fe: secp256k1_modinv64_modinfo = secp256k1_modinv64_modinfo {
    modulus: secp256k1_modinv64_signed62 {
        v: [-0x1000003D1, 0, 0, 0, 256]
    },
    modulus_inv62: 0x27C7F6E22DDACACF
};
 
// static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *x) {
pub fn secp256k1_fe_inv(r: &mut secp256k1_fe, x: &secp256k1_fe) {
    //secp256k1_fe tmp;
    let mut tmp: secp256k1_fe;
    // secp256k1_modinv64_signed62 s;
    let mut s: secp256k1_modinv64_signed62;

    tmp = *x;
    secp256k1_fe_normalize(&mut tmp);
    secp256k1_fe_to_signed62(&mut s, &tmp);
    secp256k1_modinv64(&mut s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed62(r, &s);
 
    #[cfg(feature = "verify")] {
        VERIFY_CHECK(secp256k1_fe_normalizes_to_zero(r) == secp256k1_fe_normalizes_to_zero(&tmp));
    }
}
 
pub fn secp256k1_fe_inv_var(r: &mut secp256k1_fe, x: &secp256k1_fe) {
    let mut tmp: secp256k1_fe;
    let mut s: secp256k1_modinv64_signed62;

    tmp = *x;
    secp256k1_fe_normalize_var(&mut tmp);
    secp256k1_fe_to_signed62(&mut s, &tmp);
    secp256k1_modinv64_var(&mut s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed62(r, &s);
 
    #[cfg(feature = "verify")] {
        VERIFY_CHECK(secp256k1_fe_normalizes_to_zero(r) == secp256k1_fe_normalizes_to_zero(&tmp));
    }
}