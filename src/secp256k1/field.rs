#![allow(warnings)]
use crate::secp256k1::field_5x52::*;
use crate::{VERIFY_CHECK};

//SECP256K1_INLINE static int secp256k1_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b) {
pub fn secp256k1_fe_equal(a: &secp256k1_fe, b: &secp256k1_fe) -> i32 {
    //secp256k1_fe na;
    let mut na = secp256k1_fe::new();
    secp256k1_fe_negate(&mut na, a, 1);
    secp256k1_fe_add(&mut na, b);
    return secp256k1_fe_normalizes_to_zero(&na);
}

//SECP256K1_INLINE static int secp256k1_fe_equal_var(const secp256k1_fe *a, const secp256k1_fe *b) {
pub fn secp256k1_fe_equal_var(a: &secp256k1_fe, b: &secp256k1_fe) -> i32 {
    let mut na = secp256k1_fe::new();
    secp256k1_fe_negate(&mut na, a, 1);
    secp256k1_fe_add(&mut na, b);
    return secp256k1_fe_normalizes_to_zero_var(&na);
}

//static int secp256k1_fe_sqrt(secp256k1_fe *r, const secp256k1_fe *a) {
pub fn secp256k1_fe_sqrt(r: &mut secp256k1_fe, a: &secp256k1_fe) -> i32 {
    /** Given that p is congruent to 3 mod 4, we can compute the square root of
     *  a mod p as the (p+1)/4'th power of a.
     *
     *  As (p+1)/4 is an even number, it will have the same result for a and for
     *  (-a). Only one of these two numbers actually has a square root however,
     *  so we test at the end by squaring and comparing to the input.
     *  Also because (p+1)/4 is an even number, the computed square root is
     *  itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
     */
    let mut x2 = secp256k1_fe::new();
    let mut x3 = secp256k1_fe::new();
    let mut x6 = secp256k1_fe::new();
    let mut x9 = secp256k1_fe::new();
    let mut x11 = secp256k1_fe::new();
    let mut x22 = secp256k1_fe::new();
    let mut x44 = secp256k1_fe::new();
    let mut x88 = secp256k1_fe::new();
    let mut x176 = secp256k1_fe::new();
    let mut x220 = secp256k1_fe::new();
    let mut x223 = secp256k1_fe::new();
    let mut t1 = secp256k1_fe::new();

    VERIFY_CHECK!(r != a);

    /** The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
     *  { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    secp256k1_fe_sqr(&mut x2, a);
    let x2_clone = x2.clone();
    secp256k1_fe_mul(&mut x2, &x2_clone, a);

    secp256k1_fe_sqr(&mut x3, &x2);
    let x3_clone = x3.clone();
    secp256k1_fe_mul(&mut x3, &x3_clone, a);

    x6 = x3.clone();
    for j in [0..3] {
        let x6_clone = x6.clone();
        secp256k1_fe_sqr(&mut x6, &x6_clone);
    }
    let x6_clone = x6.clone();
    secp256k1_fe_mul(&mut x6, &x6_clone, &x3);

    x9 = x6.clone();
    for j in [0..3] {
        let x9_clone = x9.clone();
        secp256k1_fe_sqr(&mut x9, &x9_clone);
    }
    let x9_clone = x9.clone();
    secp256k1_fe_mul(&mut x9, &x9_clone, &x3);

    x11 = x9.clone();
    for j in [0..2] {
        let x11_clone = x11.clone();
        secp256k1_fe_sqr(&mut x11, &x11_clone);
    }
    let x11_clone = x11.clone();
    secp256k1_fe_mul(&mut x11, &x11_clone, &x2);

    x22 = x11.clone();
    for j in [0..11] {
        let x22_clone = x22.clone();
        secp256k1_fe_sqr(&mut x22, &x22_clone);
    }
    let x22_clone = x22.clone();
    secp256k1_fe_mul(&mut x22, &x22_clone, &x11);

    x44 = x22.clone();
    for j in [0..22] {
        let x44_clone = x44.clone();
        secp256k1_fe_sqr(&mut x44, &x44_clone);
    }
    let x44_clone = x44.clone();
    secp256k1_fe_mul(&mut x44, &x44_clone, &x22);

    x88 = x44.clone();
    for j in [0..44] {
        let x88_clone = x88.clone();
        secp256k1_fe_sqr(&mut x88, &x88_clone);
    }
    let x88_clone = x88.clone();
    secp256k1_fe_mul(&mut x88, &x88_clone, &x44);

    x176 = x88.clone();
    for j in [0..88] {
        let x176_clone = x176.clone();
        secp256k1_fe_sqr(&mut x176, &x176_clone);
    }
    let x176_clone = x176.clone();
    secp256k1_fe_mul(&mut x176, &x176_clone, &x88);

    x220 = x176.clone();
    for j in [0..44] {
        let x220_clone = x220.clone();
        secp256k1_fe_sqr(&mut x220, &x220_clone);
    }
    let x220_clone = x220.clone();
    secp256k1_fe_mul(&mut x220, &x220_clone, &x44);

    x223 = x220.clone();
    for j in [0..3] {
        let x223_clone = x223.clone();
        secp256k1_fe_sqr(&mut x223, &x223_clone);
    }
    let x223_clone = x223.clone();
    secp256k1_fe_mul(&mut x223, &x223_clone, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223.clone();
    for j in [0..23] {
        let t1_clone = t1.clone();
        secp256k1_fe_sqr(&mut t1, &t1_clone);
    }
    let t1_clone = t1.clone();
    secp256k1_fe_mul(&mut t1, &t1_clone, &x22);
    for j in [0..6] {
        let t1_clone = t1.clone();
        secp256k1_fe_sqr(&mut t1, &t1_clone);
    }
    let t1_clone = t1.clone();
    secp256k1_fe_mul(&mut t1, &t1_clone, &x2);
    let t1_clone = t1.clone();
    secp256k1_fe_sqr(&mut t1, &t1_clone);
    secp256k1_fe_sqr(r, &t1);

    /* Check that a square root was actually calculated */

    secp256k1_fe_sqr(&mut t1, r);
    return secp256k1_fe_equal(&t1, a);
}
