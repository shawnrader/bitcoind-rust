/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/
 #[macro_export] 
#[cfg(feature="verify")]
macro_rules! VERIFY_BITS {
    ($x:expr, $n:expr) => {
        VERIFY_CHECK((($x) >> ($n)) == 0)
    };
}
#[cfg(not(feature="verify"))] 
macro_rules! VERIFY_BITS {
    ($x:expr, $n:expr) => {
        ()
    };
}


//SECP256K1_INLINE static void secp256k1_fe_mul_inner(uint64_t *r, const uint64_t *a, const uint64_t * SECP256K1_RESTRICT b) {
fn secp256k1_fe_mul_inner(r: &mut [u64], a: &[u64], b: &[u64]) {
    let mut c: u128;
    let mut d: u128;
    //uint64_t t3, t4, tx, u0;
    let mut t3: u64;
    let mut t4: u64;
    let mut tx: u64;
    let mut u0: u64;
    //uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    let (a0, a1, a2, a3, a4) = (a[0], a[1], a[2], a[3], a[4]);
    //const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;
    let M: u64 = 0xFFFFFFFFFFFFF_u64;
    let R: u64 = 0x1000003D10_u64;

    VERIFY_BITS!(a[0], 56);
    VERIFY_BITS!(a[1], 56);
    VERIFY_BITS!(a[2], 56);
    VERIFY_BITS!(a[3], 56);
    VERIFY_BITS!(a[4], 52);
    VERIFY_BITS!(b[0], 56);
    VERIFY_BITS!(b[1], 56);
    VERIFY_BITS!(b[2], 56);
    VERIFY_BITS!(b[3], 56);
    VERIFY_BITS!(b[4], 52);
    VERIFY_CHECK(r != b);
    VERIFY_CHECK(a != b);

    /*  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  for 0 <= x <= 4, px is a shorthand for sum(a[i]*b[x-i], i=0..x).
     *  for 4 <= x <= 8, px is a shorthand for sum(a[i]*b[x-i], i=(x-4)..4)
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    d  = a0 as u128 * b[3] as u128
       + a1 as u128 * b[2] as u128
       + a2 as u128 * b[1] as u128
       + a3 as u128 * b[0] as u128;
    VERIFY_BITS!(d, 114);
    /* [d 0 0 0] = [p3 0 0 0] */
    c  = a4 as u128 * b[4];
    VERIFY_BITS!(c, 112);
    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    d += R as u128 * c; c >>= 64;
    VERIFY_BITS!(d, 115);
    VERIFY_BITS!(c, 48);
    /* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    t3 = d & M; d >>= 52;
    VERIFY_BITS!(t3, 52);
    VERIFY_BITS!(d, 63);
    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    d += a0 as u128 * b[4] as u128
       + a1 as u128 * b[3] as u128
       + a2 as u128 * b[2] as u128
       + a3 as u128 * b[1] as u128
       + a4 as u128 * b[0] as u128;
    VERIFY_BITS!(d, 115);
    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    d += (uint128_t)(R << 12) * (uint64_t)c;
    VERIFY_BITS!(d, 116);
    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    t4 = d & M; d >>= 52;
    VERIFY_BITS!(t4, 52);
    VERIFY_BITS!(d, 64);
    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    tx = (t4 >> 48); t4 &= (M >> 4);
    VERIFY_BITS!(tx, 4);
    VERIFY_BITS!(t4, 48);
    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    c  = a0 as u128 * b[0];
    VERIFY_BITS!(c, 112);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    d += a1 as u128 * b[4]
       + a2 as u128 * b[3]
       + a3 as u128 * b[2]
       + a4 as u128 * b[1];
    VERIFY_BITS!(d, 115);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = d & M; d >>= 52;
    VERIFY_BITS!(u0, 52);
    VERIFY_BITS!(d, 63);
    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;
    VERIFY_BITS!(u0, 56);
    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    c += u0 as u128 * (R >> 4);
    VERIFY_BITS!(c, 115);
    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    r[0] = c & M; c >>= 52;
    VERIFY_BITS!(r[0], 52);
    VERIFY_BITS!(c, 61);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    c += a0 as u128 * b[1]
       + a1 as u128 * b[0];
    VERIFY_BITS!(c, 114);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    d += a2 as u128 * b[4]
       + a3 as u128 * b[3]
       + a4 as u128 * b[2];
    VERIFY_BITS!(d, 114);
    /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    c += (d & M) * R; d >>= 52;
    VERIFY_BITS!(c, 115);
    VERIFY_BITS!(d, 62);
    /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    r[1] = c & M; c >>= 52;
    VERIFY_BITS!(r[1], 52);
    VERIFY_BITS!(c, 63);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    c += a0 as u128 * b[2]
       + a1 as u128 * b[1]
       + a2 as u128 * b[0];
    VERIFY_BITS!(c, 114);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    d += a3 as u128 * b[4]
       + a4 as u128 * b[3];
    VERIFY_BITS!(d, 114);
    /* [d 0 0 t4 t3 c t1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c += R as u128 * (d as u64) as u128; d >>= 64;
    VERIFY_BITS!(c, 115);
    VERIFY_BITS!(d, 50);
    /* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    r[2] = c & M; c >>= 52;
    VERIFY_BITS!(r[2], 52);
    VERIFY_BITS!(c, 63);
    /* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += (R << 12) as u128 * (d as u64) as u128 + t3;
    VERIFY_BITS!(c, 100);
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = c & M; c >>= 52;
    VERIFY_BITS!(r[3], 52);
    VERIFY_BITS!(c, 48);
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += t4;
    VERIFY_BITS!(c, 49);
    /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = c;
    VERIFY_BITS!(r[4], 49);
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

//SECP256K1_INLINE static void secp256k1_fe_sqr_inner(uint64_t *r, const uint64_t *a) {
fn secp256k1_fe_sqr_inner(r: &mut [u64], a: &[u64]) {
    //uint128_t c, d;
    let mut c: u128;
    let mut d: u128;
    //uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    let (a0, a1, a2, a3, a4) = (a[0], a[1], a[2], a[3], a[4]);
    //int64_t t3, t4, tx, u0;
    let (t3, t4, tx, u0): (i64, i64, i64, i64);
    //const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;
    const M: u128 = 0xFFFFFFFFFFFFF_u128;
    const R: u128 = 0x1000003D10_u128;

    VERIFY_BITS!(a[0], 56);
    VERIFY_BITS!(a[1], 56);
    VERIFY_BITS!(a[2], 56);
    VERIFY_BITS!(a[3], 56);
    VERIFY_BITS!(a[4], 52);

    /*  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    d  = (a0*2) as u128 * a3 as u128
       + (a1*2) as u128 * a2 as u128;
    VERIFY_BITS!(d, 114);
    /* [d 0 0 0] = [p3 0 0 0] */
    c  = a4 as u128 * a4 as u128;
    VERIFY_BITS!(c, 112);
    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    d += R as u128 * (c as u64) as u128; c >>= 64;
    VERIFY_BITS!(d, 115);
    VERIFY_BITS!(c, 48);
    /* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    t3 = (d & M) as i64; d >>= 52;
    VERIFY_BITS!(t3, 52);
    VERIFY_BITS!(d, 63);
    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    a4 *= 2;
    d += a0 as u128 * a4 as u128
       + (a1*2) as u128 * a3 as u128
       + a2 as u128 * a2 as u128;
    VERIFY_BITS!(d, 115);
    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    d += (R << 12) as u128 * c;
    VERIFY_BITS!(d, 116);
    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    t4 = (d & M) as i64; d >>= 52;
    VERIFY_BITS!(t4, 52);
    VERIFY_BITS!(d, 64);
    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    tx = 4 >> 48; t4 &= (M >> 4) as i64;
    VERIFY_BITS!(tx, 4);
    VERIFY_BITS!(t4, 48);
    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    c  = a0 as u128 * a0 as u128;
    VERIFY_BITS!(c, 112);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    d += a1 as u128 * a4 as u128
       + (a2*2) as u128 * a3 as u128;
    VERIFY_BITS!(d, 114);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (d & M) as i64; d >>= 52;
    VERIFY_BITS!(u0, 52);
    VERIFY_BITS!(d, 62);
    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;
    VERIFY_BITS!(u0, 56);
    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    c += u0 as u128 * (R >> 4);
    VERIFY_BITS!(c, 113);
    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    r[0] = (c & M) as u64; c >>= 52;
    VERIFY_BITS!(r[0], 52);
    VERIFY_BITS!(c, 61);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    a0 *= 2;
    c += a0 as u128 * a1 as u128;
    VERIFY_BITS!(c, 114);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    d += a2 as u128 * a4 as u128
       + a3 as u128 * a3 as u128;
    VERIFY_BITS!(d, 114);
    /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    c += (d & M) * R; d >>= 52;
    VERIFY_BITS!(c, 115);
    VERIFY_BITS!(d, 62);
    /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    r[1] = c & M; c >>= 52;
    VERIFY_BITS!(r[1], 52);
    VERIFY_BITS!(c, 63);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    c += a0 as u128 * a2 as u128
       + a1 as u128 * a1 as u128;
    VERIFY_BITS!(c, 114);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    d += a3 as u128 * a4 as u128;
    VERIFY_BITS!(d, 114);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c += R  as u128 * d as u128; d >>= 64;
    VERIFY_BITS!(c, 115);
    VERIFY_BITS!(d, 50);
    /* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[2] = (c & M) as u64; c >>= 52;
    VERIFY_BITS!(r[2], 52);
    VERIFY_BITS!(c, 63);
    /* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    c   += (R << 12) as u128 * (d as u64) as u128 + t3 as u128;
    VERIFY_BITS!(c, 100);
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = (c & M) as u64; c >>= 52;
    VERIFY_BITS!(r[3], 52);
    VERIFY_BITS!(c, 48);
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += t4 as u128;
    VERIFY_BITS!(c, 49);
    /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = c as u64;
    VERIFY_BITS!(r[4], 49);
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}