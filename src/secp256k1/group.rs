/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

use super::field_5x52::*;
use crate::SECP256K1_FE_STORAGE_CONST_GET;
use super::field::*;
use super::ecmult_gen::{secp256k1_fe_one, secp256k1_const_beta};

 /** A group element in affine coordinates on the secp256k1 curve,
 *  or occasionally on an isomorphic curve of the form y^2 = x^3 + 7*t^6.
 *  Note: For exhaustive test mode, secp256k1 is replaced by a small subgroup of a different curve.
 */
pub struct secp256k1_ge {
    pub x: secp256k1_fe,
    pub y: secp256k1_fe,
    pub infinity: i32, /* whether this represents the point at infinity */
}

impl secp256k1_ge {
    pub fn new() -> secp256k1_ge {
        secp256k1_ge {
            x: secp256k1_fe::new(),
            y: secp256k1_fe::new(),
            infinity: 0,
        }
    }
}

fn SECP256K1_GE_CONST(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32, i: u32, j: u32, k: u32, l: u32, m: u32, n: u32, o: u32, p: u32) -> secp256k1_ge {
    secp256k1_ge {
        x: SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)),
        y: SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)),
        infinity: 0
    }
}

fn SECP256K1_GE_CONST_INFINITY() -> secp256k1_ge { secp256k1_ge {x: SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), y: SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), infinity:1}}

/** A group element of the secp256k1 curve, in jacobian coordinates.
 *  Note: For exhastive test mode, sepc256k1 is replaced by a small subgroup of a different curve.
 */
pub struct secp256k1_gej {
    x: secp256k1_fe, /* actual X: x/z^2 */
    y: secp256k1_fe, /* actual Y: y/z^3 */
    z: secp256k1_fe,
    infinity: i32, /* whether this represents the point at infinity */
}

impl secp256k1_gej {
    pub fn new() -> secp256k1_gej {
        secp256k1_gej {
            x: secp256k1_fe::new(),
            y: secp256k1_fe::new(),
            z: secp256k1_fe::new(),
            infinity: 0,
        }
    }
}

fn SECP256K1_GEJ_CONST(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32, i: u32, j: u32, k: u32, l: u32, m: u32, n: u32, o: u32, p: u32) -> secp256k1_gej {
    secp256k1_gej {
        x: SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)),
        y: SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)),
        z: SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1),
        infinity: 0
    }
}

fn SECP256K1_GEJ_CONST_INFINITY() -> secp256k1_gej {
    secp256k1_gej {
        x: SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        y: SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        z: SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0),
        infinity: 1
    }
}

pub struct secp256k1_ge_storage {
    pub x: secp256k1_fe_storage,
    pub y: secp256k1_fe_storage,
}

#[macro_export]
macro_rules! SECP256K1_GE_STORAGE_CONST {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr, $m:expr, $n:expr, $o:expr, $p:expr) => {
        secp256k1_ge_storage {
            x: SECP256K1_FE_STORAGE_CONST($a as u64, $b as u64, $c as u64, $d as u64, $e as u64, $f as u64, $g as u64, $h as u64),
            y: SECP256K1_FE_STORAGE_CONST($i as u64, $j as u64, $k as u64, $l as u64, $m as u64, $n as u64, $o as u64, $p as u64),
        }
    }
}

// fn SECP256K1_GE_STORAGE_CONST(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32, i: u32, j: u32, k: u32, l: u32, m: u32, n: u32, o: u32, p: u32) -> secp256k1_ge_storage {
//     secp256k1_ge_storage {
//         x: SECP256K1_FE_STORAGE_CONST(a as u64,b as u64,c as u64,d as u64,e as u64,f as u64,g as u64,h as u64),
//         y: SECP256K1_FE_STORAGE_CONST(i as u64,j as u64,k as u64,l as u64, m as u64, n as u64, o as u64,p as u64),
//     }
// }

//fn SECP256K1_GE_STORAGE_CONST_GET(t: secp256k1_ge_storage) -> (secp256k1_fe_storage, secp256k1_fe_storage) {
//    (SECP256K1_FE_STORAGE_CONST_GET!(t.x), SECP256K1_FE_STORAGE_CONST_GET!(t.y))
//}

fn SECP256K1_G_ORDER_13() -> secp256k1_ge {
    SECP256K1_GE_CONST( 0xc3459c3d, 0x35326167, 0xcd86cce8, 0x07a2417f,
        0x5b8bd567, 0xde8538ee, 0x0d507b0c, 0xd128f5bb,
        0x8e467fec, 0xcd30000a, 0x6cc1184e, 0x25d382c2,
        0xa2f4494e, 0x2fbe9abc, 0x8b64abac, 0xd005fb24)
}

fn SECP256K1_G_ORDER_199() -> secp256k1_ge {
    SECP256K1_GE_CONST(
        0x226e653f, 0xc8df7744, 0x9bacbf12, 0x7d1dcbf9,
        0x87f05b2a, 0xe7edbd28, 0x1f564575, 0xc48dcf18,
        0xa13872c2, 0xe933bb17, 0x5d9ffd5b, 0xb5b6e10c,
        0x57fe3c00, 0xbaaaa15a, 0xe003ec3e, 0x9c269bae)
}

/** Generator for secp256k1, value 'g' defined in
 *  "Standards for Efficient Cryptography" (SEC2) 2.7.1.
 */
fn SECP256K1_G() -> secp256k1_ge {
     SECP256K1_GE_CONST(
        0x79BE667E, 0xF9DCBBAC, 0x55A06295, 0xCE870B07,
        0x029BFCDB, 0x2DCE28D9, 0x59F2815B, 0x16F81798,
        0x483ADA77, 0x26A3C465, 0x5DA4FBFC, 0x0E1108A8,
        0xFD17B448, 0xA6855419, 0x9C47D08F, 0xFB10D4B8
    )
}

/* These exhaustive group test orders and generators are chosen such that:
 * - The field size is equal to that of secp256k1, so field code is the same.
 * - The curve equation is of the form y^2=x^3+B for some constant B.
 * - The subgroup has a generator 2*P, where P.x=1.
 * - The subgroup has size less than 1000 to permit exhaustive testing.
 * - The subgroup admits an endomorphism of the form lambda*(x,y) == (beta*x,y).
 *
 * These parameters are generated using sage/gen_exhaustive_groups.sage.
 */
//#if defined(EXHAUSTIVE_TEST_ORDER)
//#  if EXHAUSTIVE_TEST_ORDER == 13
#[cfg(EXHAUSTIVE_TEST_ORDER = "13")]
pub const  secp256k1_ge_const_g: secp256k1_ge = SECP256K1_G_ORDER_13();

#[cfg(EXHAUSTIVE_TEST_ORDER = "13")]
const secp256k1_fe_const_b: secp256k1_fe = SECP256K1_FE_CONST(
    0x3d3486b2, 0x159a9ca5, 0xc75638be, 0xb23a69bc,
    0x946a45ab, 0x24801247, 0xb4ed2b8e, 0x26b6a417
);

//#  elif EXHAUSTIVE_TEST_ORDER == 199
#[cfg(EXHAUSTIVE_TEST_ORDER = "199")]
pub const secp256k1_ge_const_g: secp256k1_ge = SECP256K1_G_ORDER_199();
#[cfg(EXHAUSTIVE_TEST_ORDER = "199")]
const secp256k1_fe_const_b: secp256k1_fe = SECP256K1_FE_CONST(
    0x2cca28fa, 0xfc614b80, 0x2a3db42b, 0x00ba00b1,
    0xbea8d943, 0xdace9ab2, 0x9536daea, 0x0074defb
);

pub const secp256k1_ge_const_g: secp256k1_ge = SECP256K1_G();

const secp256k1_fe_const_b: secp256k1_fe = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 7);


//static void secp256k1_ge_set_gej_zinv(secp256k1_ge *r, const secp256k1_gej *a, const secp256k1_fe *zi) {
fn secp256k1_ge_set_gej_zinv(r: &mut secp256k1_ge, a: &secp256k1_gej, zi: &secp256k1_fe) {
    let mut zi2: secp256k1_fe;
    let mut zi3: secp256k1_fe;
    //VERIFY_CHECK(!a->infinity);
    secp256k1_fe_sqr(&mut zi2, zi);
    secp256k1_fe_mul(&mut zi3, &zi2, zi);
    secp256k1_fe_mul(&mut r.x, &a.x, &zi2);
    secp256k1_fe_mul(&mut r.y, &a.y, &zi3);
    r.infinity = a.infinity;
}

//static void secp256k1_ge_set_xy(secp256k1_ge *r, const secp256k1_fe *x, const secp256k1_fe *y) {
fn secp256k1_ge_set_xy(r: &mut secp256k1_ge, x: &secp256k1_fe, y: &secp256k1_fe) {
    r.infinity = 0;
    r.x = *x;
    r.y = *y;
}

fn secp256k1_ge_is_infinity(a: &secp256k1_ge) -> bool {
    return a.infinity != 0;
}

pub fn secp256k1_ge_neg(r: &mut secp256k1_ge, a: &secp256k1_ge) {
    *r = *a;
    secp256k1_fe_normalize_weak(&mut r.y);
    secp256k1_fe_negate(&mut r.y, &r.y, 1);
}

pub fn secp256k1_ge_set_gej(r: &mut secp256k1_ge, a: &secp256k1_gej) {
    //secp256k1_fe z2, z3;
    let mut z2: secp256k1_fe;
    let mut z3: secp256k1_fe;
    r.infinity = a.infinity;
    secp256k1_fe_inv(&mut a.z, &a.z);
    secp256k1_fe_sqr(&mut z2, &a.z);
    secp256k1_fe_mul(&mut z3, &a.z, &z2);
    secp256k1_fe_mul(&mut a.x, &a.x, &z2);
    secp256k1_fe_mul(&mut a.y, &a.y, &z3);
    secp256k1_fe_set_int(&mut a.z, 1);
    r.x = a.x;
    r.y = a.y;
}

//static void secp256k1_ge_set_gej_var(secp256k1_ge *r, secp256k1_gej *a) {
fn secp256k1_ge_set_gej_var(r: &mut secp256k1_ge, a: &secp256k1_gej) {
    let mut z2: secp256k1_fe;
    let mut z3: secp256k1_fe;
    if (a.infinity != 0) {
        secp256k1_ge_set_infinity(r);
        return;
    }
    secp256k1_fe_inv_var(&mut a.z, &a.z);
    secp256k1_fe_sqr(&mut z2, &a.z);
    secp256k1_fe_mul(&mut z3, &a.z, &z2);
    secp256k1_fe_mul(&mut a.x, &a.x, &z2);
    secp256k1_fe_mul(&mut a.y, &a.y, &z3);
    secp256k1_fe_set_int(&mut a.z, 1);
    secp256k1_ge_set_xy(r, &a.x, &a.y);
}

//static void secp256k1_ge_set_all_gej_var(secp256k1_ge *r, const secp256k1_gej *a, size_t len) {
fn secp256k1_ge_set_all_gej_var(r: &mut [secp256k1_ge], a: &[secp256k1_gej], len: usize) {
    let mut u: secp256k1_fe;
    let mut i: usize;
    let mut last_i: usize = usize::MAX;

    for i in 0..len {
        if (a[i].infinity != 0) {
            secp256k1_ge_set_infinity(&mut r[i]);
        } else {
            /* Use destination's x coordinates as scratch space */
            if (last_i == usize::MAX) {
                r[i].x = a[i].z;
            } else {
                secp256k1_fe_mul(&mut r[i].x, &r[last_i].x, &a[i].z);
            }
            last_i = i;
        }
    }
    if (last_i == usize::MAX) {
        return;
    }
    secp256k1_fe_inv_var(&mut u, &r[last_i].x);

    i = last_i;
    while (i > 0) {
        i-=1;
        if (a[i].infinity == 0) {
            secp256k1_fe_mul(&mut r[last_i].x, &r[i].x, &u);
            secp256k1_fe_mul(&mut u, &u, &a[last_i].z);
            last_i = i;
        }
    }
    #[cfg(feature = "verify")] VERIFY_CHECK(!a[last_i].infinity);
    r[last_i].x = u;

    for i in 0..len {
        if (a[i].infinity == 0) {
            secp256k1_ge_set_gej_zinv(&mut r[i], &a[i], &r[i].x);
        }
    }
}

//static void secp256k1_ge_table_set_globalz(size_t len, secp256k1_ge *a, const secp256k1_fe *zr) {
fn secp256k1_ge_table_set_globalz(len: usize, a: &mut [secp256k1_ge], zr: &[secp256k1_fe]) {
    let mut i: usize = len - 1;
    let mut zs: secp256k1_fe;

    if (len > 0) {
        /* Ensure all y values are in weak normal form for fast negation of points */
        secp256k1_fe_normalize_weak(&mut a[i].y);
        zs = zr[i];

        /* Work our way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            let mut tmpa: secp256k1_gej;
            if (i != len - 1) {
                secp256k1_fe_mul(&mut zs, &zs, &zr[i]);
            }
            i-=1;
            tmpa.x = a[i].x;
            tmpa.y = a[i].y;
            tmpa.infinity = 0;
            secp256k1_ge_set_gej_zinv(&mut a[i], &tmpa, &zs);
        }
    }
}

//static void secp256k1_gej_set_infinity(secp256k1_gej *r) {
pub fn secp256k1_gej_set_infinity(r: &mut secp256k1_gej) {
    r.infinity = 1;
    secp256k1_fe_clear(&mut r.x);
    secp256k1_fe_clear(&mut r.y);
    secp256k1_fe_clear(&mut r.z);
}

//static void secp256k1_ge_set_infinity(secp256k1_ge *r) {
fn secp256k1_ge_set_infinity(r: &mut secp256k1_ge) {
    r.infinity = 1;
    secp256k1_fe_clear(&mut r.x);
    secp256k1_fe_clear(&mut r.y);
}

//static void secp256k1_gej_clear(secp256k1_gej *r) {
pub fn secp256k1_gej_clear(r: &mut secp256k1_gej) {
    r.infinity = 0;
    secp256k1_fe_clear(&mut r.x);
    secp256k1_fe_clear(&mut r.y);
    secp256k1_fe_clear(&mut r.z);
}

//static void secp256k1_ge_clear(secp256k1_ge *r) {
pub fn secp256k1_ge_clear(r: &mut secp256k1_ge) {
    r.infinity = 0;
    secp256k1_fe_clear(&mut r.x);
    secp256k1_fe_clear(&mut r.y);
}

//static int secp256k1_ge_set_xo_var(secp256k1_ge *r, const secp256k1_fe *x, int odd) {
fn secp256k1_ge_set_xo_var(r: &mut secp256k1_ge, x: &secp256k1_fe, odd: i32) -> i32 {
    //secp256k1_fe x2, x3;
    let mut x2: secp256k1_fe;
    let mut x3: secp256k1_fe;
    r.x = *x;
    secp256k1_fe_sqr(&mut x2, x);
    secp256k1_fe_mul(&mut x3, x, &x2);
    r.infinity = 0;
    secp256k1_fe_add(&mut x3, &secp256k1_fe_const_b);
    if (!secp256k1_fe_sqrt(&mut r.y, &x3)) {
        return 0;
    }
    secp256k1_fe_normalize_var(&mut r.y);
    if (secp256k1_fe_is_odd(&r.y) != odd) {
        secp256k1_fe_negate(&mut r.y, &r.y, 1);
    }
    return 1;
}

//static void secp256k1_gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a) {
pub fn secp256k1_gej_set_ge(r: &mut secp256k1_gej, a: &secp256k1_ge) {
   r.infinity = a.infinity;
   r.x = a.x;
   r.y = a.y;
   secp256k1_fe_set_int(&mut r.z, 1);
}

//static int secp256k1_gej_eq_x_var(const secp256k1_fe *x, const secp256k1_gej *a) {
fn secp256k1_gej_eq_x_var(x: &secp256k1_fe, a: &secp256k1_gej) -> i32 {
    //secp256k1_fe r, r2;
    let mut r: secp256k1_fe;
    let mut r2: secp256k1_fe;
    //VERIFY_CHECK(!a.infinity);
    secp256k1_fe_sqr(&mut r, &a.z); secp256k1_fe_mul(&mut r, &r, x);
    r2 = a.x; secp256k1_fe_normalize_weak(&mut r2);
    return secp256k1_fe_equal_var(&r, &r2);
}

//static void secp256k1_gej_neg(secp256k1_gej *r, const secp256k1_gej *a) {
pub fn secp256k1_gej_neg(r: &mut secp256k1_gej, a: &secp256k1_gej) {
    r.infinity = a.infinity;
    r.x = a.x;
    r.y = a.y;
    r.z = a.z;
    secp256k1_fe_normalize_weak(&mut r.y);
    secp256k1_fe_negate(&mut r.y, &r.y, 1);
}

//static int secp256k1_gej_is_infinity(const secp256k1_gej *a) {
pub fn secp256k1_gej_is_infinity(a: &secp256k1_gej) -> i32 {
    return a.infinity;
}

//static int secp256k1_ge_is_valid_var(const secp256k1_ge *a) {
fn secp256k1_ge_is_valid_var(a: &secp256k1_ge) -> i32 {
    //secp256k1_fe y2, x3;
    let y2: secp256k1_fe;
    let x3: secp256k1_fe;
    if (a.infinity != 0) {
        return 0;
    }
    /* y^2 = x^3 + 7 */
    secp256k1_fe_sqr(&mut y2, &a.y);
    secp256k1_fe_sqr(&mut x3, &a.x); secp256k1_fe_mul(&mut x3, &x3, &a.x);
    secp256k1_fe_add(&mut x3, &secp256k1_fe_const_b);
    secp256k1_fe_normalize_weak(&mut x3);
    return secp256k1_fe_equal_var(&y2, &x3);
}

//static SECP256K1_INLINE void secp256k1_gej_double(secp256k1_gej *r, const secp256k1_gej *a) {
fn secp256k1_gej_double(r: &mut secp256k1_gej, a: &secp256k1_gej) {
    /* Operations: 3 mul, 4 sqr, 8 add/half/mul_int/negate */
    let mut l: secp256k1_fe;
    let mut s: secp256k1_fe;
    let mut t: secp256k1_fe;

    r.infinity = a.infinity;

    /* Formula used:
     * L = (3/2) * X1^2
     * S = Y1^2
     * T = -X1*S
     * X3 = L^2 + 2*T
     * Y3 = -(L*(X3 + T) + S^2)
     * Z3 = Y1*Z1
     */

    secp256k1_fe_mul(&mut r.z, &a.z, &a.y); /* Z3 = Y1*Z1 (1) */
    secp256k1_fe_sqr(&mut s, &a.y);           /* S = Y1^2 (1) */
    secp256k1_fe_sqr(&mut l, &a.x);           /* L = X1^2 (1) */
    secp256k1_fe_mul_int(&mut l, 3);           /* L = 3*X1^2 (3) */
    secp256k1_fe_half(&mut l);                 /* L = 3/2*X1^2 (2) */
    secp256k1_fe_negate(&mut t, &s, 1);        /* T = -S (2) */
    secp256k1_fe_mul(&mut t, &t, &a.x);       /* T = -X1*S (1) */
    secp256k1_fe_sqr(&mut r.x, &l);           /* X3 = L^2 (1) */
    secp256k1_fe_add(&mut r.x, &t);           /* X3 = L^2 + T (2) */
    secp256k1_fe_add(&mut r.x, &t);           /* X3 = L^2 + 2*T (3) */
    secp256k1_fe_sqr(&mut s, &s);              /* S' = S^2 (1) */
    secp256k1_fe_add(&mut t, &r.x);           /* T' = X3 + T (4) */
    secp256k1_fe_mul(&mut r.y, &t, &l);       /* Y3 = L*(X3 + T) (1) */
    secp256k1_fe_add(&mut r.y, &s);           /* Y3 = L*(X3 + T) + S^2 (2) */
    secp256k1_fe_negate(&mut r.y, &r.y, 2);  /* Y3 = -(L*(X3 + T) + S^2) (3) */
}

//static void secp256k1_gej_double_var(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr) {
fn secp256k1_gej_double_var(r: &mut secp256k1_gej, a: &secp256k1_gej, rzr: Option<&mut secp256k1_fe>) {
    /** For secp256k1, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
     *  Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a point on y^2 = x^3 + 7 to have
     *  y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
     *
     *  Having said this, if this function receives a point on a sextic twist, e.g. by
     *  a fault attack, it is possible for y to be 0. This happens for y^2 = x^3 + 6,
     *  since -6 does have a cube root mod p. For this point, this function will not set
     *  the infinity flag even though the point doubles to infinity, and the result
     *  point will be gibberish (z = 0 but infinity = 0).
     */
    if (a.infinity != 0) {
        secp256k1_gej_set_infinity(r);
        // TODO: make this an Option?
        if rzr.is_some() {
            secp256k1_fe_set_int(rzr.unwrap(), 1);
        }
        return;
    }

    if rzr.is_some() {
        let rzr = rzr.unwrap();
        *rzr = a.y;
        secp256k1_fe_normalize_weak(rzr);
    }

    secp256k1_gej_double(r, a);
}

//static void secp256k1_gej_add_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_gej *b, secp256k1_fe *rzr) {
fn secp256k1_gej_add_var(r: &mut secp256k1_gej, a: &secp256k1_gej, b: &secp256k1_gej, rzr: Option<&mut secp256k1_fe>) {
    /* 12 mul, 4 sqr, 11 add/negate/normalizes_to_zero (ignoring special cases) */
    //secp256k1_fe z22, z12, u1, u2, s1, s2, h, i, h2, h3, t;
    let mut z22: secp256k1_fe;
    let mut z12: secp256k1_fe;
    let mut u1: secp256k1_fe;
    let mut u2: secp256k1_fe;
    let mut s1: secp256k1_fe;
    let mut s2: secp256k1_fe;
    let mut h: secp256k1_fe;
    let mut i: secp256k1_fe;
    let mut h2: secp256k1_fe;
    let mut h3: secp256k1_fe;
    let mut t: secp256k1_fe;

    if a.infinity != 0 {
        VERIFY_CHECK(rzr.is_none());
        *r = *b;
        return;
    }
    if b.infinity != 0 {
        if rzr.is_some() {
            secp256k1_fe_set_int(rzr.unwrap(), 1);
        }
        *r = *a;
        return;
    }

    secp256k1_fe_sqr(&mut z22, &b.z);
    secp256k1_fe_sqr(&mut z12, &a.z);
    secp256k1_fe_mul(&mut u1, &a.x, &z22);
    secp256k1_fe_mul(&mut u2, &b.x, &z12);
    secp256k1_fe_mul(&mut s1, &a.y, &z22); secp256k1_fe_mul(&mut s1, &s1, &b.z);
    secp256k1_fe_mul(&mut s2, &b.y, &z12); secp256k1_fe_mul(&mut s2, &s2, &a.z);
    secp256k1_fe_negate(&mut h, &u1, 1); secp256k1_fe_add(&mut h, &u2);
    secp256k1_fe_negate(&mut i, &s2, 1); secp256k1_fe_add(&mut i, &s1);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var(r, a, rzr);
        } else {
            if rzr.is_some() {
                secp256k1_fe_set_int(rzr.unwrap(), 0);
            }
            secp256k1_gej_set_infinity(r);
        }
        return;
    }

    r.infinity = 0;
    secp256k1_fe_mul(&mut t, &h, &b.z);
    if rzr.is_some() {
        let rzr = rzr.unwrap();
        *rzr = t;
    }
    secp256k1_fe_mul(&mut r.z, &a.z, &t);

    secp256k1_fe_sqr(&mut h2, &h);
    secp256k1_fe_negate(&mut h2, &h2, 1);
    secp256k1_fe_mul(&mut h3, &h2, &h);
    secp256k1_fe_mul(&mut t, &u1, &h2);

    secp256k1_fe_sqr(&mut r.x, &i);
    secp256k1_fe_add(&mut r.x, &h3);
    secp256k1_fe_add(&mut r.x, &t);
    secp256k1_fe_add(&mut r.x, &t);

    secp256k1_fe_add(&mut t, &r.x);
    secp256k1_fe_mul(&mut r.y, &t, &i);
    secp256k1_fe_mul(&mut h3, &h3, &s1);
    secp256k1_fe_add(&mut r.y, &h3);
}

//static void secp256k1_gej_add_ge_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, secp256k1_fe *rzr) {
fn secp256k1_gej_add_ge_var(r: &mut secp256k1_gej, a: &secp256k1_gej, b: &secp256k1_ge, rzr: &mut secp256k1_fe) {
    /* 8 mul, 3 sqr, 13 add/negate/normalize_weak/normalizes_to_zero (ignoring special cases) */
    //secp256k1_fe z12, u1, u2, s1, s2, h, i, h2, h3, t;
    let mut z12: secp256k1_fe;
    let mut u1: secp256k1_fe;
    let mut u2: secp256k1_fe;
    let mut s1: secp256k1_fe;
    let mut s2: secp256k1_fe;
    let mut h: secp256k1_fe;
    let mut i: secp256k1_fe;
    let mut h2: secp256k1_fe;
    let mut h3: secp256k1_fe;
    let mut t: secp256k1_fe;

    if a.infinity != 0 {
        //VERIFY_CHECK(rzr == NULL);
        secp256k1_gej_set_ge(r, b);
        return;
    }
    if b.infinity != 0 {
        // TODO: make option?
        //if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        //}
        *r = *a;
        return;
    }

    secp256k1_fe_sqr(&mut z12, &a.z);
    u1 = a.x; secp256k1_fe_normalize_weak(&mut u1);
    secp256k1_fe_mul(&mut u2, &b.x, &z12);
    s1 = a.y; secp256k1_fe_normalize_weak(&mut s1);
    secp256k1_fe_mul(&mut s2, &b.y, &z12); secp256k1_fe_mul(&mut s2, &s2, &a.z);
    secp256k1_fe_negate(&mut h, &u1, 1); secp256k1_fe_add(&mut h, &u2);
    secp256k1_fe_negate(&mut i, &s2, 1); secp256k1_fe_add(&mut i, &s1);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var(r, a, rzr);
        } else {
            //if (rzr != NULL) {
                secp256k1_fe_set_int(rzr, 0);
            //}
            secp256k1_gej_set_infinity(r);
        }
        return;
    }

    r.infinity = 0;
    // TODO: make option?
    //if (rzr != NULL) {
        *rzr = h;
    //}
    secp256k1_fe_mul(&mut r.z, &a.z, &h);

    secp256k1_fe_sqr(&mut h2, &h);
    secp256k1_fe_negate(&mut h2, &h2, 1);
    secp256k1_fe_mul(&mut h3, &h2, &h);
    secp256k1_fe_mul(&mut t, &u1, &h2);

    secp256k1_fe_sqr(&mut r.x, &i);
    secp256k1_fe_add(&mut r.x, &h3);
    secp256k1_fe_add(&mut r.x, &t);
    secp256k1_fe_add(&mut r.x, &t);

    secp256k1_fe_add(&mut t, &r.x);
    secp256k1_fe_mul(&mut r.y, &t, &i);
    secp256k1_fe_mul(&mut h3, &h3, &s1);
    secp256k1_fe_add(&mut r.y, &h3);
}

//static void secp256k1_gej_add_zinv_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, const secp256k1_fe *bzinv) {
fn secp256k1_gej_add_zinv_var(r: &mut secp256k1_gej, a: &secp256k1_gej, b: &secp256k1_ge, bzinv: &secp256k1_fe) {
    /* 9 mul, 3 sqr, 13 add/negate/normalize_weak/normalizes_to_zero (ignoring special cases) */
    let mut az: secp256k1_fe;
    let mut z12: secp256k1_fe;
    let mut u1: secp256k1_fe;
    let mut u2: secp256k1_fe;
    let mut s1: secp256k1_fe;
    let mut s2: secp256k1_fe;
    let mut h: secp256k1_fe;
    let mut i: secp256k1_fe;
    let mut h2: secp256k1_fe;
    let mut h3: secp256k1_fe;
    let mut t: secp256k1_fe;

    if a.infinity {
        //secp256k1_fe bzinv2, bzinv3;
        let mut bzinv2: secp256k1_fe;
        let mut bzinv3: secp256k1_fe;
        r.infinity = b.infinity;
        secp256k1_fe_sqr(&mut bzinv2, bzinv);
        secp256k1_fe_mul(&mut bzinv3, &bzinv2, bzinv);
        secp256k1_fe_mul(&mut r.x, &b.x, &bzinv2);
        secp256k1_fe_mul(&mut r.y, &b.y, &bzinv3);
        secp256k1_fe_set_int(&mut r.z, 1);
        return;
    }
    if (b.infinity) {
        *r = *a;
        return;
    }

    /** We need to calculate (rx,ry,rz) = (ax,ay,az) + (bx,by,1/bzinv). Due to
     *  secp256k1's isomorphism we can multiply the Z coordinates on both sides
     *  by bzinv, and get: (rx,ry,rz*bzinv) = (ax,ay,az*bzinv) + (bx,by,1).
     *  This means that (rx,ry,rz) can be calculated as
     *  (ax,ay,az*bzinv) + (bx,by,1), when not applying the bzinv factor to rz.
     *  The variable az below holds the modified Z coordinate for a, which is used
     *  for the computation of rx and ry, but not for rz.
     */
    secp256k1_fe_mul(&mut az, &a.z, bzinv);

    secp256k1_fe_sqr(&mut z12, &az);
    u1 = a.x; secp256k1_fe_normalize_weak(&mut u1);
    secp256k1_fe_mul(&mut u2, &b.x, &z12);
    s1 = a.y; secp256k1_fe_normalize_weak(&mut s1);
    secp256k1_fe_mul(&mut s2, &b.y, &z12); secp256k1_fe_mul(&mut s2, &s2, &az);
    secp256k1_fe_negate(&mut h, &u1, 1); secp256k1_fe_add(&mut h, &u2);
    secp256k1_fe_negate(&mut i, &s2, 1); secp256k1_fe_add(&mut i, &s1);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var(r, a, None);
        } else {
            secp256k1_gej_set_infinity(r);
        }
        return;
    }

    r.infinity = 0;
    secp256k1_fe_mul(&mut r.z, &a.z, &h);

    secp256k1_fe_sqr(&mut h2, &h);
    secp256k1_fe_negate(&h2, &h2, 1);
    secp256k1_fe_mul(&mut h3, &h2, &h);
    secp256k1_fe_mul(&mut t, &u1, &h2);

    secp256k1_fe_sqr(&mut r.x, &i);
    secp256k1_fe_add(&r.x, &h3);
    secp256k1_fe_add(&r.x, &t);
    secp256k1_fe_add(&r.x, &t);

    secp256k1_fe_add(&t, &r.x);
    secp256k1_fe_mul(&mut r.y, &t, &i);
    secp256k1_fe_mul(&mut h3, &h3, &s1);
    secp256k1_fe_add(&r.y, &h3);
}


//static void secp256k1_gej_add_ge(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b) {
pub fn secp256k1_gej_add_ge(r: &mut secp256k1_gej, a: &secp256k1_gej, b: &secp256k1_ge) {
    /* Operations: 7 mul, 5 sqr, 24 add/cmov/half/mul_int/negate/normalize_weak/normalizes_to_zero */
    //secp256k1_fe zz, u1, u2, s1, s2, t, tt, m, n, q, rr;
    let mut zz: secp256k1_fe;
    let mut u1: secp256k1_fe;
    let mut u2: secp256k1_fe;
    let mut s1: secp256k1_fe;
    let mut s2: secp256k1_fe;
    let mut t: secp256k1_fe;
    let mut tt: secp256k1_fe;
    let mut m: secp256k1_fe;
    let mut n: secp256k1_fe;
    let mut q: secp256k1_fe;
    let mut rr: secp256k1_fe;
    let mut m_alt: secp256k1_fe;
    let mut rr_alt: secp256k1_fe;
    
    let mut infinity: i32;
    let mut degenerate: i32;

    //VERIFY_CHECK(!b.infinity);
    //VERIFY_CHECK(a.infinity == 0 || a.infinity == 1);

    /** In:
     *    Eric Brier and Marc Joye, Weierstrass Elliptic Curves and Side-Channel Attacks.
     *    In D. Naccache and P. Paillier, Eds., Public Key Cryptography, vol. 2274 of Lecture Notes in Computer Science, pages 335-345. Springer-Verlag, 2002.
     *  we find as solution for a unified addition/doubling formula:
     *    lambda = ((x1 + x2)^2 - x1 * x2 + a) / (y1 + y2), with a = 0 for secp256k1's curve equation.
     *    x3 = lambda^2 - (x1 + x2)
     *    2*y3 = lambda * (x1 + x2 - 2 * x3) - (y1 + y2).
     *
     *  Substituting x_i = Xi / Zi^2 and yi = Yi / Zi^3, for i=1,2,3, gives:
     *    U1 = X1*Z2^2, U2 = X2*Z1^2
     *    S1 = Y1*Z2^3, S2 = Y2*Z1^3
     *    Z = Z1*Z2
     *    T = U1+U2
     *    M = S1+S2
     *    Q = -T*M^2
     *    R = T^2-U1*U2
     *    X3 = R^2+Q
     *    Y3 = -(R*(2*X3+Q)+M^4)/2
     *    Z3 = M*Z
     *  (Note that the paper uses xi = Xi / Zi and yi = Yi / Zi instead.)
     *
     *  This formula has the benefit of being the same for both addition
     *  of distinct points and doubling. However, it breaks down in the
     *  case that either point is infinity, or that y1 = -y2. We handle
     *  these cases in the following ways:
     *
     *    - If b is infinity we simply bail by means of a VERIFY_CHECK.
     *
     *    - If a is infinity, we detect this, and at the end of the
     *      computation replace the result (which will be meaningless,
     *      but we compute to be constant-time) with b.x : b.y : 1.
     *
     *    - If a = -b, we have y1 = -y2, which is a degenerate case.
     *      But here the answer is infinity, so we simply set the
     *      infinity flag of the result, overriding the computed values
     *      without even needing to cmov.
     *
     *    - If y1 = -y2 but x1 != x2, which does occur thanks to certain
     *      properties of our curve (specifically, 1 has nontrivial cube
     *      roots in our field, and the curve equation has no x coefficient)
     *      then the answer is not infinity but also not given by the above
     *      equation. In this case, we cmov in place an alternate expression
     *      for lambda. Specifically (y1 - y2)/(x1 - x2). Where both these
     *      expressions for lambda are defined, they are equal, and can be
     *      obtained from each other by multiplication by (y1 + y2)/(y1 + y2)
     *      then substitution of x^3 + 7 for y^2 (using the curve equation).
     *      For all pairs of nonzero points (a, b) at least one is defined,
     *      so this covers everything.
     */

    secp256k1_fe_sqr(&mut zz, &a.z);                       /* z = Z1^2 */
    u1 = a.x; secp256k1_fe_normalize_weak(&mut u1);        /* u1 = U1 = X1*Z2^2 (1) */
    secp256k1_fe_mul(&mut u2, &b.x, &zz);                  /* u2 = U2 = X2*Z1^2 (1) */
    s1 = a.y; secp256k1_fe_normalize_weak(&mut s1);        /* s1 = S1 = Y1*Z2^3 (1) */
    secp256k1_fe_mul(&mut s2, &b.y, &zz);                  /* s2 = Y2*Z1^2 (1) */
    secp256k1_fe_mul(&mut s2, &s2, &a.z);                  /* s2 = S2 = Y2*Z1^3 (1) */
    t = u1; secp256k1_fe_add(&mut t, &u2);                  /* t = T = U1+U2 (2) */
    m = s1; secp256k1_fe_add(&mut m, &s2);                  /* m = M = S1+S2 (2) */
    secp256k1_fe_sqr(&mut rr, &t);                          /* rr = T^2 (1) */
    secp256k1_fe_negate(&mut m_alt, &u2, 1);                /* Malt = -X2*Z1^2 */
    secp256k1_fe_mul(&mut tt, &u1, &m_alt);                 /* tt = -U1*U2 (2) */
    secp256k1_fe_add(&mut rr, &tt);                         /* rr = R = T^2-U1*U2 (3) */
    /* If lambda = R/M = 0/0 we have a problem (except in the "trivial"
     *  case that Z = z1z2 = 0, and this is special-cased later on).
     */
    degenerate = secp256k1_fe_normalizes_to_zero(&m) &
                 secp256k1_fe_normalizes_to_zero(&rr);
    /* This only occurs when y1 == -y2 and x1^3 == x2^3, but x1 != x2.
     * This means either x1 == beta*x2 or beta*x1 == x2, where beta is
     * a nontrivial cube root of one. In either case, an alternate
     * non-indeterminate expression for lambda is (y1 - y2)/(x1 - x2),
     * so we set R/M equal to this. */
    rr_alt = s1;
    secp256k1_fe_mul_int(&mut rr_alt, 2);       /* rr = Y1*Z2^3 - Y2*Z1^3 (2) */
    secp256k1_fe_add(&mut m_alt, &u1);          /* Malt = X1*Z2^2 - X2*Z1^2 */

    secp256k1_fe_cmov(&mut rr_alt, &rr, !degenerate);
    secp256k1_fe_cmov(&mut m_alt, &m, !degenerate);
    /* Now Ralt / Malt = lambda and is guaranteed not to be 0/0.
     * From here on out Ralt and Malt represent the numerator
     * and denominator of lambda; R and M represent the explicit
     * expressions x1^2 + x2^2 + x1x2 and y1 + y2. */
    secp256k1_fe_sqr(&mut n, &m_alt);                       /* n = Malt^2 (1) */
    secp256k1_fe_negate(&mut q, &t, 2);                     /* q = -T (3) */
    secp256k1_fe_mul(&mut q, &q, &n);                       /* q = Q = -T*Malt^2 (1) */
    /* These two lines use the observation that either M == Malt or M == 0,
     * so M^3 * Malt is either Malt^4 (which is computed by squaring), or
     * zero (which is "computed" by cmov). So the cost is one squaring
     * versus two multiplications. */
    secp256k1_fe_sqr(&mut n, &n);
    secp256k1_fe_cmov(&mut n, &m, degenerate);              /* n = M^3 * Malt (2) */
    secp256k1_fe_sqr(&mut t, &rr_alt);                      /* t = Ralt^2 (1) */
    secp256k1_fe_mul(&mut r.z, &a.z, &m_alt);             /* r.z = Z3 = Malt*Z (1) */
    infinity = secp256k1_fe_normalizes_to_zero(&r.z) & !a.infinity;
    secp256k1_fe_add(&mut t, &q);                           /* t = Ralt^2 + Q (2) */
    r.x = t;                                           /* r.x = X3 = Ralt^2 + Q (2) */
    secp256k1_fe_mul_int(&mut t, 2);                        /* t = 2*X3 (4) */
    secp256k1_fe_add(&mut t, &q);                           /* t = 2*X3 + Q (5) */
    secp256k1_fe_mul(&mut t, &t, &rr_alt);                  /* t = Ralt*(2*X3 + Q) (1) */
    secp256k1_fe_add(&mut t, &n);                           /* t = Ralt*(2*X3 + Q) + M^3*Malt (3) */
    secp256k1_fe_negate(&mut r.y, &t, 3);                  /* r.y = -(Ralt*(2*X3 + Q) + M^3*Malt) (4) */
    secp256k1_fe_half(&mut r.y);                           /* r.y = Y3 = -(Ralt*(2*X3 + Q) + M^3*Malt)/2 (3) */

    /** In case a.infinity == 1, replace r with (b.x, b.y, 1). */
    secp256k1_fe_cmov(&mut r.x, &b.x, a.infinity);
    secp256k1_fe_cmov(&mut r.y, &b.y, a.infinity);
    secp256k1_fe_cmov(&mut r.z, &secp256k1_fe_one, a.infinity);
    r.infinity = infinity;
}

//static void secp256k1_gej_rescale(secp256k1_gej *r, const secp256k1_fe *s) {
fn sec256k1_gej_rescale(r: &mut secp256k1_gej, s: &secp256k1_fe) {
    /* Operations: 4 mul, 1 sqr */
    //secp256k1_fe zz;
    let mut zz: secp256k1_fe;
    //VERIFY_CHECK(!secp256k1_fe_is_zero(s));
    secp256k1_fe_sqr(&mut zz, s);
    secp256k1_fe_mul(&mut r.x, &r.x, &zz);                /* r.x *= s^2 */
    secp256k1_fe_mul(&mut r.y, &r.y, &zz);
    secp256k1_fe_mul(&mut r.y, &r.y, s);                  /* r.y *= s^3 */
    secp256k1_fe_mul(&mut r.z, &r.z, s);                  /* r.z *= s   */
}

//static void secp256k1_ge_to_storage(secp256k1_ge_storage *r, const secp256k1_ge *a) {
fn secp256k1_ge_to_storage(r: &mut secp256k1_ge_storage, a: &secp256k1_ge) {
    //secp256k1_fe x, y;
    let mut x: secp256k1_fe;
    let mut y: secp256k1_fe;
    //VERIFY_CHECK(!a.infinity);
    x = a.x;
    secp256k1_fe_normalize(&x);
    y = a.y;
    secp256k1_fe_normalize(&y);
    secp256k1_fe_to_storage(&r.x, &x);
    secp256k1_fe_to_storage(&r.y, &y);
}

//static void secp256k1_ge_from_storage(secp256k1_ge *r, const secp256k1_ge_storage *a) {
pub fn secp256k1_ge_from_storage(r: &mut secp256k1_ge, a: &secp256k1_ge_storage) {
    secp256k1_fe_from_storage(&r.x, &a.x);
    secp256k1_fe_from_storage(&r.y, &a.y);
    r.infinity = 0;
}

//static SECP256K1_INLINE void secp256k1_gej_cmov(secp256k1_gej *r, const secp256k1_gej *a, int flag) {
fn sec256k1_gej_cmov(r: &mut secp256k1_gej, a: &secp256k1_gej, flag: i32) {
    secp256k1_fe_cmov(&r.x, &a.x, flag);
    secp256k1_fe_cmov(&r.y, &a.y, flag);
    secp256k1_fe_cmov(&r.z, &a.z, flag);

    r.infinity ^= (r.infinity ^ a.infinity) & flag;
}

//static SECP256K1_INLINE void secp256k1_ge_storage_cmov(secp256k1_ge_storage *r, const secp256k1_ge_storage *a, int flag) {
pub fn secp256k1_ge_storage_cmov(r: &mut secp256k1_ge_storage, a: &secp256k1_ge_storage, flag: i32) {
    secp256k1_fe_storage_cmov(&r.x, &a.x, flag);
    secp256k1_fe_storage_cmov(&r.y, &a.y, flag);
}

//static void secp256k1_ge_mul_lambda(secp256k1_ge *r, const secp256k1_ge *a) {
fn secp256k1_ge_mul_lambda(r: &mut secp256k1_ge, a: &secp256k1_ge) {
    *r = *a;
    secp256k1_fe_mul(&mut r.x, &r.x, &secp256k1_const_beta);
}

//static int secp256k1_ge_is_in_correct_subgroup(const secp256k1_ge* ge) {
fn sec256k1_ge_is_in_correct_subgroup(ge: &secp256k1_ge) -> i32 {

#[cfg(feature = "EXHAUSTIVE_TEST_ORDER")]
    {
        let mut out: secp256k1_gej;
        let mut i: i32;

        /* A very simple EC multiplication ladder that avoids a dependency on ecmult. */
        secp256k1_gej_set_infinity(&out);
        for i in 0..32 {
            secp256k1_gej_double_var(&out, &out, NULL);
            todo!();
            //if ((((uint32_t)EXHAUSTIVE_TEST_ORDER) >> (31 - i)) & 1) {
            //    secp256k1_gej_add_ge_var(&out, &out, ge, NULL);
            //}
        }
        return secp256k1_gej_is_infinity(&out);
    }
#[cfg(not(feature = "EXHAUSTIVE_TEST_ORDER"))]
    {
        /* The real secp256k1 group has cofactor 1, so the subgroup is the entire curve. */
        return 1;
    }
}