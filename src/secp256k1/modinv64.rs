#![allow(warnings)]
// typedef struct {
//     int64_t v[5];
// } secp256k1_modinv64_signed62;
#[derive(Clone)]
pub struct secp256k1_modinv64_signed62 {
    pub v: [i64; 5],
}

impl secp256k1_modinv64_signed62 {
    pub fn new () -> Self {
        Self {
            v: [0i64; 5]
        }
    }
}

pub struct secp256k1_modinv64_modinfo {
    /* The modulus in signed62 notation, must be odd and in [3, 2^256]. */
    pub modulus: secp256k1_modinv64_signed62,
    /* modulus^{-1} mod 2^62 */
    pub modulus_inv62: u64,
}

pub fn secp256k1_modinv64_normalize_62(r: &mut secp256k1_modinv64_signed62, sign: i64, modinfo: &secp256k1_modinv64_modinfo) {
    let M62 = (u64::MAX >> 2) as i64;
    let mut r0 = r.v[0];
    let mut r1 = r.v[1];
    let mut r2 = r.v[2];
    let mut r3 = r.v[3];
    let mut r4 = r.v[4];
    let mut cond_add: i64 = 0;
    let mut cond_negate: i64 = 0;

    // #ifdef VERIFY
    // /* Verify that all limbs are in range (-2^62,2^62). */
    // int i;
    // for (i = 0; i < 5; ++i) {
    //     VERIFY_CHECK(r->v[i] >= -M62);
    //     VERIFY_CHECK(r->v[i] <= M62);
    // }
    // VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(r, 5, &modinfo->modulus, -2) > 0); /* r > -2*modulus */
    // VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(r, 5, &modinfo->modulus, 1) < 0); /* r < modulus */
    // #endif

    /* In a first step, add the modulus if the input is negative, and then negate if requested.
     * This brings r from range (-2*modulus,modulus) to range (-modulus,modulus). As all input
     * limbs are in range (-2^62,2^62), this cannot overflow an int64_t. Note that the right
     * shifts below are signed sign-extending shifts (see assumptions.h for tests that that is
     * indeed the behavior of the right shift operator). */
    cond_add = r4 >> 63;
    r0 += modinfo.modulus.v[0] & cond_add;
    r1 += modinfo.modulus.v[1] & cond_add;
    r2 += modinfo.modulus.v[2] & cond_add;
    r3 += modinfo.modulus.v[3] & cond_add;
    r4 += modinfo.modulus.v[4] & cond_add;
    cond_negate = sign >> 63;
    r0 = (r0 ^ cond_negate) - cond_negate;
    r1 = (r1 ^ cond_negate) - cond_negate;
    r2 = (r2 ^ cond_negate) - cond_negate;
    r3 = (r3 ^ cond_negate) - cond_negate;
    r4 = (r4 ^ cond_negate) - cond_negate;

    // In a second step add the modulus again if the result is still negative, bringing
    // r to range [0,modulus).
    cond_add = r4 >> 63;
    r0 += modinfo.modulus.v[0] & cond_add;
    r1 += modinfo.modulus.v[1] & cond_add;
    r2 += modinfo.modulus.v[2] & cond_add;
    r3 += modinfo.modulus.v[3] & cond_add;
    r4 += modinfo.modulus.v[4] & cond_add;
    // And propagate again.
    r1 += r0 >> 62; r0 &= M62;
    r2 += r1 >> 62; r1 &= M62;
    r3 += r2 >> 62; r2 &= M62;
    r4 += r3 >> 62; r3 &= M62;

    r.v[0] = r0;
    r.v[1] = r1;
    r.v[2] = r2;
    r.v[3] = r3;
    r.v[4] = r4;

    #[cfg(feature = "verify")] {
        VERIFY_CHECK(r0 >> 62 == 0);
        VERIFY_CHECK(r1 >> 62 == 0);
        VERIFY_CHECK(r2 >> 62 == 0);
        VERIFY_CHECK(r3 >> 62 == 0);
        VERIFY_CHECK(r4 >> 62 == 0);
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(r, 5, &modinfo.modulus, 0) >= 0); /* r >= 0 */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(r, 5, &modinfo.modulus, 1) < 0); /* r < modulus */
    }
}

/* Data type for transition matrices (see section 3 of explanation).
 *
 * t = [ u  v ]
 *     [ q  r ]
 */

struct secp256k1_modinv64_trans2x2 {
    u: u64,
    v: u64,
    q: u64,
    r: u64,
}

/* Compute the transition matrix and eta for 59 divsteps (where zeta=-(delta+1/2)).
 * Note that the transformation matrix is scaled by 2^62 and not 2^59.
 *
 * Input:  zeta: initial zeta
 *         f0:   bottom limb of initial f
 *         g0:   bottom limb of initial g
 * Output: t: transition matrix
 * Return: final zeta
 *
 * Implements the divsteps_n_matrix function from the explanation.
 */
fn secp256k1_modinv64_divsteps_59(mut zeta: i64, f0: u64, g0: u64, t: &mut secp256k1_modinv64_trans2x2) -> i64 {
    let mut u: u64 = 8;
    let mut v: u64 = 0;
    let mut q: u64 = 0;
    let mut r: u64 = 8;
    let mut c1: u64;
    let mut c2: u64;
    let mut f: u64 = f0;
    let mut g: u64 = g0;
    let mut x: u64;
    let mut y: u64;
    let mut z: u64;
    let mut i: i32;

    for i in 3..62 {
        #[cfg(feature = "verify")] {
            VERIFY_CHECK((f & 1) == 1); /* f must always be odd */
            VERIFY_CHECK((u * f0 + v * g0) == f << i);
            VERIFY_CHECK((q * f0 + r * g0) == g << i);
        }
        /* Compute conditional masks for (zeta < 0) and for (g & 1). */
        c1 = zeta as u64 >> 63;
        c2 = -(g as i64 & 1) as u64;
        /* Compute x,y,z, conditionally negated versions of f,u,v. */
        x = (f ^ c1) - c1;
        y = (u ^ c1) - c1;
        z = (v ^ c1) - c1;
        /* Conditionally add x,y,z to g,q,r. */
        g += x & c2;
        q += y & c2;
        r += z & c2;
        /* In what follows, c1 is a condition mask for (zeta < 0) and (g & 1). */
        c1 &= c2;
        /* Conditionally change zeta into -zeta-2 or zeta-1. */
        zeta = (zeta ^ c1 as i64) - 1;
        /* Conditionally add g,q,r to f,u,v. */
        f += g & c1;
        u += q & c1;
        v += r & c1;
        /* Shifts */
        g >>= 1;
        u <<= 1;
        v <<= 1;
        // Bounds on zeta that follow from the bounds on iteration
        #[cfg(feature = "verify")] {
            VERIFY_CHECK(zeta >= -591 && zeta <= 591);
        }
    }
    /* Return data in t and return value. */
    t.u = u;
    t.v = v;
    t.q = q;
    t.r = r;
    /* The determinant of t must be a power of two. This guarantees that multiplication with t
     * does not change the gcd of f and g, apart from adding a power-of-2 factor to it (which
     * will be divided out again). As each divstep's individual matrix has determinant 2, the
     * aggregate of 59 of them will have determinant 2^59. Multiplying with the initial
     * 8*identity (which has determinant 2^6) means the overall outputs has determinant
     * 2^65. */
    #[cfg(feature = "verify")] {
        VERIFY_CHECK((t.u as i128 * t.r as i128 - t.v as i128 * t.q as i128) == ((1 as i128) << 65));
    }
    return zeta;
}

/* Compute the transition matrix and eta for 62 divsteps (variable time, eta=-delta).
 *
 * Input:  eta: initial eta
 *         f0:  bottom limb of initial f
 *         g0:  bottom limb of initial g
 * Output: t: transition matrix
 * Return: final eta
 *
 * Implements the divsteps_n_matrix_var function from the explanation.
 */
fn secp256k1_modinv64_divsteps_62_var(mut eta: i64, f0: u64, g0: u64, t: &mut secp256k1_modinv64_trans2x2) -> i64 {
    let mut u: u64 = 1;
    let mut v: u64 = 0;
    let mut q: u64 = 0;
    let mut r: u64 = 1;
    let mut f: u64 = f0;
    let mut g: u64 = g0;
    let mut m: u64;
    let mut w: u32;
    let mut i: i32 = 62;
    let mut limit: i32;
    let mut zeros: i32;

    loop {
        /* Use a sentinel bit to count zeros only up to i. */
        zeros = (g | (u64::MAX << i)).trailing_zeros() as i32;
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= zeros as i64;
        i -= zeros;
        /* We're done once we've done 62 divsteps. */
        if i == 0 {
            break;
        }
        #[cfg(feature = "verify")] {
            VERIFY_CHECK((f & 1) == 1);
            VERIFY_CHECK((g & 1) == 1);
            VERIFY_CHECK((u * f0 + v * g0) == f << (62 - i));
            VERIFY_CHECK((q * f0 + r * g0) == g << (62 - i));
            VERIFY_CHECK(eta >= -745 && eta <= 745);
        }
        if eta < 0 {
            let mut tmp: u64;
            eta = -eta;
            tmp = f; f = g; g = -(tmp as i64) as u64;
            tmp = u; u = q; q = -(tmp as i64) as u64;
            tmp = v; v = r; r = -(tmp as i64) as u64;
             /* Use a formula to cancel out up to 6 bits of g. Also, no more than i can be cancelled
              * out (as we'd be done before that point), and no more than eta+1 can be done as its
              * will flip again once that happens. */
            limit = if ((eta + 1) as i32 > i as i32) { i } else { (eta + 1) as i32};
            #[cfg(feature = "verify")] {
                VERIFY_CHECK(limit > 0 && limit <= 62);
            }
            m = (u64::MAX >> (64 - limit)) & 63;
            //w = ((f * g * (f * f - 2)) & m) as u32;
            w = ((f.wrapping_mul(g).wrapping_mul((f.wrapping_mul(f)).wrapping_sub(2))) & m) as u32;
        } else {
            limit = if ((eta + 1) as i32 > i as i32) { i } else { (eta + 1) as i32};
            #[cfg(feature = "verify")] VERIFY_CHECK(limit > 0 && limit <= 62);
            m = (u64::MAX >> (64 - limit)) & 15;
            /* Find what multiple of f must be added to g to cancel its bottom min(limit, 4)
             * bits. */
            w = (f + (((f + 1) & 4) << 1)) as u32;
            w = ((-(w as i64) as u64 * g) & m) as u32;
        }
        g += f * w as u64;
        q += u * w as u64;
        r += v * w as u64;
        #[cfg(feature = "verify")] VERIFY_CHECK((g & m) == 0);
    }
    /* Return data in t and return value. */
    t.u = u;
    t.v = v;
    t.q = q;
    t.r = r;
    /* The determinant of t must be a power of two. This guarantees that multiplication with t
     * does not change the gcd of f and g, apart from adding a power-of-2 factor to it (which
     * will be divided out again). As each divstep's individual matrix has determinant 2, the
     * aggregate of 62 of them will have determinant 2^62. */
    #[cfg(feature = "verify")] {
        VERIFY_CHECK((t.u as i128 * t.r as i128 - t.v as i128 * t.q as i128) == ((1 as i128) << 62));
    }
    return eta;
}

/* Compute (t/2^62) * [d, e] mod modulus, where t is a transition matrix scaled by 2^62.
 *
 * On input and output, d and e are in range (-2*modulus,modulus). All output limbs will be in range
 * (-2^62,2^62).
 *
 * This implements the update_de function from the explanation.
 */
fn secp256k1_modinv64_update_de_62(d: &mut secp256k1_modinv64_signed62, e: &mut secp256k1_modinv64_signed62, t: &secp256k1_modinv64_trans2x2, modinfo: &secp256k1_modinv64_modinfo) {
    let M62 = (u64::MAX >> 2) as i64;
    let d0 = d.v[0];
    let d1 = d.v[1];
    let d2 = d.v[2];
    let d3 = d.v[3];
    let d4 = d.v[4];
    let e0 = e.v[0];
    let e1 = e.v[1];
    let e2 = e.v[2];
    let e3 = e.v[3];
    let e4 = e.v[4];
    let u = t.u;
    let v = t.v;
    let q = t.q;
    let r = t.r;
    let mut md: i64;
    let mut me: i64;
    let mut sd: i64;
    let mut se: i64;
    let mut cd: i128;
    let mut ce: i128;

    #[cfg(feature = "verify")] {
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(d, 5, &modinfo.modulus, -2) > 0); /* d > -2*modulus */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(d, 5, &modinfo.modulus, 1) < 0);  /* d <    modulus */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(e, 5, &modinfo.modulus, -2) > 0); /* e > -2*modulus */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(e, 5, &modinfo.modulus, 1) < 0);  /* e <    modulus */
        VERIFY_CHECK((secp256k1_modinv64_abs(u) + secp256k1_modinv64_abs(v)) >= 0); /* |u|+|v| doesn't overflow */
        VERIFY_CHECK((secp256k1_modinv64_abs(q) + secp256k1_modinv64_abs(r)) >= 0); /* |q|+|r| doesn't overflow */
        VERIFY_CHECK((secp256k1_modinv64_abs(u) + secp256k1_modinv64_abs(v)) <= M62 + 1); /* |u|+|v| <= 2^62 */
    }

    /* [md,me] start as zero; plus [u,q] if d is negative; plus [v,r] if e is negative. */
    sd = d4 >> 63;
    se = e4 >> 63;
    md = (u as i64 & sd) + (v as i64 & se);
    me = (q as i64 & sd) + (r as i64 & se);
    /* Begin computing t*[d,e]. */
    cd = u as i128 * d0 as i128 + v as i128 * e0 as i128;
    ce = q as i128 * d0 as i128 + r as i128 * e0 as i128;
    /* Correct md,me so that t*[d,e]+modulus*[md,me] has 62 zero bottom bits. */
    md -= (modinfo.modulus_inv62 * cd as u64 + md as u64) as i64 & M62;
    me -= (modinfo.modulus_inv62 * ce as u64 + me as u64) as i64 & M62;
    /* Update the beginning of computation for t*[d,e]+modulus*[md,me] now md,me are known. */
    cd += modinfo.modulus.v[0] as i128 * md as i128;
    ce += modinfo.modulus.v[0] as i128 * me as i128;
    /* Verify that the low 62 bits of the computation are indeed zero, and then throw them away. */
    #[cfg(feature = "verify")] {
        VERIFY_CHECK((cd as i64 & M62) == 0); cd >>= 62;
        VERIFY_CHECK((ce as i64 & M62) == 0); ce >>= 62;
    }
    /* Compute limb 1 of t*[d,e]+modulus*[md,me], and store it as output limb 0 (= down shift). */
    cd += u as i128 * d1 as i128 + v as i128 * e1 as i128;
    ce += q as i128 * d1 as i128 + r as i128 * e1 as i128;
    if (modinfo.modulus.v[1] != 0) { /* Optimize for the case where limb of modulus is zero. */
        cd += modinfo.modulus.v[1] as i128 * md as i128;
        ce += modinfo.modulus.v[1] as i128 * me as i128;
    }
    d.v[0] = cd as i64 & M62; cd >>= 62;
    e.v[0] = ce as i64 & M62; ce >>= 62;
    /* Compute limb 2 of t*[d,e]+modulus*[md,me], and store it as output limb 1. */
    cd += u as i128 * d2 as i128 + v as i128 * e2 as i128;
    ce += q as i128 * d2 as i128 + r as i128 * e2 as i128;
    if (modinfo.modulus.v[2] != 0) { /* Optimize for the case where limb of modulus is zero. */
        cd += modinfo.modulus.v[2] as i128 * md as i128;
        ce += modinfo.modulus.v[2] as i128 * me as i128;
    }
    d.v[1] = cd as i64 & M62; cd >>= 62;
    e.v[1] = ce as i64 & M62; ce >>= 62;
    /* Compute limb 3 of t*[d,e]+modulus*[md,me], and store it as output limb 2. */
    cd += u as i128 * d3 as i128 + v as i128 * e3 as i128;
    ce += q as i128 * d3 as i128 + r as i128 as i128 * e3 as i128;
    if (modinfo.modulus.v[3] != 0) { /* Optimize for the case where limb of modulus is zero. */
        cd += modinfo.modulus.v[3] as i128 * md as i128;
        ce += modinfo.modulus.v[3] as i128 * me as i128;
    }
    d.v[2] = cd as i64 & M62; cd >>= 62;
    e.v[2] = ce as i64 & M62; ce >>= 62;
    /* Compute limb 4 of t*[d,e]+modulus*[md,me], and store it as output limb 3. */
    cd += u as i128 * d4 as i128 + v as i128 * e4 as i128;
    ce += q as i128 * d4 as i128 + r as i128 * e4 as i128;
    cd += modinfo.modulus.v[4] as i128 * md as i128;
    ce += modinfo.modulus.v[4] as i128 * me as i128;
    d.v[3] = cd as i64 & M62; cd >>= 62;
    e.v[3] = ce as i64 & M62; ce >>= 62;
    /* What remains is limb 5 of t*[d,e]+modulus*[md,me]; store it as output limb 4. */
    d.v[4] = cd as i64;
    e.v[4] = ce as i64;
    #[cfg(feature = "verify")] {
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(d, 5, &modinfo.modulus, -2) > 0); /* d > -2*modulus */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(d, 5, &modinfo.modulus, 1) < 0);  /* d <    modulus */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(e, 5, &modinfo.modulus, -2) > 0); /* e > -2*modulus */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(e, 5, &modinfo.modulus, 1) < 0);  /* e <    modulus */
    }
}

/* Compute (t/2^62) * [f, g], where t is a transition matrix scaled by 2^62.
 *
 * This implements the update_fg function from the explanation.
 */
fn secp256k1_modinv64_update_fg_62(f: &mut secp256k1_modinv64_signed62, g: &mut secp256k1_modinv64_signed62, t: &secp256k1_modinv64_trans2x2) {
    let M62: i64 = (u64::MAX >> 2) as i64;
    let f0: i64 = f.v[0]; let f1: i64 = f.v[1]; let f2: i64 = f.v[2]; let f3: i64 = f.v[3]; let f4: i64 = f.v[4];

    let g0: i64 = g.v[0]; let g1: i64 = g.v[1]; let g2: i64 = g.v[2]; let g3: i64 = g.v[3]; let g4: i64 = g.v[4];

    let u: i64 = t.u as i64; let v: i64 = t.v as i64; let q: i64 = t.q as i64; let r: i64 = t.r as i64;

    let mut cf: i128; let mut cg: i128;
    /* Start computing t*[f,g]. */
    cf = (u as i128) * (f0 as i128) + (v as i128) * (g0 as i128);
    cg = (q as i128) * (f0 as i128) + (r as i128) * (g0 as i128);

    /* Verify that the bottom 62 bits of the result are zero, and then throw them away. */
    #[cfg(feature = "verify")] {
        VERIFY_CHECK((cf as i64 & M62) == 0); cf >>= 62;
        VERIFY_CHECK((cg as i64 & M62) == 0); cg >>= 62;
    }
    /* Compute limb 1 of t*[f,g], and store it as output limb 0 (= down shift). */
    cf += u as i128 * f1 as i128 + v as i128 * g1 as i128;
    cg += q as i128 * f1 as i128 + r as i128 * g1 as i128;
    f.v[0] = cf as i64 & M62; cf >>= 62;
    g.v[0] = cg as i64 & M62; cg >>= 62;
    /* Compute limb 2 of t*[f,g], and store it as output limb 1. */
    cf += u as i128 * f2 as i128 + v as i128 * g2 as i128;
    cg += q as i128 * f2 as i128 + r as i128 * g2 as i128;
    f.v[1] = cf as i64 & M62; cf >>= 62;
    g.v[1] = cg as i64 & M62; cg >>= 62;
    /* Compute limb 3 of t*[f,g], and store it as output limb 2. */
    cf += u as i128 * f3 as i128 + v as i128 * g3 as i128;
    cg += q as i128 * f3 as i128 + r as i128 * g3 as i128;
    f.v[2] = cf as i64 & M62; cf >>= 62;
    g.v[2] = cg as i64 & M62; cg >>= 62;
    /* Compute limb 4 of t*[f,g], and store it as output limb 3. */
    cf += u as i128 * f4 as i128 + v as i128 * g4 as i128;
    cg += q as i128 * f4 as i128 + r as i128 * g4 as i128;
    f.v[3] = cf as i64 & M62; cf >>= 62;
    g.v[3] = cg as i64 & M62; cg >>= 62;
    /* What remains is limb 5 of t*[f,g]; store it as output limb 4. */
    f.v[4] = cf as i64;
    g.v[4] = cg as i64;
}

/* Compute (t/2^62) * [f, g], where t is a transition matrix for 62 divsteps.
 *
 * Version that operates on a variable number of limbs in f and g.
 *
 * This implements the update_fg function from the explanation.
 */
fn secp256k1_modinv64_update_fg_62_var(len: usize, f: &mut secp256k1_modinv64_signed62, g: &mut secp256k1_modinv64_signed62, t: &secp256k1_modinv64_trans2x2) {
    let M62: i64 = (u64::MAX >> 2) as i64;
    let u: i64 = t.u as i64; let v: i64 = t.v as i64; let q: i64 = t.q as i64; let r: i64 = t.r as i64;
    let mut fi: i64; let mut gi: i64;
    let mut cf: i128; let mut cg: i128;
    let mut i: usize;
    #[cfg(feature = "verify")] {
        VERIFY_CHECK(len > 0);
    }
    /* Start computing t*[f,g]. */
    fi = f.v[0];
    gi = g.v[0];
    cf = (u as i128) * (fi as i128) + (v as i128) * (gi as i128);
    cg = (q as i128) * (fi as i128) + (r as i128) * (gi as i128);
    /* Verify that the bottom 62 bits of the result are zero, and then throw them away. */
    #[cfg(feature = "verify")] {
        VERIFY_CHECK(((cf as i64) & M62) == 0); cf >>= 62;
        VERIFY_CHECK(((cg as i64) & M62) == 0); cg >>= 62;
    }
    /* Now iteratively compute limb i=1..len of t*[f,g], and store them in output limb i-1 (shifting
     * down by 62 bits). */
    for i in 1..len {
        fi = f.v[i];
        gi = g.v[i];
        cf += (u as i128) * (fi as i128) + (v as i128) * (gi as i128);
        cg += (q as i128) * (fi as i128) + (r as i128) * (gi as i128);
        f.v[i - 1] = (cf as i64) & M62; cf >>= 62;
        g.v[i - 1] = (cg as i64) & M62; cg >>= 62;
    }
    /* What remains is limb (len) of t*[f,g]; store it as output limb (len-1). */
    f.v[len - 1] = cf as i64;
    g.v[len - 1] = cg as i64;
}

/* Compute the inverse of x modulo modinfo->modulus, and replace x with it (constant time in x). */
pub fn secp256k1_modinv64(x: &mut secp256k1_modinv64_signed62, modinfo: &mut secp256k1_modinv64_modinfo) {
    /* Start with d=0, e=1, f=modulus, g=x, zeta=-1. */
    let mut d: secp256k1_modinv64_signed62 = secp256k1_modinv64_signed62 { v: [0; 5] };
    let mut e: secp256k1_modinv64_signed62 = secp256k1_modinv64_signed62 { v: [1, 0, 0, 0, 0] };
    let mut f: secp256k1_modinv64_signed62 = modinfo.modulus.clone();
    let mut g: secp256k1_modinv64_signed62 = x.clone();
    let mut i: i32;
    let mut zeta: i64 = -1; /* zeta = -(delta+1/2); delta starts at 1/2. */

    /* Do 10 iterations of 59 divsteps each = 590 divsteps. This suffices for 256-bit inputs. */
    for i in 0..10 {
        /* Compute transition matrix and new zeta after 59 divsteps. */
        let mut t: secp256k1_modinv64_trans2x2 = secp256k1_modinv64_trans2x2 { u: 0, v: 0, q: 0, r: 0 };
        zeta = secp256k1_modinv64_divsteps_59(zeta, f.v[0] as u64, g.v[0] as u64, &mut t);
        /* Update d,e using that transition matrix. */
        secp256k1_modinv64_update_de_62(&mut d, &mut e, &t, modinfo);
        /* Update f,g using that transition matrix. */
        #[cfg(feature = "verify")] {
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&f, 5, &modinfo.modulus, -1) > 0); /* f > -modulus */
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&f, 5, &modinfo.modulus, 1) <= 0); /* f <= modulus */
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&g, 5, &modinfo.modulus, -1) > 0); /* g > -modulus */
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&g, 5, &modinfo.modulus, 1) < 0);  /* g <  modulus */
        }
        secp256k1_modinv64_update_fg_62(&mut f, &mut g, &t);
        #[cfg(feature = "verify")] {
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&f, 5, &modinfo.modulus, -1) > 0); /* f > -modulus */
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&f, 5, &modinfo.modulus, 1) <= 0); /* f <= modulus */
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&g, 5, &modinfo.modulus, -1) > 0); /* g > -modulus */
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&g, 5, &modinfo.modulus, 1) < 0);  /* g <  modulus */
        }
    }
    /* At this point sufficient iterations have been performed that g must have reached 0
     * and (if g was not originally 0) f must now equal +/- GCD of the initial f, g
     * values i.e. +/- 1, and d now contains +/- the modular inverse. */
    #[cfg(feature = "verify")] {
        /* g == 0 */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&g, 5, &SECP256K1_SIGNED62_ONE, 0) == 0);
        /* |f| == 1, or (x == 0 and d == 0 and |f|=modulus) */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&f, 5, &SECP256K1_SIGNED62_ONE, -1) == 0 ||
                     secp256k1_modinv64_mul_cmp_62(&f, 5, &SECP256K1_SIGNED62_ONE, 1) == 0 ||
                     (secp256k1_modinv64_mul_cmp_62(x, 5, &SECP256K1_SIGNED62_ONE, 0) == 0 &&
                      secp256k1_modinv64_mul_cmp_62(&d, 5, &SECP256K1_SIGNED62_ONE, 0) == 0 &&
                      (secp256k1_modinv64_mul_cmp_62(&f, 5, &modinfo.modulus, 1) == 0 ||
                       secp256k1_modinv64_mul_cmp_62(&f, 5, &modinfo.modulus, -1) == 0)));
    }
    /* Optionally negate d, normalize to [0,modulus), and return it. */
    secp256k1_modinv64_normalize_62(&mut d, f.v[4], modinfo);
    *x = d;
}

/* Compute the inverse of x modulo modinfo->modulus, and replace x with it (variable time). */
pub fn secp256k1_modinv64_var(x: &mut secp256k1_modinv64_signed62, modinfo: &secp256k1_modinv64_modinfo) {
    /* Start with d=0, e=1, f=modulus, g=x, eta=-1. */
    let mut d: secp256k1_modinv64_signed62 = secp256k1_modinv64_signed62 { v: [0; 5] };
    let mut e: secp256k1_modinv64_signed62 = secp256k1_modinv64_signed62 { v: [1, 0, 0, 0, 0] };
    let mut f: secp256k1_modinv64_signed62 = modinfo.modulus.clone();
    let mut g: secp256k1_modinv64_signed62 = x.clone();

    #[cfg(feature = "verify")] let i = 0;
    let mut j: usize;
    let mut len: usize = 5;
    
    let eta: i64 = -1; /* eta = -delta; delta is initially 1 */
    //int64_t cond, fn, gn;
    let mut cond: i64;
    let mut fN: i64;
    let mut gn: i64;

    /* Do iterations of 62 divsteps each until g=0. */
    //while (1) {
    loop {
        /* Compute transition matrix and new eta after 62 divsteps. */
        let mut t: secp256k1_modinv64_trans2x2 = secp256k1_modinv64_trans2x2 { u: 0, v: 0, q: 0, r: 0 };
        let eta = secp256k1_modinv64_divsteps_62_var(eta, f.v[0] as u64, g.v[0] as u64, &mut t);
        /* Update d,e using that transition matrix. */
        secp256k1_modinv64_update_de_62(&mut d, &mut e, &t, modinfo);
        /* Update f,g using that transition matrix. */
#[cfg(feature = "verify")] {
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&f, len, &modinfo.modulus, -1) > 0); /* f > -modulus */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&f, len, &modinfo.modulus, 1) <= 0); /* f <= modulus */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&g, len, &modinfo.modulus, -1) > 0); /* g > -modulus */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&g, len, &modinfo.modulus, 1) < 0);  /* g <  modulus */
}
        secp256k1_modinv64_update_fg_62_var(len, &mut f, &mut g, &t);
        /* If the bottom limb of g is zero, there is a chance that g=0. */
        if (g.v[0] == 0) {
            cond = 0;
            /* Check if the other limbs are also 0. */
            for j in 0..len {
                cond |= g.v[j];
            }
            /* If so, we're done. */
            if (cond == 0) {break;}
        }

        /* Determine if len>1 and limb (len-1) of both f and g is 0 or -1. */
        fN = f.v[len - 1];
        gn = g.v[len - 1];
        cond = (len as i64 - 2) >> 63;
        cond |= fN ^ (fN >> 63);
        cond |= gn ^ (gn >> 63);
        /* If so, reduce length, propagating the sign of f and g's top limb into the one below. */
        if (cond == 0) {
            f.v[len - 2] |= ((fN as u64) << 62) as i64;
            g.v[len - 2] |= ((gn as u64) << 62) as i64;
            len -= 1;
        }
        #[cfg(feature = "verify")] {
            i += 1;
            VERIFY_CHECK(i < 12); /* We should never need more than 12*62 = 744 divsteps */
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&f, len, &modinfo.modulus, -1) > 0); /* f > -modulus */
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&f, len, &modinfo.modulus, 1) <= 0); /* f <= modulus */
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&g, len, &modinfo.modulus, -1) > 0); /* g > -modulus */
            VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&g, len, &modinfo.modulus, 1) < 0);  /* g <  modulus */
        }
    }

    /* At this point g is 0 and (if g was not originally 0) f must now equal +/- GCD of
     * the initial f, g values i.e. +/- 1, and d now contains +/- the modular inverse. */
    #[cfg(feature = "verify")] {
        /* g == 0 */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&g, len, &SECP256K1_SIGNED62_ONE, 0) == 0);
        /* |f| == 1, or (x == 0 and d == 0 and |f|=modulus) */
        VERIFY_CHECK(secp256k1_modinv64_mul_cmp_62(&f, len, &SECP256K1_SIGNED62_ONE, -1) == 0 ||
                    secp256k1_modinv64_mul_cmp_62(&f, len, &SECP256K1_SIGNED62_ONE, 1) == 0 ||
                    (secp256k1_modinv64_mul_cmp_62(x, 5, &SECP256K1_SIGNED62_ONE, 0) == 0 &&
                    secp256k1_modinv64_mul_cmp_62(&d, 5, &SECP256K1_SIGNED62_ONE, 0) == 0 &&
                    (secp256k1_modinv64_mul_cmp_62(&f, len, &modinfo.modulus, 1) == 0 ||
                    secp256k1_modinv64_mul_cmp_62(&f, len, &modinfo.modulus, -1) == 0)));
    }

    /* Optionally negate d, normalize to [0,modulus), and return it. */
    secp256k1_modinv64_normalize_62(&mut d, f.v[len - 1], modinfo);
    *x = d;
}
