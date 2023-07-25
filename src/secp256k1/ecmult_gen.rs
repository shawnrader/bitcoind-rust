/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/
use super::{secp256k1_scalar, secp256k1_scalar_clear};
use super::group::*;
use crate::secp256k1::precomputed_ec_mult_gen::*;

pub const ECMULT_GEN_PREC_BITS: i32 = 4;
pub const ECMULT_WINDOW_SIZE: i32 = 15;

//fn ECMULT_GEN_PREC_G(bits: u64) -> u64 {1 << bits}
macro_rules! ECMULT_GEN_PREC_G {
    ($bits:expr) => {
        1 << $bits
    };
}

macro_rules! ECMULT_GEN_PREC_N {
    ($bits:expr) => {
        256 / $bits
    };
}

pub struct secp256k1_ecmult_gen_context {
    /* Whether the context has been built. */
    built: i32,

    /* Blinding values used when computing (n-b)G + bG. */
    blind: secp256k1_scalar, /* -b */
    initial: secp256k1_gej,  /* bG */
}

impl secp256k1_ecmult_gen_context {

    pub fn new() -> Self {
        secp256k1_ecmult_gen_context {
            built: 0,
            blind: secp256k1_scalar::new(),
            initial: secp256k1_gej::new(),
        }
    }

    //static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context *ctx) {
    pub fn secp256k1_ecmult_gen_context_build(ctx: &mut secp256k1_ecmult_gen_context) {
        Self::secp256k1_ecmult_gen_blind(ctx, &[]);
        ctx.built = 1;
    }
    
    pub fn secp256k1_ecmult_gen_context_is_built(ctx: &secp256k1_ecmult_gen_context) -> bool {
        return ctx.built != 0;
    }
    
    pub fn secp256k1_ecmult_gen_context_clear(ctx: &secp256k1_ecmult_gen_context) {
        ctx.built = 0;
        secp256k1_scalar_clear(&mut ctx.blind);
        secp256k1_gej_clear(&ctx.initial);
    }
    
    /* For accelerating the computation of a*G:
     * To harden against timing attacks, use the following mechanism:
     * * Break up the multiplicand into groups of PREC_BITS bits, called n_0, n_1, n_2, ..., n_(PREC_N-1).
     * * Compute sum(n_i * (PREC_G)^i * G + U_i, i=0 ... PREC_N-1), where:
     *   * U_i = U * 2^i, for i=0 ... PREC_N-2
     *   * U_i = U * (1-2^(PREC_N-1)), for i=PREC_N-1
     *   where U is a point with no known corresponding scalar. Note that sum(U_i, i=0 ... PREC_N-1) = 0.
     * For each i, and each of the PREC_G possible values of n_i, (n_i * (PREC_G)^i * G + U_i) is
     * precomputed (call it prec(i, n_i)). The formula now becomes sum(prec(i, n_i), i=0 ... PREC_N-1).
     * None of the resulting prec group elements have a known scalar, and neither do any of
     * the intermediate sums while computing a*G.
     * The prec values are stored in secp256k1_ecmult_gen_prec_table[i][n_i] = n_i * (PREC_G)^i * G + U_i.
     */
    pub fn secp256k1_ecmult_gen(ctx: &secp256k1_ecmult_gen_context, r: &secp256k1_gej, gn: &secp256k1_scalar) {
        let bits = ECMULT_GEN_PREC_BITS;
        let g = ECMULT_GEN_PREC_G(bits as u64) as i32;
        let n = ECMULT_GEN_PREC_N(bits as u64) as i32;
    
        let mut adds: secp256k1_ge_storage;
        let mut gnb: secp256k1_scalar;
        let (mut i, mut j, mut n_i): (i32, i32, i32);
        
        //memset(&adds, 0, sizeof(adds));
        let mut add: secp256k1_ge = secp256k1_ge::new();
        *r = ctx.initial;
        /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
        secp256k1_scalar_add(&gnb, gn, &ctx.blind);
        add.infinity = 0;
        for i in (0..n) {
            n_i = secp256k1_scalar_get_bits(&gnb, i * bits, bits);
            for j in (0..g) {
                /* This uses a conditional move to avoid any secret data in array indexes.
                 *   _Any_ use of secret indexes has been demonstrated to result in timing
                 *   sidechannels, even when the cache-line access patterns are uniform.
                 *  See also:
                 *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
                 *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
                 *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
                 *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
                 *    (https://www.tau.ac.il/~tromer/papers/cache.pdf)
                 */
                secp256k1_ge_storage_cmov(&adds, &secp256k1_ecmult_gen_prec_table[i][j], j == n_i);
            }
            secp256k1_ge_from_storage(&add, &adds);
            secp256k1_gej_add_ge(r, r, &add);
        }
        n_i = 0;
        secp256k1_ge_clear(&add);
        secp256k1_scalar_clear(&gnb);
    }
    
    /* Setup blinding values for secp256k1_ecmult_gen. */
    //static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
    pub fn secp256k1_ecmult_gen_blind(ctx: &mut secp256k1_ecmult_gen_context, seed32: &[u8]) {
        let mut b: secp256k1_scalar;
        let mut gb: secp256k1_gej;
        let mut s: secp256k1_fe;
        let mut nonce32: [u8; 32] = [0; 32];
        let mut rng: secp256k1_rfc6979_hmac_sha256;
        let mut overflow: i32;
        let mut keydata: [u8; 64] = [0; 64];

        if seed32.len() == 0 {
            /* When seed is NULL, reset the initial point and blinding value. */
            secp256k1_gej_set_ge(&ctx.initial, &secp256k1_ge_const_g);
            secp256k1_gej_neg(&ctx.initial, &ctx.initial);
            secp256k1_scalar_set_int(&ctx.blind, 1);
        }
        /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
        secp256k1_scalar_get_b32(nonce32, &ctx.blind);
        /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
         *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
         *   asking the caller for blinding values directly and expecting them to retry on failure.
         */
        //memcpy(keydata, nonce32, 32);
        keydata[..32].copy_from_slice(&nonce32[..32]);
        if seed32.len() > 0 {
            //memcpy(keydata + 32, seed32, 32);
            keydata[32..64].copy_from_slice(&seed32[..32]);
        }
        secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, if seed32 { 64 } else { 32 });
        //memset(keydata, 0, sizeof(keydata));
        keydata = [0; 64];
        /* Accept unobservably small non-uniformity. */
        secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        overflow = !secp256k1_fe_set_b32(&s, nonce32);
        overflow |= secp256k1_fe_is_zero(&s);
        secp256k1_fe_cmov(&s, &secp256k1_fe_one, overflow);
        /* Randomize the projection to defend against multiplier sidechannels. */
        secp256k1_gej_rescale(&ctx.initial, &s);
        secp256k1_fe_clear(&s);
        secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        secp256k1_scalar_set_b32(&b, nonce32, NULL);
        /* A blinding value of 0 works, but would undermine the projection hardening. */
        secp256k1_scalar_cmov(&b, &secp256k1_scalar_one, secp256k1_scalar_is_zero(&b));
        secp256k1_rfc6979_hmac_sha256_finalize(&rng);
        //memset(nonce32, 0, 32);
        nonce32 = [0; 32];
        secp256k1_ecmult_gen(ctx, &gb, &b);
        secp256k1_scalar_negate(&b, &b);
        ctx.blind = b;
        ctx.initial = gb;
        secp256k1_scalar_clear(&b);
        secp256k1_gej_clear(&gb);
    }
    
}