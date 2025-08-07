/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/
 #![allow(warnings)]
pub mod eckey;
pub mod ecmult_gen;
pub mod ecmult_impl;
pub mod field;
pub mod field_5x52;
pub mod field_5x52_int128;
pub mod scalar_4x64;
pub mod group;
pub mod hash;
pub mod precomputed_ec_mult_gen;
pub mod util;
pub mod modinv64;
pub mod scalar_impl;
pub mod scratch;

use ecmult_gen::secp256k1_ecmult_gen_context;
use group::{secp256k1_ge, secp256k1_ge_storage, secp256k1_ge_from_storage, secp256k1_gej, secp256k1_gej_add_ge, secp256k1_gej_is_infinity};
use field_5x52::{
    secp256k1_fe,
    secp256k1_fe_set_b32,
    secp256k1_fe_normalize_var,
    secp256k1_fe_get_b32
};
use scalar_4x64::{
    secp256k1_scalar,
    secp256k1_scalar_clear,
    secp256k1_scalar_cmov,
    secp256k1_scalar_negate,
    secp256k1_scalar_get_b32,
    secp256k1_scalar_set_b32,
};
use group::{
    secp256k1_ge_set_xy,
    secp256k1_ge_to_storage,
    secp256k1_ge_neg,
    secp256k1_ge_set_gej,
    secp256k1_gej_set_infinity
};
use eckey::{
    secp256k1_eckey_pubkey_serialize,
    secp256k1_eckey_privkey_tweak_add,
    secp256k1_eckey_pubkey_tweak_add,
    secp256k1_eckey_privkey_tweak_mul,
    secp256k1_eckey_pubkey_tweak_mul
};
use hash::{secp256k1_sha256, secp256k1_sha256_initialize_tagged, secp256k1_sha256_write, secp256k1_sha256_finalize};
use scalar_impl::{secp256k1_scalar_set_b32_seckey, secp256k1_scalar_one, secp256k1_scalar_zero};
// use hash::*;
// use field_5x52::*;
// use util::*;


/** All flags' lower 8 bits indicate what they're for. Do not use directly. */
pub const SECP256K1_FLAGS_TYPE_MASK: u32 = (1 << 8) - 1;
pub const SECP256K1_FLAGS_TYPE_CONTEXT: u32 = 1 << 0;
pub const SECP256K1_FLAGS_TYPE_COMPRESSION: u32 = 1 << 1;
/** The higher bits contain the actual data. Do not use directly. */
pub const SECP256K1_FLAGS_BIT_CONTEXT_VERIFY: u32 = 1 << 8;
pub const SECP256K1_FLAGS_BIT_CONTEXT_SIGN: u32 = 1 << 9;
pub const SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY: u32 = 1 << 10;
pub const SECP256K1_FLAGS_BIT_COMPRESSION: u32 = 1 << 8;

/** Flags to pass to secp256k1_context_create, secp256k1_context_preallocated_size, and
 *  secp256k1_context_preallocated_create. */
pub const SECP256K1_CONTEXT_VERIFY: u32 = SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY;
pub const SECP256K1_CONTEXT_SIGN: u32 = SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN;
pub const SECP256K1_CONTEXT_DECLASSIFY: u32 = SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY;
pub const SECP256K1_CONTEXT_NONE: u32 = SECP256K1_FLAGS_TYPE_CONTEXT;

/** Flag to pass to secp256k1_ec_pubkey_serialize. */
pub const SECP256K1_EC_COMPRESSED: u32 = SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION;
pub const SECP256K1_EC_UNCOMPRESSED: u32 = SECP256K1_FLAGS_TYPE_COMPRESSION;

/** Prefix byte used to tag various encoded curvepoints for specific purposes */
pub const SECP256K1_TAG_PUBKEY_EVEN: u8 = 0x02;
pub const SECP256K1_TAG_PUBKEY_ODD: u8 = 0x03;
pub const SECP256K1_TAG_PUBKEY_UNCOMPRESSED: u8 = 0x04;
pub const SECP256K1_TAG_PUBKEY_HYBRID_EVEN: u8 = 0x06;
pub const SECP256K1_TAG_PUBKEY_HYBRID_ODD: u8 = 0x07;


/** Opaque data structure that holds a parsed and valid public key.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage or transmission,
 *  use secp256k1_ec_pubkey_serialize and secp256k1_ec_pubkey_parse. To
 *  compare keys, use secp256k1_ec_pubkey_cmp.
 */
pub struct secp256k1_pubkey {
    data: [u8; 64],
}

pub struct secp256k1_context {
    ecmult_gen_ctx: secp256k1_ecmult_gen_context,
    //secp256k1_callback illegal_callback;
    //secp256k1_callback error_callback;
    declassify: i32,
}

impl secp256k1_context {
    pub fn new() -> Self {
        secp256k1_context {
            ecmult_gen_ctx: secp256k1_ecmult_gen_context::new(),
            //ecmult_gen_ctx: secp256k1_ecmult_gen_context::new(),
            //illegal_callback: secp256k1_callback::new(),
            //error_callback: secp256k1_callback::new(),
            declassify: 0,
        }
    }
}


pub fn secp256k1_ec_seckey_verify(ctx: &secp256k1_context, seckey: &[u8; 32]) -> i32 {
    let mut sec: secp256k1_scalar = secp256k1_scalar{ d: [0; 4] };

    let ret = secp256k1_scalar_set_b32_seckey(&mut sec, seckey);
    secp256k1_scalar_clear(&mut sec);
    return ret;
}

// static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
//     if (sizeof(secp256k1_ge_storage) == 64) {
//         /* When the secp256k1_ge_storage type is exactly 64 byte, use its
//          * representation inside secp256k1_pubkey, as conversion is very fast.
//          * Note that secp256k1_pubkey_save must use the same representation. */
//         secp256k1_ge_storage s;
//         memcpy(&s, &pubkey->data[0], sizeof(s));
//         secp256k1_ge_from_storage(ge, &s);
//     } else {
//         /* Otherwise, fall back to 32-byte big endian for X and Y. */
//         secp256k1_fe x, y;
//         secp256k1_fe_set_b32(&x, pubkey->data);
//         secp256k1_fe_set_b32(&y, pubkey->data + 32);
//         secp256k1_ge_set_xy(ge, &x, &y);
//     }
//     ARG_CHECK(!secp256k1_fe_is_zero(&ge->x));
//     return 1;
// }
fn secp256k1_pubkey_load(ctx: &secp256k1_context, ge: &mut secp256k1_ge, pubkey: &secp256k1_pubkey) -> i32 {
    if std::mem::size_of::<secp256k1_ge_storage>() == 64 {
        /* When the secp256k1_ge_storage type is exactly 64 byte, use its
         * representation inside secp256k1_pubkey, as conversion is very fast.
         * Note that secp256k1_pubkey_save must use the same representation. */
        let mut s: secp256k1_ge_storage;
        //memcpy(&s, &pubkey.data[0], std::mem::size_of::<secp256k1_ge_storage>());
        s.x.copy_from_u8slice(pubkey.data.as_slice());
        secp256k1_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        let mut x: secp256k1_fe;
        let mut y: secp256k1_fe;
        secp256k1_fe_set_b32(&mut x, &pubkey.data);
        secp256k1_fe_set_b32(&mut y, &pubkey.data[32..]);
        secp256k1_ge_set_xy(ge, &x, &y);
    }
    return 1;
}

// static void secp256k1_pubkey_save(secp256k1_pubkey* pubkey, secp256k1_ge* ge) {
//     if (sizeof(secp256k1_ge_storage) == 64) {
//         secp256k1_ge_storage s;
//         secp256k1_ge_to_storage(&s, ge);
//         memcpy(&pubkey->data[0], &s, sizeof(s));
//     } else {
//         VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
//         secp256k1_fe_normalize_var(&ge->x);
//         secp256k1_fe_normalize_var(&ge->y);
//         secp256k1_fe_get_b32(pubkey->data, &ge->x);
//         secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
//     }
// }

fn secp256k1_pubkey_save(pubkey: &mut secp256k1_pubkey, ge: &secp256k1_ge) {
    if std::mem::size_of::<secp256k1_ge_storage>() == 64 {
        let mut s: secp256k1_ge_storage;
        secp256k1_ge_to_storage(&mut s, ge);
        //memcpy(&pubkey.data[0], &s, std::mem::size_of::<secp256k1_ge_storage>());
        pubkey.data.copy_from_slice(&s.to_array());
    } else {
       // VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
        secp256k1_fe_normalize_var(&mut ge.x);
        secp256k1_fe_normalize_var(&mut ge.y);
        secp256k1_fe_get_b32(&mut pubkey.data, &ge.x);
        secp256k1_fe_get_b32(&mut pubkey.data[32..], &ge.y);
    }
}

//static int secp256k1_ec_pubkey_create_helper(const secp256k1_ecmult_gen_context *ecmult_gen_ctx, secp256k1_scalar *seckey_scalar, secp256k1_ge *p, const unsigned char *seckey) 
pub fn secp256k1_ec_pubkey_create_helper(ecmult_gen_ctx: &secp256k1_ecmult_gen_context, seckey_scalar: &mut secp256k1_scalar, p: &mut secp256k1_ge, seckey: &[u8; 32]) -> bool {

    let mut pj: secp256k1_gej;

    let ret = secp256k1_scalar_set_b32_seckey(seckey_scalar, seckey);
    secp256k1_scalar_cmov(seckey_scalar, &secp256k1_scalar_one, !ret);

    ecmult_gen_ctx.secp256k1_ecmult_gen(&mut pj, seckey_scalar);
    secp256k1_ge_set_gej(p, &pj);
    return ret != 0;
}

//int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey) 
pub fn secp256k1_ec_pubkey_create(ctx: &secp256k1_context, pubkey: &mut secp256k1_pubkey, seckey: &[u8; 32]) -> bool {
    let mut p: secp256k1_ge;
    let mut seckey_scalar: secp256k1_scalar;
 
    //TODO: memset(pubkey, 0, sizeof(*pubkey));
    //ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    //ARG_CHECK(seckey != NULL);

    let ret = secp256k1_ec_pubkey_create_helper(&ctx.ecmult_gen_ctx, &mut seckey_scalar, &mut p, seckey);
    secp256k1_pubkey_save(pubkey, &p);
    //secp256k1_memczero(pubkey, !ret);
    if !ret {pubkey.data.fill(0)};

    secp256k1_scalar_clear(&mut seckey_scalar);
    return ret;
}

//int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey* pubkey, unsigned int flags) {
pub fn secp256k1_ec_pubkey_serialize(ctx: &secp256k1_context, output: &mut [u8], outputlen: &mut usize, pubkey: &secp256k1_pubkey, flags: u32) -> bool {
    let mut Q: secp256k1_ge;
    let mut len: usize;
    let mut ret: i32 = 0;

    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(outputlen != NULL);
    //ARG_CHECK(*outputlen >= ((flags & SECP256K1_FLAGS_BIT_COMPRESSION) ? 33u : 65u));
    len = *outputlen;
    *outputlen = 0;
    //ARG_CHECK(output != NULL);
    //memset(output, 0, len);
    output.fill(0); 
    //ARG_CHECK(pubkey != NULL);
    //ARG_CHECK((flags & SECP256K1_FLAGS_TYPE_MASK) == SECP256K1_FLAGS_TYPE_COMPRESSION);
    if secp256k1_pubkey_load(ctx, &mut Q, pubkey) != 0 {
        let compressed = (flags & SECP256K1_FLAGS_BIT_COMPRESSION) != 0;
        ret = secp256k1_eckey_pubkey_serialize(&mut Q, output, compressed);
        if ret != 0 {
            *outputlen = len;
        }
    }
    return ret != 0;
}

//int secp256k1_ec_seckey_negate(const secp256k1_context* ctx, unsigned char *seckey) {
pub fn secp256k1_ec_seckey_negate(ctx: &secp256k1_context, seckey: &mut [u8; 32]) -> i32 {
    let mut sec: secp256k1_scalar;
    let mut ret: i32 = 0;
    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(seckey != NULL);

    ret = secp256k1_scalar_set_b32_seckey(&mut sec, seckey);
    secp256k1_scalar_cmov(&mut sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_negate(&mut sec, &sec);
    secp256k1_scalar_get_b32(seckey, &mut sec);

    secp256k1_scalar_clear(&mut sec);
    return ret;
}

//int secp256k1_ec_privkey_negate(const secp256k1_context* ctx, unsigned char *seckey) {
pub fn secp256k1_ec_privkey_negate(ctx: &secp256k1_context, seckey: &mut [u8; 32]) -> i32 {
    return secp256k1_ec_seckey_negate(ctx, seckey);
}

//int secp256k1_ec_pubkey_negate(const secp256k1_context* ctx, secp256k1_pubkey *pubkey) {
pub fn secp256k1_ec_pubkey_negate(ctx: &secp256k1_context, pubkey: &mut secp256k1_pubkey) -> i32 {
    let mut ret: i32 = 0;
    let mut p: secp256k1_ge = secp256k1_ge::new();
 
    ret = secp256k1_pubkey_load(ctx, &mut p, pubkey);
    pubkey.data = [0u8; 64];
    if ret != 0 {
        secp256k1_ge_neg(&mut p, &p);
        secp256k1_pubkey_save(pubkey, &p);
    }
    return ret;
}


//static int secp256k1_ec_seckey_tweak_add_helper(secp256k1_scalar *sec, const unsigned char *tweak32) {
fn secp256k1_ec_seckey_tweak_add_helper(sec: &mut secp256k1_scalar, tweak32: &[u8; 32]) -> i32 {
    let mut term: secp256k1_scalar;
    let mut overflow: i32 = 0;
    let mut ret: i32 = 0;

    secp256k1_scalar_set_b32(&mut term, tweak32, &mut overflow);
    ret = ((overflow == 0) && secp256k1_eckey_privkey_tweak_add(sec, &term)) as i32;
    secp256k1_scalar_clear(&mut term);
    return ret;
}

//int secp256k1_ec_seckey_tweak_add(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
pub fn secp256k1_ec_seckey_tweak_add(ctx: &secp256k1_context, seckey: &mut [u8; 32], tweak32: &[u8; 32]) -> i32 {
    let mut sec: secp256k1_scalar;
    let mut ret: i32 = 0;

    ret = secp256k1_scalar_set_b32_seckey(&mut sec, seckey);
    ret &= secp256k1_ec_seckey_tweak_add_helper(&mut sec, tweak32);
    secp256k1_scalar_cmov(&mut sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_get_b32(seckey, &mut sec);

    secp256k1_scalar_clear(&mut sec);
    return ret;
}

//int secp256k1_ec_privkey_tweak_add(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
pub fn secp256k1_ec_privkey_tweak_add(ctx: &secp256k1_context, seckey: &mut [u8; 32], tweak32: &[u8; 32]) -> i32 {
    return secp256k1_ec_seckey_tweak_add(ctx, seckey, tweak32);
}

//static int secp256k1_ec_pubkey_tweak_add_helper(secp256k1_ge *p, const unsigned char *tweak32) {
fn secp256k1_ec_pubkey_tweak_add_helper(p: &mut secp256k1_ge, tweak32: &[u8; 32]) -> i32 {
    let mut term: secp256k1_scalar;
    let mut overflow: i32 = 0;
    secp256k1_scalar_set_b32(&mut term, tweak32, &mut overflow);
    return (overflow == 0 && secp256k1_eckey_pubkey_tweak_add(p, &term)) as i32;
}

//int secp256k1_ec_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak32) {
pub fn secp256k1_ec_pubkey_tweak_add(ctx: &secp256k1_context, pubkey: &mut secp256k1_pubkey, tweak32: &[u8; 32]) -> i32 {
    let mut p: secp256k1_ge;
    let mut ret: i32 = 0;

    ret = secp256k1_pubkey_load(ctx, &mut p, pubkey);
    pubkey.data = [0u8; 64];
    ret = ret & secp256k1_ec_pubkey_tweak_add_helper(&mut p, tweak32) as i32;
    if ret != 0 {
        secp256k1_pubkey_save(pubkey, &p);
    }

    return ret;
}

//int secp256k1_ec_seckey_tweak_mul(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
pub fn secp256k1_ec_seckey_tweak_mul(ctx: &secp256k1_context, seckey: &mut [u8; 32], tweak32: &[u8; 32]) -> i32 {
    let mut factor: secp256k1_scalar;
    let mut sec: secp256k1_scalar;
    let mut ret: i32 = 0;
    let mut overflow: i32 = 0;

    secp256k1_scalar_set_b32(&mut factor, tweak32, &mut overflow);
    ret = secp256k1_scalar_set_b32_seckey(&mut sec, seckey);
    ret &= ((overflow != 0) && secp256k1_eckey_privkey_tweak_mul(&mut sec, &factor)) as i32;
    secp256k1_scalar_cmov(&mut sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_get_b32(seckey, &mut sec);

    secp256k1_scalar_clear(&mut sec);
    secp256k1_scalar_clear(&mut factor);
    return ret;
}

//int secp256k1_ec_privkey_tweak_mul(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
pub fn secp256k1_ec_privkey_tweak_mul(ctx: &secp256k1_context, seckey: &mut [u8; 32], tweak32: &[u8; 32]) -> i32 {
    return secp256k1_ec_seckey_tweak_mul(ctx, seckey, tweak32);
}

//int secp256k1_ec_pubkey_tweak_mul(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak32) {
pub fn secp256k1_ec_pubkey_tweak_mul(ctx: &secp256k1_context, pubkey: &mut secp256k1_pubkey, tweak32: &[u8; 32]) -> i32 {
    let mut p: secp256k1_ge;
    let mut factor: secp256k1_scalar;
    let mut ret: i32 = 0;
    let mut overflow: i32 = 0;

    secp256k1_scalar_set_b32(&mut factor, tweak32, &mut overflow);
    ret = (overflow != 0) as i32 & secp256k1_pubkey_load(ctx, &mut p, pubkey);
    //memset(pubkey, 0, sizeof(*pubkey));
    pubkey.data.fill(0);
    if (ret) {
        if (secp256k1_eckey_pubkey_tweak_mul(&mut p, &factor)) {
            secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

//int secp256k1_context_randomize(secp256k1_context* ctx, const unsigned char *seed32) {
pub fn secp256k1_context_randomize(ctx: &mut secp256k1_context, seed32: &[u8; 32]) -> i32 {
    if ctx.ecmult_gen_ctx.secp256k1_ecmult_gen_context_is_built() {
        ctx.ecmult_gen_ctx.secp256k1_ecmult_gen_blind(seed32);
    }
    return 1;
}

//int secp256k1_ec_pubkey_combine(const secp256k1_context* ctx, secp256k1_pubkey *pubnonce, const secp256k1_pubkey * const *pubnonces, size_t n) {
pub fn secp256k1_ec_pubkey_combine(ctx: &secp256k1_context, pubnonce: &mut secp256k1_pubkey, pubnonces: &mut [secp256k1_pubkey], n: usize) -> i32 {
    let mut i: usize = 0;
    let mut Qj: secp256k1_gej;
    let mut Q: secp256k1_ge;

    //memset(pubnonce, 0, sizeof(*pubnonce));
    pubnonce.data.fill(0);
    //ARG_CHECK(n >= 1);
    //ARG_CHECK(pubnonces != NULL);

    secp256k1_gej_set_infinity(&mut Qj);

    for i in 0..n {
        //ARG_CHECK(pubnonces[i] != NULL);
        secp256k1_pubkey_load(ctx, &mut Q, &pubnonces[i]);
        secp256k1_gej_add_ge(&mut Qj, &Qj, &Q);
    }
    if secp256k1_gej_is_infinity(&Qj) != 0 {
        return 0;
    }
    secp256k1_ge_set_gej(&mut Q, &Qj);
    secp256k1_pubkey_save(pubnonce, &Q);
    return 1;
}

//int secp256k1_tagged_sha256(const secp256k1_context* ctx, unsigned char *hash32, const unsigned char *tag, size_t taglen, const unsigned char *msg, size_t msglen) {
pub fn secp256k1_tagged_sha256(ctx: &secp256k1_context, hash32: &mut [u8; 32], tag: &[u8], taglen: usize, msg: &[u8], msglen: usize) -> i32 {
    let mut sha: secp256k1_sha256;

    secp256k1_sha256_initialize_tagged(&mut sha, tag);
    secp256k1_sha256_write(&mut sha, msg);
    secp256k1_sha256_finalize(&mut sha, hash32);
    return 1;
}