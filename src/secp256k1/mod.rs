use ecmult_gen::secp256k1_ecmult_gen_context;

pub mod ecmult_gen;
pub mod field_5x52;
pub mod group;

/* Limbs of the secp256k1 order. */
pub const SECP256K1_N_0: u64 = 0xBFD25E8CD0364141;
pub const SECP256K1_N_1: u64 = 0xBAAEDCE6AF48A03B;
pub const SECP256K1_N_2: u64 = 0xFFFFFFFFFFFFFFFE;
pub const SECP256K1_N_3: u64 = 0xFFFFFFFFFFFFFFFF;

/* Limbs of 2^256 minus the secp256k1 order. */
pub const SECP256K1_N_C_0: u64 = !SECP256K1_N_0 + 1;
pub const SECP256K1_N_C_1: u64 = !SECP256K1_N_1;
pub const SECP256K1_N_C_2: u64 = 1;

/* Limbs of half the secp256k1 order. */
pub const SECP256K1_N_H_0: u64 = 0xDFE92F46681B20A0;
pub const SECP256K1_N_H_1: u64 = 0x5D576E7357A4501D;
pub const SECP256K1_N_H_2: u64 = 0xFFFFFFFFFFFFFFFF;
pub const SECP256K1_N_H_3: u64 = 0x7FFFFFFFFFFFFFFF;

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

fn secp256k1_scalar_clear(r: &mut secp256k1_scalar) {
    r.d[0] = 0;
    r.d[1] = 0;
    r.d[2] = 0;
    r.d[3] = 0;
}

fn secp256k1_scalar_set_int(r: &mut secp256k1_scalar, v: u32) {
    r.d[0] = v as u64;
    r.d[1] = 0;
    r.d[2] = 0;
    r.d[3] = 0;
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

struct secp256k1_scalar {
    d: [u64; 4],
}

impl secp256k1_scalar {
    pub fn new() -> Self {
        secp256k1_scalar {
            d: [0; 4],
        }
    }
}

fn SECP256K1_SCALAR_CONST(d7: u64, d6: u64, d5: u64, d4: u64, d3: u64, d2: u64, d1: u64, d0: u64) -> secp256k1_scalar {
    secp256k1_scalar{d: [(d1 << 32) | d0, (d3 << 32) | d2, (d5 << 32) | d4, (d7 << 32) | d6]}
}

fn secp256k1_scalar_check_overflow(a: &secp256k1_scalar) -> i32 {
    let mut yes: i32 = 0;
    let mut no: i32 = 0;
    no |= (a.d[3] < SECP256K1_N_3) as i32; /* No need for a > check. */
    no |= (a.d[2] < SECP256K1_N_2) as i32;
    yes |= (a.d[2] > SECP256K1_N_2) as i32 & !no;
    no |= (a.d[1] < SECP256K1_N_1) as i32;
    yes |= (a.d[1] > SECP256K1_N_1) as i32 & !no;
    yes |= (a.d[0] >= SECP256K1_N_0) as i32 & !no;
    return yes;
}

fn secp256k1_scalar_reduce(r: &mut secp256k1_scalar, overflow: i32) -> i32 {
    let mut t: u128;
    //VERIFY_CHECK(overflow <= 1);
    t = r.d[0] as u128 + overflow as u128 * SECP256K1_N_C_0 as u128;
    r.d[0] = t as u64 & 0xFFFFFFFFFFFFFFFF; t >>= 64;
    t += r.d[1] as u128 + overflow as u128 * SECP256K1_N_C_1 as u128;
    r.d[1] = t as u64 & 0xFFFFFFFFFFFFFFFF; t >>= 64;
    t += r.d[2] as u128 + overflow as u128 * SECP256K1_N_C_2 as u128;
    r.d[2] = t as u64 & 0xFFFFFFFFFFFFFFFF; t >>= 64;
    t += r.d[3] as u128;
    r.d[3] = t as u64 & 0xFFFFFFFFFFFFFFFF;
    return overflow;
}


fn secp256k1_scalar_set_b32(r: &mut secp256k1_scalar, b32: &[u8; 32], overflow: &mut i32) {
    r.d[0] = b32[31] as u64 | (b32[30] as u64) << 8 | (b32[29] as u64) << 16 | (b32[28] as u64) << 24 | (b32[27] as u64) << 32 | (b32[26] as u64) << 40 | (b32[25] as u64) << 48 | (b32[24] as u64) << 56;
    r.d[1] = b32[23] as u64 | (b32[22] as u64) << 8 | (b32[21] as u64) << 16 | (b32[20] as u64) << 24 | (b32[19] as u64) << 32 | (b32[18] as u64) << 40 | (b32[17] as u64) << 48 | (b32[16] as u64) << 56;
    r.d[2] = b32[15] as u64 | (b32[14] as u64) << 8 | (b32[13] as u64) << 16 | (b32[12] as u64) << 24 | (b32[11] as u64) << 32 | (b32[10] as u64) << 40 | (b32[9] as u64) << 48 | (b32[8] as u64) << 56;
    r.d[3] = b32[7] as u64 | (b32[6] as u64) << 8 | (b32[5] as u64) << 16 | (b32[4] as u64) << 24 | (b32[3] as u64) << 32 | (b32[2] as u64) << 40 | (b32[1] as u64) << 48 | (b32[0] as u64) << 56;
    let over = secp256k1_scalar_reduce(r, secp256k1_scalar_check_overflow(r));
    *overflow = over;

}

fn secp256k1_scalar_get_b32(bin: &mut [u8], a: &secp256k1_scalar) {
    bin[0] = (a.d[3] >> 56) as u8; bin[1] = (a.d[3] >> 48) as u8; bin[2] = (a.d[3] >> 40) as u8; bin[3] = (a.d[3] >> 32) as u8; bin[4] = (a.d[3] >> 24) as u8; bin[5] = (a.d[3] >> 16) as u8; bin[6] = (a.d[3] >> 8) as u8; bin[7] = a.d[3] as u8;
    bin[8] = (a.d[2] >> 56) as u8; bin[9] = (a.d[2] >> 48) as u8; bin[10] = (a.d[2] >> 40) as u8; bin[11] = (a.d[2] >> 32) as u8; bin[12] = (a.d[2] >> 24) as u8; bin[13] = (a.d[2] >> 16) as u8; bin[14] = (a.d[2] >> 8) as u8; bin[15] = a.d[2] as u8;
    bin[16] = (a.d[1] >> 56) as u8; bin[17] = (a.d[1] >> 48) as u8; bin[18] = (a.d[1] >> 40) as u8; bin[19] = (a.d[1] >> 32) as u8; bin[20] = (a.d[1] >> 24) as u8; bin[21] = (a.d[1] >> 16) as u8; bin[22] = (a.d[1] >> 8) as u8; bin[23] = a.d[1] as u8;
    bin[24] = (a.d[0] >> 56) as u8; bin[25] = (a.d[0] >> 48) as u8; bin[26] = (a.d[0] >> 40) as u8; bin[27] = (a.d[0] >> 32) as u8; bin[28] = (a.d[0] >> 24) as u8; bin[29] = (a.d[0] >> 16) as u8; bin[30] = (a.d[0] >> 8) as u8; bin[31] = a.d[0] as u8;
}

fn secp256k1_scalar_is_zero(a: &secp256k1_scalar) -> bool {
    return (a.d[0] | a.d[1] | a.d[2] | a.d[3]) == 0;
}


fn secp256k1_scalar_set_b32_seckey(r: &mut secp256k1_scalar, bin: &[u8; 32]) -> bool {
    let mut overflow: i32 = 0;
    secp256k1_scalar_set_b32(r, bin, &mut overflow);
    return (overflow == 0) & !secp256k1_scalar_is_zero(r);
}

pub fn secp256k1_ec_seckey_verify(ctx: &secp256k1_context, seckey: &[u8; 32]) -> bool {
    let mut sec: secp256k1_scalar = secp256k1_scalar{ d: [0; 4] };

    let ret = secp256k1_scalar_set_b32_seckey(&mut sec, seckey);
    secp256k1_scalar_clear(&mut sec);
    return ret;
}

//static int secp256k1_ec_pubkey_create_helper(const secp256k1_ecmult_gen_context *ecmult_gen_ctx, secp256k1_scalar *seckey_scalar, secp256k1_ge *p, const unsigned char *seckey) 
pub fn secp256k1_ec_pubkey_create_helper(ecmult_gen_ctx: &secp256k1_ecmult_gen_context, seckey_scalar: &mut secp256k1_scalar, p: &secp256k1_ge, seckey: &[u8; 32]) -> bool {

    let mut pj: secp256k1_gej;

    let ret = secp256k1_scalar_set_b32_seckey(seckey_scalar, seckey);
    secp256k1_scalar_cmov(seckey_scalar, &secp256k1_scalar_one, !ret);

    secp256k1_ecmult_gen(ecmult_gen_ctx, &pj, seckey_scalar);
    secp256k1_ge_set_gej(p, &pj);
    return ret;
}

//int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey) 
pub fn secp256k1_ec_pubkey_create(ctx: &secp256k1_context, pubkey: &mut secp256k1_pubkey, seckey: &[u8; 32]) -> bool {
    let p: secp256k1_ge;
    let mut seckey_scalar: secp256k1_scalar;
 
    //TODO: memset(pubkey, 0, sizeof(*pubkey));
    //ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    //ARG_CHECK(seckey != NULL);

    let ret = secp256k1_ec_pubkey_create_helper(&ctx.ecmult_gen_ctx, &mut seckey_scalar, &p, seckey);
    secp256k1_pubkey_save(pubkey, &p);
    secp256k1_memczero(pubkey, sizeof(*pubkey), !ret);

    secp256k1_scalar_clear(&mut seckey_scalar);
    return ret;
}

//int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey* pubkey, unsigned int flags) {
pub fn secp256k1_ec_pubkey_serialize(ctx: &secp256k1_context, output: &mut [u8], outputlen: &mut usize, pubkey: &secp256k1_pubkey, flags: u32) -> bool {
    let mut Q: secp256k1_ge;
    let mut len: usize;
    let ret: i32 = 0;

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
    if (secp256k1_pubkey_load(ctx, &Q, pubkey)) {
        ret = secp256k1_eckey_pubkey_serialize(&Q, output, &len, flags & SECP256K1_FLAGS_BIT_COMPRESSION);
        if (ret) {
            *outputlen = len;
        }
    }
    return ret;
}

//int secp256k1_ec_seckey_negate(const secp256k1_context* ctx, unsigned char *seckey) {
pub fn secp256k1_ec_seckey_negate(ctx: &secp256k1_context, seckey: &mut [u8; 32]) -> i32 {
    let mut sec: secp256k1_scalar;
    let mut ret: i32 = 0;
    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(seckey != NULL);

    ret = secp256k1_scalar_set_b32_seckey(&mut sec, seckey);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_negate(&sec, &sec);
    secp256k1_scalar_get_b32(seckey, &sec);

    secp256k1_scalar_clear(&mut sec);
    return ret;
}

//int secp256k1_ec_privkey_negate(const secp256k1_context* ctx, unsigned char *seckey) {
pub fn secp256k1_ec_privkey_negate(ctx: &secp256k1_context, seckey: &mut [u8; 32]) -> i32 {
    return secp256k1_ec_seckey_negate(ctx, seckey);
}

//int secp256k1_ec_pubkey_negate(const secp256k1_context* ctx, secp256k1_pubkey *pubkey) {
pub fn secp256k1_ec_pubkey_negate(ctx: &secp256k1_context, pubkey: &mut secp256k1_pubkey) -> i32 {
    let ret: i32 = 0;
    let p: secp256k1_ge;
 
    ret = secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        secp256k1_ge_neg(&p, &p);
        secp256k1_pubkey_save(pubkey, &p);
    }
    return ret;
}


//static int secp256k1_ec_seckey_tweak_add_helper(secp256k1_scalar *sec, const unsigned char *tweak32) {
fn secp256k1_ec_seckey_tweak_add_helper(sec: &mut secp256k1_scalar, tweak32: &[u8; 32]) -> i32 {
    let mut term: secp256k1_scalar;
    let mut overflow: i32 = 0;
    let ret: i32 = 0;

    secp256k1_scalar_set_b32(&mut term, tweak32, &mut overflow);
    ret = (!overflow) & secp256k1_eckey_privkey_tweak_add(sec, &term);
    secp256k1_scalar_clear(&mut term);
    return ret;
}

//int secp256k1_ec_seckey_tweak_add(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
pub fn secp256k1_ec_seckey_tweak_add(ctx: &secp256k1_context, seckey: &mut [u8; 32], tweak32: &[u8; 32]) -> i32 {
    let mut sec: secp256k1_scalar;
    let ret: i32 = 0;

    ret = secp256k1_scalar_set_b32_seckey(&mut sec, seckey);
    ret &= secp256k1_ec_seckey_tweak_add_helper(&mut sec, tweak32);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_get_b32(seckey, &sec);

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
    let overflow: i32 = 0;
    secp256k1_scalar_set_b32(&mut term, tweak32, &mut overflow);
    return !overflow && secp256k1_eckey_pubkey_tweak_add(p, &term);
}

//int secp256k1_ec_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak32) {
pub fn secp256k1_ec_pubkey_tweak_add(ctx: &secp256k1_context, pubkey: &mut secp256k1_pubkey, tweak32: &[u8; 32]) -> i32 {
    let mut p: secp256k1_ge;
    let ret: i32 = 0;

    ret = secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    ret = ret && secp256k1_ec_pubkey_tweak_add_helper(&mut p, tweak32);
    if (ret) {
        secp256k1_pubkey_save(pubkey, &p);
    }

    return ret;
}

//int secp256k1_ec_seckey_tweak_mul(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
pub fn secp256k1_ec_seckey_tweak_mul(ctx: &secp256k1_context, seckey: &mut [u8; 32], tweak32: &[u8; 32]) -> i32 {
    let mut factor: secp256k1_scalar;
    let mut sec: secp256k1_scalar;
    let mut ret: i32 = 0;
    let overflow: i32 = 0;

    secp256k1_scalar_set_b32(&mut factor, tweak32, &mut overflow);
    ret = secp256k1_scalar_set_b32_seckey(&mut sec, seckey);
    ret &= (!overflow) & secp256k1_eckey_privkey_tweak_mul(&sec, &factor);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_get_b32(seckey, &sec);

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
    let overflow: i32 = 0;

    secp256k1_scalar_set_b32(&mut factor, tweak32, &mut overflow);
    ret = !overflow && secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (secp256k1_eckey_pubkey_tweak_mul(&p, &factor)) {
            secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

//int secp256k1_context_randomize(secp256k1_context* ctx, const unsigned char *seed32) {
pub fn secp256k1_context_randomize(ctx: &mut secp256k1_context, seed32: &[u8; 32]) -> i32 {
    if (secp256k1_ecmult_gen_context_is_built(&mut ctx.ecmult_gen_ctx)) {
        secp256k1_ecmult_gen_blind(&mut ctx.ecmult_gen_ctx, seed32);
    }
    return 1;
}

//int secp256k1_ec_pubkey_combine(const secp256k1_context* ctx, secp256k1_pubkey *pubnonce, const secp256k1_pubkey * const *pubnonces, size_t n) {
pub fn secp256k1_ec_pubkey_combine(ctx: &secp256k1_context, pubnonce: &mut secp256k1_pubkey, pubnonces: &mut [secp256k1_pubkey], n: usize) -> i32 {
    let mut i: usize = 0;
    let mut Qj: secp256k1_gej;
    let Q: secp256k1_ge;

    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(n >= 1);
    ARG_CHECK(pubnonces != NULL);

    secp256k1_gej_set_infinity(&Qj);

    for i in 0..n {
        ARG_CHECK(pubnonces[i] != NULL);
        secp256k1_pubkey_load(ctx, &Q, pubnonces[i]);
        secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    }
    if (secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&Q, &Qj);
    secp256k1_pubkey_save(pubnonce, &Q);
    return 1;
}

//int secp256k1_tagged_sha256(const secp256k1_context* ctx, unsigned char *hash32, const unsigned char *tag, size_t taglen, const unsigned char *msg, size_t msglen) {
pub fn secp256k1_tagged_sha256(ctx: &secp256k1_context, hash32: &mut [u8; 32], tag: &[u8], taglen: usize, msg: &[u8], msglen: usize) -> i32 {
    let mut sha: secp256k1_sha256;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(hash32 != NULL);
    ARG_CHECK(tag != NULL);
    ARG_CHECK(msg != NULL);

    secp256k1_sha256_initialize_tagged(&sha, tag, taglen);
    secp256k1_sha256_write(&sha, msg, msglen);
    secp256k1_sha256_finalize(&sha, hash32);
    return 1;
}