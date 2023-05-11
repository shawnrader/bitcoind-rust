

/* Limbs of the secp256k1 order. */
const SECP256K1_N_0: u64 = 0xBFD25E8CD0364141;
const SECP256K1_N_1: u64 = 0xBAAEDCE6AF48A03B;
const SECP256K1_N_2: u64 = 0xFFFFFFFFFFFFFFFE;
const SECP256K1_N_3: u64 = 0xFFFFFFFFFFFFFFFF;

/* Limbs of 2^256 minus the secp256k1 order. */
const SECP256K1_N_C_0: u64 = !SECP256K1_N_0 + 1;
const SECP256K1_N_C_1: u64 = !SECP256K1_N_1;
const SECP256K1_N_C_2: u64 = 1;

/* Limbs of half the secp256k1 order. */
const SECP256K1_N_H_0: u64 = 0xDFE92F46681B20A0;
const SECP256K1_N_H_1: u64 = 0x5D576E7357A4501D;
const SECP256K1_N_H_2: u64 = 0xFFFFFFFFFFFFFFFF;
const SECP256K1_N_H_3: u64 = 0x7FFFFFFFFFFFFFFF;

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
    //secp256k1_ecmult_gen_context ecmult_gen_ctx;
    //secp256k1_callback illegal_callback;
    //secp256k1_callback error_callback;
    declassify: i32,
}

impl secp256k1_context {
    pub fn new() -> Self {
        secp256k1_context {
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


fn secp256k1_scalar_set_b32_seckey(r: &mut secp256k1_scalar, bin: &[u8; 32]) -> i32 {
    let mut overflow: i32 = 0;
    secp256k1_scalar_set_b32(r, bin, &mut overflow);
    return (!overflow) & (!secp256k1_scalar_is_zero(r) as i32);
}

pub fn secp256k1_ec_seckey_verify(ctx: &secp256k1_context, seckey: &[u8; 32]) -> i32 {
    let mut sec: secp256k1_scalar = secp256k1_scalar{ d: [0; 4] };

    let ret = secp256k1_scalar_set_b32_seckey(&mut sec, seckey);
    secp256k1_scalar_clear(&mut sec);
    return ret;
}