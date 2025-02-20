/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/
use super::group::*;
use super::field_5x52::*;
use super::*;
use ecmult_impl::*;
use super::scalar_4x64::*;

// static int secp256k1_eckey_pubkey_parse(secp256k1_ge *elem, const unsigned char *pub, size_t size) {
//     if (size == 33 && (pub[0] == SECP256K1_TAG_PUBKEY_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_ODD)) {
//         secp256k1_fe x;
//         return secp256k1_fe_set_b32(&x, pub+1) && secp256k1_ge_set_xo_var(elem, &x, pub[0] == SECP256K1_TAG_PUBKEY_ODD);
//     } else if (size == 65 && (pub[0] == SECP256K1_TAG_PUBKEY_UNCOMPRESSED || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
//         secp256k1_fe x, y;
//         if (!secp256k1_fe_set_b32(&x, pub+1) || !secp256k1_fe_set_b32(&y, pub+33)) {
//             return 0;
//         }
//         secp256k1_ge_set_xy(elem, &x, &y);
//         if ((pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
//             secp256k1_fe_is_odd(&y) != (pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
//             return 0;
//         }
//         return secp256k1_ge_is_valid_var(elem);
//     } else {
//         return 0;
//     }
// }

pub fn secp256k1_eckey_pubkey_parse(elem: &mut secp256k1_ge, pubkey: &[u8]) -> bool {
    if pubkey.len() == 33 && (pubkey[0] == SECP256K1_TAG_PUBKEY_EVEN || pubkey[0] == SECP256K1_TAG_PUBKEY_ODD) {
        let mut x = secp256k1_fe::new();
        return secp256k1_fe_set_b32(&mut x, &pubkey[1..33]) == 1 && secp256k1_ge_set_xo_var(elem, &x, (pubkey[0] == SECP256K1_TAG_PUBKEY_ODD) as i32) == 1;
    } else if pubkey.len() == 65 && (pubkey[0] == SECP256K1_TAG_PUBKEY_UNCOMPRESSED || pubkey[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pubkey[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) {
        let mut x = secp256k1_fe::new();
        let mut y = secp256k1_fe::new();
        if secp256k1_fe_set_b32(&mut x, &pubkey[1..33]) == 0 || secp256k1_fe_set_b32(&mut y, &pubkey[33..65]) == 0 {
            return false;
        }
        secp256k1_ge_set_xy(elem, &x, &y);
        if (pubkey[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pubkey[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
            secp256k1_fe_is_odd(&y) != (pubkey[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) as i32 {
            return false;
        }
        return secp256k1_ge_is_valid_var(elem) != 0;
    } else {
        return false;
    }
}

// static int secp256k1_eckey_pubkey_serialize(secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed) {
//     if (secp256k1_ge_is_infinity(elem)) {
//         return 0;
//     }
//     secp256k1_fe_normalize_var(&elem->x);
//     secp256k1_fe_normalize_var(&elem->y);
//     secp256k1_fe_get_b32(&pub[1], &elem->x);
//     if (compressed) {
//         *size = 33;
//         pub[0] = secp256k1_fe_is_odd(&elem->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
//     } else {
//         *size = 65;
//         pub[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
//         secp256k1_fe_get_b32(&pub[33], &elem->y);
//     }
//     return 1;
// }

pub fn secp256k1_eckey_pubkey_serialize(elem: &mut secp256k1_ge, pubkey: &mut [u8], compressed: bool) -> bool {
    if secp256k1_ge_is_infinity(elem) {
        return false;
    }
    secp256k1_fe_normalize_var(&mut elem.x);
    secp256k1_fe_normalize_var(&mut elem.y);
    secp256k1_fe_get_b32(&mut pubkey[1..33], &elem.x);
    if compressed {
        pubkey[0] = if (secp256k1_fe_is_odd(&elem.y) != 0){ SECP256K1_TAG_PUBKEY_ODD } else { SECP256K1_TAG_PUBKEY_EVEN };
    } else {
        pubkey[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
        secp256k1_fe_get_b32(&mut pubkey[33..65], &elem.y);
    }
    return true;
}

// static int secp256k1_eckey_privkey_tweak_add(secp256k1_scalar *key, const secp256k1_scalar *tweak) {
//     secp256k1_scalar_add(key, key, tweak);
//     return !secp256k1_scalar_is_zero(key);
// }

pub fn secp256k1_eckey_privkey_tweak_add(key: &mut secp256k1_scalar, tweak: &secp256k1_scalar) -> bool {
    secp256k1_scalar_add(key, key, tweak);
    return !secp256k1_scalar_is_zero(key);
}

// static int secp256k1_eckey_pubkey_tweak_add(secp256k1_ge *key, const secp256k1_scalar *tweak) {
//     secp256k1_gej pt;
//     secp256k1_scalar one;
//     secp256k1_gej_set_ge(&pt, key);
//     secp256k1_scalar_set_int(&one, 1);
//     secp256k1_ecmult(&pt, &pt, &one, tweak);

//     if (secp256k1_gej_is_infinity(&pt)) {
//         return 0;
//     }
//     secp256k1_ge_set_gej(key, &pt);
//     return 1;
// }

pub fn secp256k1_eckey_pubkey_tweak_add(key: &mut secp256k1_ge, tweak: &secp256k1_scalar) -> bool {
    let mut pt = secp256k1_gej::new();
    let mut one = secp256k1_scalar::new();
    secp256k1_gej_set_ge(&mut pt, key);
    secp256k1_scalar_set_int(&mut one, 1);
    secp256k1_ecmult(&mut pt, &pt, &one, tweak);

    if secp256k1_gej_is_infinity(&pt) {
        return false;
    }
    secp256k1_ge_set_gej(key, &pt);
    return true;
}

// static int secp256k1_eckey_privkey_tweak_mul(secp256k1_scalar *key, const secp256k1_scalar *tweak) {
//     int ret;
//     ret = !secp256k1_scalar_is_zero(tweak);

//     secp256k1_scalar_mul(key, key, tweak);
//     return ret;
// }

pub fn secp256k1_eckey_privkey_tweak_mul(key: &mut secp256k1_scalar, tweak: &secp256k1_scalar) -> bool {
    let ret = !secp256k1_scalar_is_zero(tweak);

    secp256k1_scalar_mul(key, key, tweak);
    return ret;
}

// static int secp256k1_eckey_pubkey_tweak_mul(secp256k1_ge *key, const secp256k1_scalar *tweak) {
//     secp256k1_scalar zero;
//     secp256k1_gej pt;
//     if (secp256k1_scalar_is_zero(tweak)) {
//         return 0;
//     }

//     secp256k1_scalar_set_int(&zero, 0);
//     secp256k1_gej_set_ge(&pt, key);
//     secp256k1_ecmult(&pt, &pt, tweak, &zero);
//     secp256k1_ge_set_gej(key, &pt);
//     return 1;
// }

pub fn secp256k1_eckey_pubkey_tweak_mul(key: &mut secp256k1_ge, tweak: &secp256k1_scalar) -> bool {
    let mut zero = secp256k1_scalar::new();
    let mut pt = secp256k1_gej::new();
    if secp256k1_scalar_is_zero(tweak) {
        return false;
    }

    secp256k1_scalar_set_int(&mut zero, 0);
    secp256k1_gej_set_ge(&mut pt, key);
    secp256k1_ecmult(&mut pt, &pt, tweak, &zero);
    secp256k1_ge_set_gej(key, &pt);
    return true;
}