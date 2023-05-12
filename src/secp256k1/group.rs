/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

use super::field_5x52::{secp256k1_fe, secp256k1_fe_storage, SECP256K1_FE_CONST, SECP256K1_FE_STORAGE_CONST};
use crate::SECP256K1_FE_STORAGE_CONST_GET;

 /** A group element in affine coordinates on the secp256k1 curve,
 *  or occasionally on an isomorphic curve of the form y^2 = x^3 + 7*t^6.
 *  Note: For exhaustive test mode, secp256k1 is replaced by a small subgroup of a different curve.
 */
pub struct secp256k1_ge {
    x: secp256k1_fe,
    y: secp256k1_fe,
    infinity: i32, /* whether this represents the point at infinity */
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

struct secp256k1_ge_storage {
    x: secp256k1_fe_storage,
    y: secp256k1_fe_storage,
}

fn SECP256K1_GE_STORAGE_CONST(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32, i: u32, j: u32, k: u32, l: u32, m: u32, n: u32, o: u32, p: u32) -> secp256k1_ge_storage {
    secp256k1_ge_storage {
        x: SECP256K1_FE_STORAGE_CONST(a as u64,b as u64,c as u64,d as u64,e as u64,f as u64,g as u64,h as u64),
        y: SECP256K1_FE_STORAGE_CONST(i as u64,j as u64,k as u64,l as u64, m as u64, n as u64, o as u64,p as u64),
    }
}

fn SECP256K1_GE_STORAGE_CONST_GET(t: secp256k1_ge_storage) -> (secp256k1_fe_storage, secp256k1_fe_storage) {
    (SECP256K1_FE_STORAGE_CONST_GET!(t.x), SECP256K1_FE_STORAGE_CONST_GET!(t.y))
}

