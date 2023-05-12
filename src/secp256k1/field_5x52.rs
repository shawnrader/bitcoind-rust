/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

pub struct secp256k1_fe {
     /* X = sum(i=0..4, n[i]*2^(i*52)) mod p
      * where p = 2^256 - 0x1000003D1
      */
    n : [u64; 5],

#[cfg(feature = "verify")]
    magnitude: i32,
#[cfg(feature = "verify")]
    normalized: i32,
}

impl secp256k1_fe {
    pub fn new() -> secp256k1_fe {
        secp256k1_fe {
            n: [0, 0, 0, 0, 0],
            #[cfg(feature = "verify")]
            magnitude: 0,
            #[cfg(feature = "verify")]
            normalized: 0,
        }
    }
}
 
 /* Unpacks a constant into a overlapping multi-limbed FE element. */
 fn SECP256K1_FE_CONST_INNER(d7: u64, d6: u64, d5: u64, d4: u64, d3: u64, d2: u64, d1: u64, d0: u64) -> [u64; 5] {
    [(d0) | ((d1 & 0xFFFFF_u64) << 32), 
    (d1 >> 20) | (d2 << 12) | ((d3 & 0xFFu64) << 44),
    (d3 >> 8) | ((d4 & 0xFFFFFFF_u64) << 24),
    (d4 >> 28) | (d5 << 4) | ((d6 & 0xFFFF_u64) << 36),
    (d6 >> 16) | (d7 << 16)]
 }
 
#[cfg(feature = "verify")]
pub fn SECP256K1_FE_CONST(d7: u64, d6: u64, d5: u64, d4: u64, d3: u64, d2: u64, d1: u64, d0: u64) -> secp256k1_fe {
    secp256k1_fe { 
        n: SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)),
        magnitude: 1,
        normalized: 1
    }
}
 
#[cfg(not (feature = "verify"))]
pub fn SECP256K1_FE_CONST(d7: u32, d6: u32, d5: u32, d4: u32, d3: u32, d2: u32, d1: u32, d0: u32) -> secp256k1_fe {
    secp256k1_fe { 
        n: SECP256K1_FE_CONST_INNER(d7 as u64, d6 as u64, d5 as u64, d4 as u64, d3 as u64, d2 as u64, d1 as u64, d0 as u64)
    }
}

pub struct secp256k1_fe_storage {
    pub n: [u64; 4],
}
 
pub fn SECP256K1_FE_STORAGE_CONST(d7: u64, d6: u64, d5: u64, d4: u64, d3: u64, d2: u64, d1: u64, d0: u64) -> secp256k1_fe_storage {
    secp256k1_fe_storage {
        n : [(d0) | ((d1 as u64) << 32),
             (d2) | ((d3 as u64) << 32),
             (d4) | ((d5 as u64) << 32),
             (d6) | ((d7 as u64) << 32),
        ]
    }
}

#[macro_export] 
macro_rules! SECP256K1_FE_STORAGE_CONST_GET {
    ($d:expr) => {
        (($d.n[3] >> 32) as u32, $d.n[3] as u32,
         ($d.n[2] >> 32) as u32, $d.n[2] as u32,
         ($d.n[1] >> 32) as u32, $d.n[1] as u32,
         ($d.n[0] >> 32) as u32, $d.n[0] as u32)
    }
}