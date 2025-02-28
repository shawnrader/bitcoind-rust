#![allow(warnings)]
use std::process;

// Define the function pointer type using Rust-native types
pub type secp256k1_callback = fn(&str);

fn secp256k1_default_illegal_callback_fn(msg: &str) {
    eprintln!("[libsecp256k1] illegal argument: {}", msg);
    process::abort();
}

fn secp256k1_default_error_callback_fn(msg: &str) {
    eprintln!("[libsecp256k1] internal consistency check failed: {}", msg);
    process::abort();
}


/* Read a uint32_t in big endian */
// SECP256K1_INLINE static uint32_t secp256k1_read_be32(const unsigned char* p) {
//     return (uint32_t)p[0] << 24 |
//            (uint32_t)p[1] << 16 |
//            (uint32_t)p[2] << 8  |
//            (uint32_t)p[3];
// }
pub fn secp256k1_read_be32(p: &[u8]) -> u32 {
    return (p[0] as u32) << 24 |
           (p[1] as u32) << 16 |
           (p[2] as u32) << 8  |
           (p[3] as u32);
}


/* Write a uint32_t in big endian */
// SECP256K1_INLINE static void secp256k1_write_be32(unsigned char* p, uint32_t x) {
//     p[3] = x;
//     p[2] = x >>  8;
//     p[1] = x >> 16;
//     p[0] = x >> 24;
// }

pub fn secp256k1_write_be32(p: &mut [u8], x: u32) {
    p[3] = (x & 0xff) as u8;
    p[2] = ((x >> 8) & 0xff) as u8;
    p[1] = ((x >> 16) & 0xff) as u8;
    p[0] = ((x >> 24) & 0xff) as u8;
}

/* Zero memory if flag == 1. Flag must be 0 or 1. Constant time. */
// static SECP256K1_INLINE void secp256k1_memczero(void *s, size_t len, int flag) {
//     unsigned char *p = (unsigned char *)s;
//     /* Access flag with a volatile-qualified lvalue.
//        This prevents clang from figuring out (after inlining) that flag can
//        take only be 0 or 1, which leads to variable time code. */
//     volatile int vflag = flag;
//     unsigned char mask = -(unsigned char) vflag;
//     while (len) {
//         *p &= ~mask;
//         p++;
//         len--;
//     }
// }

pub fn secp256k1_memczero(s: &mut [u8], flag: bool) {
    let mut p = s;
    let mut mask = 0xff;
    if !flag {
        mask = 0x00;
    }
    for i in 0..p.len() {
        p[i] &= mask;
    }
}