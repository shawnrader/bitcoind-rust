/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

 use crate::secp256k1::util::*;
 use wrapping_arithmetic::wrappit;

// typedef struct {
//      uint32_t s[8];
//      unsigned char buf[64];
//      uint64_t bytes;
// } secp256k1_sha256;

pub struct secp256k1_sha256 {
    s: [u32; 8],
    buf: [u8; 64],
    bytes: u64,
}
 

//  static void secp256k1_sha256_initialize(secp256k1_sha256 *hash);
//  static void secp256k1_sha256_write(secp256k1_sha256 *hash, const unsigned char *data, size_t size);
//  static void secp256k1_sha256_finalize(secp256k1_sha256 *hash, unsigned char *out32);
 
//  typedef struct {
//      secp256k1_sha256 inner, outer;
//  } secp256k1_hmac_sha256;

pub struct secp256k1_hmac_sha256 {
    inner: secp256k1_sha256,
    outer: secp256k1_sha256,
}
 
//  static void secp256k1_hmac_sha256_initialize(secp256k1_hmac_sha256 *hash, const unsigned char *key, size_t size);
//  static void secp256k1_hmac_sha256_write(secp256k1_hmac_sha256 *hash, const unsigned char *data, size_t size);
//  static void secp256k1_hmac_sha256_finalize(secp256k1_hmac_sha256 *hash, unsigned char *out32);
 
//  typedef struct {
//      unsigned char v[32];
//      unsigned char k[32];
//      int retry;
//  } secp256k1_rfc6979_hmac_sha256;

pub struct secp256k1_rfc6979_hmac_sha256 {
    v: [u8; 32],
    k: [u8; 32],
    retry: bool,
}
 
//  static void secp256k1_rfc6979_hmac_sha256_initialize(secp256k1_rfc6979_hmac_sha256 *rng, const unsigned char *key, size_t keylen);
//  static void secp256k1_rfc6979_hmac_sha256_generate(secp256k1_rfc6979_hmac_sha256 *rng, unsigned char *out, size_t outlen);
//  static void secp256k1_rfc6979_hmac_sha256_finalize(secp256k1_rfc6979_hmac_sha256 *rng);

//#define Ch(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
macro_rules! Ch {
    ($x:expr, $y:expr, $z:expr) => {
        ($z) ^ (($x) & (($y) ^ ($z)))
    };
}

//#define Maj(x,y,z) (((x) & (y)) | ((z) & ((x) | (y))))
macro_rules! Maj {
    ($x:expr, $y:expr, $z:expr) => {
        (($x) & ($y)) | (($z) & (($x) | ($y)))
    };
}

//#define Sigma0(x) (((x) >> 2 | (x) << 30) ^ ((x) >> 13 | (x) << 19) ^ ((x) >> 22 | (x) << 10))
macro_rules! Sigma0 {
    ($x:expr) => {
        (($x) >> 2 | ($x) << 30) ^ (($x) >> 13 | ($x) << 19) ^ (($x) >> 22 | ($x) << 10)
    };
}

//#define Sigma1(x) (((x) >> 6 | (x) << 26) ^ ((x) >> 11 | (x) << 21) ^ ((x) >> 25 | (x) << 7))
macro_rules! Sigma1 {
    ($x:expr) => {
        (($x) >> 6 | ($x) << 26) ^ (($x) >> 11 | ($x) << 21) ^ (($x) >> 25 | ($x) << 7)
    };
}

//#define sigma0(x) (((x) >> 7 | (x) << 25) ^ ((x) >> 18 | (x) << 14) ^ ((x) >> 3))
macro_rules! sigma0 {
    ($x:expr) => {
        (($x) >> 7 | ($x) << 25) ^ (($x) >> 18 | ($x) << 14) ^ (($x) >> 3)
    };
}


//#define sigma1(x) (((x) >> 17 | (x) << 15) ^ ((x) >> 19 | (x) << 13) ^ ((x) >> 10))
macro_rules! sigma1 {
    ($x:expr) => {
        (($x) >> 17 | ($x) << 15) ^ (($x) >> 19 | ($x) << 13) ^ (($x) >> 10)
    };
}


// #define Round(a,b,c,d,e,f,g,h,k,w) do { \
//     uint32_t t1 = (h) + Sigma1(e) + Ch((e), (f), (g)) + (k) + (w); \
//     uint32_t t2 = Sigma0(a) + Maj((a), (b), (c)); \
//     (d) += t1; \
//     (h) = t1 + t2; \
// } while(0)
// macro_rules! Round {
//     ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $k:expr, $w:expr) => {
//         let t1 = ($h) + Sigma1!($e) + Ch!($e, $f, $g) + ($k) + ($w);
//         let t2 = Sigma0!($a) + Maj!($a, $b, $c);
//         ($d) += t1;
//         ($h) = t1 + t2;
//     };
// }

#[wrappit]
fn Round(a: u32, b: u32, c: u32, d: &mut u32, e: u32, f: u32, g: u32, h: &mut u32, k: u32, w: u32)
{
    let t1: u32 = h + Sigma1!(e) + Ch!(e, f, g) + k + w;
    let t2: u32 = Sigma0!(a) + Maj!(a, b, c);
    *d = d + t1;
    *h = t1 + t2;
}

// static void secp256k1_sha256_initialize(secp256k1_sha256 *hash) {
//     hash->s[0] = 0x6a09e667ul;
//     hash->s[1] = 0xbb67ae85ul;
//     hash->s[2] = 0x3c6ef372ul;
//     hash->s[3] = 0xa54ff53aul;
//     hash->s[4] = 0x510e527ful;
//     hash->s[5] = 0x9b05688cul;
//     hash->s[6] = 0x1f83d9abul;
//     hash->s[7] = 0x5be0cd19ul;
//     hash->bytes = 0;
// }

pub fn secp256k1_sha256_initialize( hash: &mut secp256k1_sha256) {
     hash.s[0] = 0x6a09e667_u32;
     hash.s[1] = 0xbb67ae85_u32;
     hash.s[2] = 0x3c6ef372_u32;
     hash.s[3] = 0xa54ff53a_u32;
     hash.s[4] = 0x510e527f_u32;
     hash.s[5] = 0x9b05688c_u32;
     hash.s[6] = 0x1f83d9ab_u32;
     hash.s[7] = 0x5be0cd19_u32;
     hash.bytes = 0;
}

/** Perform one SHA-256 transformation, processing 16 big endian 32-bit words. */
//static void secp256k1_sha256_transform(uint32_t* s, const unsigned char* buf) {
pub fn secp256k1_sha256_transform(s: &mut [u32; 8], buf: &[u8; 64]) {

    let mut a = s[0]; let mut b = s[1]; let mut c = s[2]; let mut d = s[3]; let mut e = s[4]; let mut f = s[5]; let mut g = s[6]; let mut h = s[7];
    let (mut w0, mut w1, mut w2, mut w3, mut w4, mut w5, mut w6, mut w7, mut w8, mut w9, mut w10, mut w11, mut w12, mut w13, mut w14, mut w15); (0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32,);

    w0 = secp256k1_read_be32(&buf[0..3]);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x428a2f98,  w0);
    w1 = secp256k1_read_be32(&buf[4..7]);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x71374491,  w1);
    w2 = secp256k1_read_be32(&buf[8..11]);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0xb5c0fbcf,  w2);
    w3 = secp256k1_read_be32(&buf[12..15]);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0xe9b5dba5,  w3);
    w4 = secp256k1_read_be32(&buf[16..19]);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x3956c25b,  w4);
    w5 = secp256k1_read_be32(&buf[20..23]);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x59f111f1,  w5);
    w6 = secp256k1_read_be32(&buf[24..27]);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x923f82a4,  w6);
    w7 = secp256k1_read_be32(&buf[28..31]);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0xab1c5ed5,  w7);
    w8 = secp256k1_read_be32(&buf[32..35]);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0xd807aa98,  w8);
    w9 = secp256k1_read_be32(&buf[36..39]);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x12835b01,  w9);
    w10 = secp256k1_read_be32(&buf[40..43]);;
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x243185be, w10);
    w11 = secp256k1_read_be32(&buf[44..47]);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x550c7dc3, w11);
    w12 = secp256k1_read_be32(&buf[48..51]);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x72be5d74, w12);
    w13 = secp256k1_read_be32(&buf[52..55]);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x80deb1fe, w13);
    w14 = secp256k1_read_be32(&buf[56..59]);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x9bdc06a7, w14);
    w15 = secp256k1_read_be32(&buf[60..63]);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0xc19bf174, w15);

    w0 += sigma1!(w14) + w9 + sigma0!(w1);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0xe49b69c1, w0);
    w1 += sigma1!(w15) + w10 + sigma0!(w2);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0xefbe4786, w1);
    w2 += sigma1!(w0) + w11 + sigma0!(w3);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x0fc19dc6, w2);
    w3 += sigma1!(w1) + w12 + sigma0!(w4);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x240ca1cc, w3);
    w4 += sigma1!(w2) + w13 + sigma0!(w5);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x2de92c6f, w4);
    w5 += sigma1!(w3) + w14 + sigma0!(w6);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x4a7484aa, w5);
    w6 += sigma1!(w4) + w15 + sigma0!(w7);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x5cb0a9dc, w6);
    w7 += sigma1!(w5) + w0 + sigma0!(w8);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x76f988da, w7);
    w8 += sigma1!(w6) + w1 + sigma0!(w9);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x983e5152, w8);
    w9 += sigma1!(w7) + w2 + sigma0!(w10);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0xa831c66d, w9);
    w10 += sigma1!(w8) + w3 + sigma0!(w11);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0xb00327c8, w10);
    w11 += sigma1!(w9) + w4 + sigma0!(w12);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0xbf597fc7, w11);
    w12 += sigma1!(w10) + w5 + sigma0!(w13);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0xc6e00bf3, w12);
    w13 += sigma1!(w11) + w6 + sigma0!(w14);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0xd5a79147, w13);
    w14 += sigma1!(w12) + w7 + sigma0!(w15);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x06ca6351, w14);
    w15 += sigma1!(w13) + w8 + sigma0!(w0);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x14292967, w15);

    w0 += sigma1!(w14) + w9 + sigma0!(w1);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x27b70a85, w0);
    w1 += sigma1!(w15) + w10 + sigma0!(w2);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x2e1b2138, w1);
    w2 += sigma1!(w0) + w11 + sigma0!(w3);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x4d2c6dfc, w2);
    w3 += sigma1!(w1) + w12 + sigma0!(w4);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x53380d13, w3);
    w4 += sigma1!(w2) + w13 + sigma0!(w5);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x650a7354, w4);
    w5 += sigma1!(w3) + w14 + sigma0!(w6);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x766a0abb, w5);
    w6 += sigma1!(w4) + w15 + sigma0!(w7);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x81c2c92e, w6);
    w7 += sigma1!(w5) + w0 + sigma0!(w8);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x92722c85, w7);
    w8 += sigma1!(w6) + w1 + sigma0!(w9);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0xa2bfe8a1, w8);
    w9 += sigma1!(w7) + w2 + sigma0!(w10);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0xa81a664b, w9);
    w10 += sigma1!(w8) + w3 + sigma0!(w11);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0xc24b8b70, w10);
    w11 += sigma1!(w9) + w4 + sigma0!(w12);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0xc76c51a3, w11);
    w12 += sigma1!(w10) + w5 + sigma0!(w13);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0xd192e819, w12);
    w13 += sigma1!(w11) + w6 + sigma0!(w14);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0xd6990624, w13);
    w14 += sigma1!(w12) + w7 + sigma0!(w15);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0xf40e3585, w14);
    w15 += sigma1!(w13) + w8 + sigma0!(w0);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x106aa070, w15);

    w0 += sigma1!(w14) + w9 + sigma0!(w1);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x19a4c116, w0);
    w1 += sigma1!(w15) + w10 + sigma0!(w2);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x1e376c08, w1);
    w2 += sigma1!(w0) + w11 + sigma0!(w3);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x2748774c, w2);
    w3 += sigma1!(w1) + w12 + sigma0!(w4);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x34b0bcb5, w3);
    w4 += sigma1!(w2) + w13 + sigma0!(w5);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x391c0cb3, w4);
    w5 += sigma1!(w3) + w14 + sigma0!(w6);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x4ed8aa4a, w5);
    w6 += sigma1!(w4) + w15 + sigma0!(w7);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x5b9cca4f, w6);
    w7 += sigma1!(w5) + w0 + sigma0!(w8);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x682e6ff3, w7);
    w8 += sigma1!(w6) + w1 + sigma0!(w9);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x748f82ee, w8);
    w9 += sigma1!(w7) + w2 + sigma0!(w10);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x78a5636f, w9);
    w10 += sigma1!(w8) + w3 + sigma0!(w11);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x84c87814, w10);
    w11 += sigma1!(w9) + w4 + sigma0!(w12);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x8cc70208, w11);
    w12 += sigma1!(w10) + w5 + sigma0!(w13);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x90befffa, w12);
    w13 += sigma1!(w11) + w6 + sigma0!(w14);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0xa4506ceb, w13);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0xbef9a3f7, w14 + sigma1!(w12) + w7 + sigma0!(w15));
    Round(b, c, d, &mut e, f, g, h, &mut a, 0xc67178f2, w15 + sigma1!(w13) + w8 + sigma0!(w0));

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}

// static void secp256k1_sha256_write(secp256k1_sha256 *hash, const unsigned char *data, size_t len) {
//     size_t bufsize = hash->bytes & 0x3F;
//     hash->bytes += len;
//     VERIFY_CHECK(hash->bytes >= len);
//     while (len >= 64 - bufsize) {
//         /* Fill the buffer, and process it. */
//         size_t chunk_len = 64 - bufsize;
//         memcpy(hash->buf + bufsize, data, chunk_len);
//         data += chunk_len;
//         len -= chunk_len;
//         secp256k1_sha256_transform(hash->s, hash->buf);
//         bufsize = 0;
//     }
//     if (len) {
//         /* Fill the buffer with what remains. */
//         memcpy(((unsigned char*)hash->buf) + bufsize, data, len);
//     }
// }

pub fn secp256k1_sha256_write(hash: &mut secp256k1_sha256, data: &[u8]) {
    let mut bufsize = hash.bytes as usize & 0x3F;
    let len = data.len();
    hash.bytes += len as u64;
    //VERIFY_CHECK(hash->bytes >= len);
    assert!(hash.bytes >= len as u64);
    while len >= 64 - bufsize {
        /* Fill the buffer, and process it. */
        let chunk_len = 64 - bufsize;
        hash.buf[bufsize..(bufsize + chunk_len) as usize].copy_from_slice(&data[0..chunk_len as usize]);
        //memcpy(hash->buf + bufsize, data, chunk_len);
        //data += chunk_len;
        //len -= chunk_len;
        secp256k1_sha256_transform(&mut hash.s, &hash.buf);
        bufsize = 0;
    }
    if len > 0 {
        /* Fill the buffer with what remains. */
        hash.buf[bufsize..(bufsize + len)].copy_from_slice(&data[0..len]);
        //memcpy(((unsigned char*)hash->buf) + bufsize, data, len);
    }
}

// static void secp256k1_sha256_finalize(secp256k1_sha256 *hash, unsigned char *out32) {
//     static const unsigned char pad[64] = {0x80};
//     unsigned char sizedesc[8];
//     int i;
//     /* The maximum message size of SHA256 is 2^64-1 bits. */
//     VERIFY_CHECK(hash->bytes < ((uint64_t)1 << 61));
//     secp256k1_write_be32(&sizedesc[0], hash->bytes >> 29);
//     secp256k1_write_be32(&sizedesc[4], hash->bytes << 3);
//     secp256k1_sha256_write(hash, pad, 1 + ((119 - (hash->bytes % 64)) % 64));
//     secp256k1_sha256_write(hash, sizedesc, 8);
//     for (i = 0; i < 8; i++) {
//         secp256k1_write_be32(&out32[4*i], hash->s[i]);
//         hash->s[i] = 0;
//     }
// }

pub fn secp256k1_sha256_finalize(hash: &mut secp256k1_sha256, out32: &mut [u8; 32]) {
    static PAD: [u8; 64] = [0x80; 64];
    let mut sizedesc = [0u8; 8];
    let mut i: usize;
    let bytes = hash.bytes as usize;
    /* The maximum message size of SHA256 is 2^64-1 bits. */
    //VERIFY_CHECK(hash->bytes < ((uint64_t)1 << 61));
    assert!(hash.bytes < ((1u64) << 61));
    secp256k1_write_be32(&mut sizedesc[0..4], (bytes >> 29) as u32);
    secp256k1_write_be32(&mut sizedesc[4..8], (bytes << 3) as u32);
    secp256k1_sha256_write(hash, &PAD[0..(1 + ((119 - (bytes % 64)) % 64))]);
    secp256k1_sha256_write(hash, &sizedesc);
    for i in 0..8 {
        secp256k1_write_be32(&mut out32[4*i..(4*i+4)], hash.s[i]);
        hash.s[i] = 0;
    }
}

// static void secp256k1_sha256_initialize_tagged(secp256k1_sha256 *hash, const unsigned char *tag, size_t taglen) {
//     unsigned char buf[32];
//     secp256k1_sha256_initialize(hash);
//     secp256k1_sha256_write(hash, tag, taglen);
//     secp256k1_sha256_finalize(hash, buf);

//     secp256k1_sha256_initialize(hash);
//     secp256k1_sha256_write(hash, buf, 32);
//     secp256k1_sha256_write(hash, buf, 32);
// }

/// Initializes a sha256 struct and writes the 64 byte string
/// SHA256(tag)||SHA256(tag) into it.
pub fn secp256k1_sha256_initialize_tagged(hash: &mut secp256k1_sha256, tag: &[u8]) {
    let mut buf = [0u8; 32];
    secp256k1_sha256_initialize(hash);
    secp256k1_sha256_write(hash, tag);
    secp256k1_sha256_finalize(hash, &mut buf);

    secp256k1_sha256_initialize(hash);
    secp256k1_sha256_write(hash, &buf);
    secp256k1_sha256_write(hash, &buf);
}

// static void secp256k1_hmac_sha256_initialize(secp256k1_hmac_sha256 *hash, const unsigned char *key, size_t keylen) {
//     size_t n;
//     unsigned char rkey[64];
//     if (keylen <= sizeof(rkey)) {
//         memcpy(rkey, key, keylen);
//         memset(rkey + keylen, 0, sizeof(rkey) - keylen);
//     } else {
//         secp256k1_sha256 sha256;
//         secp256k1_sha256_initialize(&sha256);
//         secp256k1_sha256_write(&sha256, key, keylen);
//         secp256k1_sha256_finalize(&sha256, rkey);
//         memset(rkey + 32, 0, 32);
//     }

//     secp256k1_sha256_initialize(&hash->outer);
//     for (n = 0; n < sizeof(rkey); n++) {
//         rkey[n] ^= 0x5c;
//     }
//     secp256k1_sha256_write(&hash->outer, rkey, sizeof(rkey));

//     secp256k1_sha256_initialize(&hash->inner);
//     for (n = 0; n < sizeof(rkey); n++) {
//         rkey[n] ^= 0x5c ^ 0x36;
//     }
//     secp256k1_sha256_write(&hash->inner, rkey, sizeof(rkey));
//     memset(rkey, 0, sizeof(rkey));
// }

pub fn secp256k1_hmac_sha256_initialize(hash: &mut secp256k1_hmac_sha256, key: &[u8]) {
    let mut n: usize;
    let mut rkey = [0u8; 64];
    if key.len() <= 64 {
        rkey[0..key.len()].copy_from_slice(key);
        rkey[key.len()..64].copy_from_slice(&[0u8; 64][key.len()..64]);
    } else {
        let mut sha256 = secp256k1_sha256 { s: [0; 8], buf: [0; 64], bytes: 0};
        secp256k1_sha256_initialize(&mut sha256);
        secp256k1_sha256_write(&mut sha256, key);
        let mut hash_final = [0u8; 32];
        secp256k1_sha256_finalize(&mut sha256, &mut hash_final);
        rkey[0..32].copy_from_slice(&hash_final);
        rkey[32..64].copy_from_slice(&[0u8; 32]);
    }

    secp256k1_sha256_initialize(&mut hash.outer);
    for n in 0..64 {
        rkey[n] ^= 0x5c;
    }
    secp256k1_sha256_write(&mut hash.outer, &rkey);

    secp256k1_sha256_initialize(&mut hash.inner);
    for n in 0..64 {
        rkey[n] ^= 0x5c ^ 0x36;
    }
    secp256k1_sha256_write(&mut hash.inner, &rkey);
    rkey = [0u8; 64];
}


// static void secp256k1_hmac_sha256_write(secp256k1_hmac_sha256 *hash, const unsigned char *data, size_t size) {
//     secp256k1_sha256_write(&hash->inner, data, size);
// }
pub fn secp256k1_hmac_sha256_write(hash: &mut secp256k1_hmac_sha256, data: &[u8]) {
    secp256k1_sha256_write(&mut hash.inner, data);
}


// static void secp256k1_hmac_sha256_finalize(secp256k1_hmac_sha256 *hash, unsigned char *out32) {
//     unsigned char temp[32];
//     secp256k1_sha256_finalize(&hash->inner, temp);
//     secp256k1_sha256_write(&hash->outer, temp, 32);
//     memset(temp, 0, 32);
//     secp256k1_sha256_finalize(&hash->outer, out32);
// }
pub fn secp256k1_hmac_sha256_finalize(hash: &mut secp256k1_hmac_sha256, out32: &mut [u8]) {
    let mut temp = [0u8; 32];
    secp256k1_sha256_finalize(&mut hash.inner, &mut temp);
    secp256k1_sha256_write(&mut hash.outer, &temp);
    temp = [0u8; 32];
    secp256k1_sha256_finalize(&mut hash.outer, out32.try_into().unwrap());
}

// static void secp256k1_rfc6979_hmac_sha256_initialize(secp256k1_rfc6979_hmac_sha256 *rng, const unsigned char *key, size_t keylen) {
//     secp256k1_hmac_sha256 hmac;
//     static const unsigned char zero[1] = {0x00};
//     static const unsigned char one[1] = {0x01};

//     memset(rng->v, 0x01, 32); /* RFC6979 3.2.b. */
//     memset(rng->k, 0x00, 32); /* RFC6979 3.2.c. */

//     /* RFC6979 3.2.d. */
//     secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
//     secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
//     secp256k1_hmac_sha256_write(&hmac, zero, 1);
//     secp256k1_hmac_sha256_write(&hmac, key, keylen);
//     secp256k1_hmac_sha256_finalize(&hmac, rng->k);
//     secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
//     secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
//     secp256k1_hmac_sha256_finalize(&hmac, rng->v);

//     /* RFC6979 3.2.f. */
//     secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
//     secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
//     secp256k1_hmac_sha256_write(&hmac, one, 1);
//     secp256k1_hmac_sha256_write(&hmac, key, keylen);
//     secp256k1_hmac_sha256_finalize(&hmac, rng->k);
//     secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
//     secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
//     secp256k1_hmac_sha256_finalize(&hmac, rng->v);
//     rng->retry = 0;
// }
pub fn secp256k1_rfc6979_hmac_sha256_initialize(rng: &mut secp256k1_rfc6979_hmac_sha256, key: &[u8]) {
    let mut hmac: secp256k1_hmac_sha256;
    static ZERO: [u8; 1] = [0x00];
    static ONE: [u8; 1] = [0x01];

    rng.v = [0x01; 32]; /* RFC6979 3.2.b. */
    rng.k = [0x00; 32]; /* RFC6979 3.2.c. */

    /* RFC6979 3.2.d. */
    secp256k1_hmac_sha256_initialize(&mut hmac, &rng.k);
    secp256k1_hmac_sha256_write(&mut hmac, &rng.v);
    secp256k1_hmac_sha256_write(&mut hmac, &ZERO);
    secp256k1_hmac_sha256_write(&mut hmac, key);
    secp256k1_hmac_sha256_finalize(&mut hmac, &mut rng.k);
    secp256k1_hmac_sha256_initialize(&mut hmac, &rng.k);
    secp256k1_hmac_sha256_write(&mut hmac, &rng.v);
    secp256k1_hmac_sha256_finalize(&mut hmac, &mut rng.v);

    /* RFC6979 3.2.f. */
    secp256k1_hmac_sha256_initialize(&mut hmac, &rng.k);
    secp256k1_hmac_sha256_write(&mut hmac, &rng.v);
    secp256k1_hmac_sha256_write(&mut hmac, &ONE);
    secp256k1_hmac_sha256_write(&mut hmac, key);
    secp256k1_hmac_sha256_finalize(&mut hmac, &mut rng.k);
    secp256k1_hmac_sha256_initialize(&mut hmac, &rng.k);
    secp256k1_hmac_sha256_write(&mut hmac, &rng.v);
    secp256k1_hmac_sha256_finalize(&mut hmac, &mut rng.v);
    rng.retry = false;
}


// static void secp256k1_rfc6979_hmac_sha256_generate(secp256k1_rfc6979_hmac_sha256 *rng, unsigned char *out, size_t outlen) {
//     /* RFC6979 3.2.h. */
//     static const unsigned char zero[1] = {0x00};
//     if (rng->retry) {
//         secp256k1_hmac_sha256 hmac;
//         secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
//         secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
//         secp256k1_hmac_sha256_write(&hmac, zero, 1);
//         secp256k1_hmac_sha256_finalize(&hmac, rng->k);
//         secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
//         secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
//         secp256k1_hmac_sha256_finalize(&hmac, rng->v);
//     }

//     while (outlen > 0) {
//         secp256k1_hmac_sha256 hmac;
//         int now = outlen;
//         secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
//         secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
//         secp256k1_hmac_sha256_finalize(&hmac, rng->v);
//         if (now > 32) {
//             now = 32;
//         }
//         memcpy(out, rng->v, now);
//         out += now;
//         outlen -= now;
//     }

//     rng->retry = 1;
// }

pub fn secp256k1_rfc6979_hmac_sha256_generate(rng: &secp256k1_rfc6979_hmac_sha256, out: &mut [u8]) {
    /* RFC6979 3.2.h. */
    static ZERO: [u8; 1] = [0x00];
    if rng.retry {
        let mut hmac: secp256k1_hmac_sha256;
        secp256k1_hmac_sha256_initialize(&mut hmac, &rng.k);
        secp256k1_hmac_sha256_write(&mut hmac, &rng.v);
        secp256k1_hmac_sha256_write(&mut hmac, &ZERO);
        secp256k1_hmac_sha256_finalize(&mut hmac, &mut rng.k);
        secp256k1_hmac_sha256_initialize(&mut hmac, &rng.k);
        secp256k1_hmac_sha256_write(&mut hmac, &rng.v);
        secp256k1_hmac_sha256_finalize(&mut hmac, &mut rng.v);
    }

    let mut i = 0;
    let mut outlen = out.len();
    while outlen > 0 {
        let mut hmac: secp256k1_hmac_sha256;
        let mut now = outlen;
        secp256k1_hmac_sha256_initialize(&mut hmac, &rng.k);
        secp256k1_hmac_sha256_write(&mut hmac, &rng.v);
        secp256k1_hmac_sha256_finalize(&mut hmac, &mut rng.v);
        if now > 32 {
            now = 32;
        }
        out[i..i + now].copy_from_slice(&rng.v[0..now]);
        i += now;
        outlen -= now;
    }

    rng.retry = true;
}

// static void secp256k1_rfc6979_hmac_sha256_finalize(secp256k1_rfc6979_hmac_sha256 *rng) {
//     memset(rng->k, 0, 32);
//     memset(rng->v, 0, 32);
//     rng->retry = 0;
// }

pub fn secp256k1_rfc6979_hmac_sha256_finalize(rng: &mut secp256k1_rfc6979_hmac_sha256) {
    rng.k = [0u8; 32];
    rng.v = [0u8; 32];
    rng.retry = false;
}
