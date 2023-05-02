// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::crypto::common::{WriteBE64, WriteBE32, ReadBE32};
use wrapping_arithmetic::wrappit;

pub struct CSHA512
{
    s: [u64; 8],
    buf: [u8; 128],
    bytes: u64,
}

impl CSHA512 {
    pub fn new() -> Self {
        let mut s = [0 as u64; 8];
        Initialize(&mut s);
        Self {s, buf: [0; 128],  bytes: 0}
    }


    pub fn Write(&mut self, mut data: &[u8], len: usize) -> &mut Self
    {
        //const unsigned char* end = data + len;
        let mut end = len;
        let mut bufsize: usize = (self.bytes % 128) as usize;
        //if (bufsize && bufsize + len >= 128) {
        if bufsize > 0 && bufsize + len >= 128 {
            // Fill the buffer, and process it.
            //memcpy(buf + bufsize, data, 128 - bufsize);
            self.buf[bufsize..].copy_from_slice(&data[0..(128 - bufsize)]);
            // bytes += 128 - bufsize;
            self.bytes += 128 - bufsize as u64;
            //data += 128 - bufsize;
            data = &data[(128-bufsize)..];
            Transform(&mut self.s, &mut self.buf, 1);
            bufsize = 0;
        }
        //if (end - data >= 128) {
        if data.len() >= 128
        {
            //size_t blocks = (end - data) / 128;
            let blocks: usize = data.len() / 128;
            Transform(&mut self.s, &mut data, blocks);
            //data += 128 * blocks;
            data = &data[(128 * blocks)..];
            self.bytes += 128 * blocks as u64;
        }
        //if (end > data) {
        if data.len() > 0
        {
            // Fill the buffer with what remains.
            //memcpy(buf + bufsize, data, end - data);
            self.buf[bufsize..(bufsize + data.len())].copy_from_slice(data);
            //bytes += end - data;
            self.bytes += data.len() as u64;
        }
        self
    }

    pub fn Finalize(&mut self, hash: &mut [u8; CSHA256::OUTPUT_SIZE])
    {
        //static const unsigned char pad[64] = {0x80};
        let mut pad: [u8; 128] = [0x80; 128];
        //unsigned char sizedesc[8];
        let mut sizedesc: [u8; 16] = [0; 16];
        WriteBE64(&mut sizedesc[8..], self.bytes << 3);
        self.Write(&mut pad, 1 + ((239 - (self.bytes % 128)) % 128) as usize);
        self.Write(&mut sizedesc, 16);
        WriteBE64(&mut hash[0..8], self.s[0]);
        WriteBE64(&mut hash[8..16], self.s[1]);
        WriteBE64(&mut hash[16..24], self.s[2]);
        WriteBE64(&mut hash[24..32], self.s[3]);
        WriteBE64(&mut hash[32..40], self.s[4]);
        WriteBE64(&mut hash[40..48], self.s[5]);
        WriteBE64(&mut hash[48..56], self.s[6]);
        WriteBE64(&mut hash[56..64], self.s[7]);
    }

}

//uint64_t inline Ch(uint64_t x, uint64_t y, uint64_t z) { return z ^ (x & (y ^ z)); }
fn Ch(x: u64, y: u64, z: u64) -> u64 { z ^ (x & (y ^ z)) }

//uint64_t inline Maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) | (z & (x | y)); }
fn Maj(x: u64, y: u64, z: u64) -> u64 { (x & y) | (z & (x | y)) }

//uint64_t inline Sigma0(uint64_t x) { return (x >> 28 | x << 36) ^ (x >> 34 | x << 30) ^ (x >> 39 | x << 25); }
fn Sigma0(x: u64) -> u64 { (x >> 28 | x << 36) ^ (x >> 34 | x << 30) ^ (x >> 39 | x << 25) }

//uint64_t inline Sigma1(uint64_t x) { return (x >> 14 | x << 50) ^ (x >> 18 | x << 46) ^ (x >> 41 | x << 23); }
fn Sigma1(x: u64) -> u64 { (x >> 14 | x << 50) ^ (x >> 18 | x << 46) ^ (x >> 41 | x << 23) }

//uint64_t inline sigma0(uint64_t x) { return (x >> 1 | x << 63) ^ (x >> 8 | x << 56) ^ (x >> 7); }
fn sigma0(x: u64) -> u64 { (x >> 1 | x << 63) ^ (x >> 8 | x << 56) ^ (x >> 7) }

//uint64_t inline sigma1(uint64_t x) { return (x >> 19 | x << 45) ^ (x >> 61 | x << 3) ^ (x >> 6); }
fn sigma1(x: u64) -> u64 { (x >> 19 | x << 45) ^ (x >> 61 | x << 3) ^ (x >> 6) }

/** One round of SHA-512. */
#[wrappit]
fn Round(a: u64, b: u64, c: u64, d: &mut u64, e: u64, f: u64, g: u64, h: &mut u64, k: u64)
{
    let t1: u64 = h + Sigma1(e) + Ch(e, f, g) + k + w;
    let t2: u64 = Sigma0(a) + Maj(a, b, c);
    *d = d + t1;
    *h = t1 + t2;
}

/** Initialize SHA-512 state. */
fn Initialize(s: &mut [u64])
{
    s[0] = 0x6a09e667f3bcc908;
    s[1] = 0xbb67ae8584caa73b;
    s[2] = 0x3c6ef372fe94f82b;
    s[3] = 0xa54ff53a5f1d36f1;
    s[4] = 0x510e527fade682d1;
    s[5] = 0x9b05688c2b3e6c1f;
    s[6] = 0x1f83d9abfb41bd6b;
    s[7] = 0x5be0cd19137e2179;
}