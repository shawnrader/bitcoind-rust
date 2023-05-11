// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::crypto::common::{WriteBE64, ReadBE64};
use wrapping_arithmetic::wrappit;
use crate::crypto::Hasher;

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

}

impl Hasher for CSHA512 {
    const OUTPUT_SIZE: usize = 64;

    fn Write(&mut self, mut data: &mut [u8], len: usize) -> &mut Self
    {
        let mut bufsize: usize = (self.bytes % 128) as usize;
        //if (bufsize && bufsize + len >= 128) {
        if bufsize > 0 && bufsize + len >= 128 {
            // Fill the buffer, and process it.
            //memcpy(buf + bufsize, data, 128 - bufsize);
            self.buf[bufsize..].copy_from_slice(&data[0..(128 - bufsize)]);
            // bytes += 128 - bufsize;
            self.bytes += 128 - bufsize as u64;
            //data += 128 - bufsize;
            data = &mut data[(128-bufsize)..];
            Transform(&mut self.s, &mut self.buf);
            bufsize = 0;
        }
        //if (end - data >= 128) {
        if data.len() >= 128
        {
            //size_t blocks = (end - data) / 128;
            let blocks: usize = data.len() / 128;
            Transform(&mut self.s, data);
            //data += 128 * blocks;
            data = &mut data[(128 * blocks)..];
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

    fn Finalize(&mut self, hash: &mut [u8])
    {
        assert!(hash.len() == Self::OUTPUT_SIZE);
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


    fn Reset(&mut self) -> &mut Self
    {
        self.bytes = 0;
        Initialize(&mut self.s);
        self
    }

    fn Size(&self) -> usize
    {
        self.bytes as usize
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
fn Round(a: u64, b: u64, c: u64, d: &mut u64, e: u64, f: u64, g: u64, h: &mut u64, k: u64, w: u64)
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

/** Perform one SHA-512 transformation, processing a 128-byte chunk. */
// void Transform(uint64_t* s, const unsigned char* chunk)
#[wrappit]
fn Transform(s: &mut [u64], chunk: &mut [u8])
{
    //uint64_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
    //uint64_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;
    let (mut w0, mut w1, mut w2, mut w3, mut w4, mut w5, mut w6, mut w7, mut w8, mut w9, mut w10, mut w11, mut w12, mut w13, mut w14, mut w15) : (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64);

    w0 = ReadBE64(&chunk[0..]);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x428a2f98d728ae22, w0);
    w1 = ReadBE64(&chunk[8..]);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x7137449123ef65cd, w1);
    w2 = ReadBE64(&chunk[16..]);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0xb5c0fbcfec4d3b2f, w2);
    w3 = ReadBE64(&chunk[24..]);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0xe9b5dba58189dbbc, w3);
    w4 = ReadBE64(&chunk[32..]);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x3956c25bf348b538, w4);
    w5 = ReadBE64(&chunk[40..]);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x59f111f1b605d019, w5);
    w6 = ReadBE64(&chunk[48..]);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x923f82a4af194f9b, w6);
    w7 = ReadBE64(&chunk[56..]);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0xab1c5ed5da6d8118, w7);
    w8 = ReadBE64(&chunk[64..]);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0xd807aa98a3030242, w8);
    w9 = ReadBE64(&chunk[72..]);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x12835b0145706fbe, w9);
    w10 = ReadBE64(&chunk[80..]);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x243185be4ee4b28c, w10);
    w11 = ReadBE64(&chunk[88..]);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x550c7dc3d5ffb4e2, w11);
    w12 = ReadBE64(&chunk[96..]);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x72be5d74f27b896f, w12);
    w13 = ReadBE64(&chunk[104..]);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x80deb1fe3b1696b1, w13);
    w14 = ReadBE64(&chunk[112..]);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x9bdc06a725c71235, w14);
    w15 = ReadBE64(&chunk[120..]);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0xc19bf174cf692694, w15);

    w0 += sigma1(w14) + w9 + sigma0(w1);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0xe49b69c19ef14ad2, w0);
    w1 += sigma1(w15) + w10 + sigma0(w2);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0xefbe4786384f25e3, w1);
    w2 += sigma1(w0) + w11 + sigma0(w3);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x0fc19dc68b8cd5b5, w2);
    w3 += sigma1(w1) + w12 + sigma0(w4);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x240ca1cc77ac9c65, w3);
    w4 += sigma1(w2) + w13 + sigma0(w5);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x2de92c6f592b0275, w4);
    w5 += sigma1(w3) + w14 + sigma0(w6);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x4a7484aa6ea6e483, w5);
    w6 += sigma1(w4) + w15 + sigma0(w7);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x5cb0a9dcbd41fbd4, w6);
    w7 += sigma1(w5) + w0 + sigma0(w8);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x76f988da831153b5, w7);
    w8 += sigma1(w6) + w1 + sigma0(w9);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x983e5152ee66dfab, w8);
    w9 += sigma1(w7) + w2 + sigma0(w10);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0xa831c66d2db43210, w9);
    w10 += sigma1(w8) + w3 + sigma0(w11);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0xb00327c898fb213f, w10);
    w11 += sigma1(w9) + w4 + sigma0(w12);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0xbf597fc7beef0ee4, w11);
    w12 += sigma1(w10) + w5 + sigma0(w13);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0xc6e00bf33da88fc2, w12);
    w13 += sigma1(w11) + w6 + sigma0(w14);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0xd5a79147930aa725, w13);
    w14 += sigma1(w12) + w7 + sigma0(w15);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x06ca6351e003826f, w14);
    w15 += sigma1(w13) + w8 + sigma0(w0);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x142929670a0e6e70, w15);

    w0 += sigma1(w14) + w9 + sigma0(w1);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x27b70a8546d22ffc, w0);
    w1 += sigma1(w15) + w10 + sigma0(w2);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x2e1b21385c26c926, w1);
    w2 += sigma1(w0) + w11 + sigma0(w3);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x4d2c6dfc5ac42aed, w2);
    w3 += sigma1(w1) + w12 + sigma0(w4);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x53380d139d95b3df, w3);
    w4 += sigma1(w2) + w13 + sigma0(w5);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x650a73548baf63de, w4);
    w5 += sigma1(w3) + w14 + sigma0(w6);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x766a0abb3c77b2a8, w5);
    w6 += sigma1(w4) + w15 + sigma0(w7);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x81c2c92e47edaee6, w6);
    w7 += sigma1(w5) + w0 + sigma0(w8);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x92722c851482353b, w7);
    w8 += sigma1(w6) + w1 + sigma0(w9);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0xa2bfe8a14cf10364, w8);
    w9 += sigma1(w7) + w2 + sigma0(w10);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0xa81a664bbc423001, w9);
    w10 += sigma1(w8) + w3 + sigma0(w11);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0xc24b8b70d0f89791, w10);
    w11 += sigma1(w9) + w4 + sigma0(w12);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0xc76c51a30654be30, w11);
    w12 += sigma1(w10) + w5 + sigma0(w13);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0xd192e819d6ef5218, w12);
    w13 += sigma1(w11) + w6 + sigma0(w14);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0xd69906245565a910, w13);
    w14 += sigma1(w12) + w7 + sigma0(w15);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0xf40e35855771202a, w14);
    w15 += sigma1(w13) + w8 + sigma0(w0);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x106aa07032bbd1b8, w15);

    w0 += sigma1(w14) + w9 + sigma0(w1);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x19a4c116b8d2d0c8, w0);
    w1 += sigma1(w15) + w10 + sigma0(w2);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x1e376c085141ab53, w1);
    w2 += sigma1(w0) + w11 + sigma0(w3);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x2748774cdf8eeb99, w2);
    w3 += sigma1(w1) + w12 + sigma0(w4);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x34b0bcb5e19b48a8, w3);
    w4 += sigma1(w2) + w13 + sigma0(w5);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x391c0cb3c5c95a63, w4);
    w5 += sigma1(w3) + w14 + sigma0(w6);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x4ed8aa4ae3418acb, w5);
    w6 += sigma1(w4) + w15 + sigma0(w7);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x5b9cca4f7763e373, w6);
    w7 += sigma1(w5) + w0 + sigma0(w8);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x682e6ff3d6b2b8a3, w7);
    w8 += sigma1(w6) + w1 + sigma0(w9);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x748f82ee5defb2fc, w8);
    w9 += sigma1(w7) + w2 + sigma0(w10);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x78a5636f43172f60, w9);
    w10 += sigma1(w8) + w3 + sigma0(w11);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x84c87814a1f0ab72, w10);
    w11 += sigma1(w9) + w4 + sigma0(w12);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x8cc702081a6439ec, w11);
    w12 += sigma1(w10) + w5 + sigma0(w13);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x90befffa23631e28, w12);
    w13 += sigma1(w11) + w6 + sigma0(w14);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0xa4506cebde82bde9, w13);
    w14 += sigma1(w12) + w7 + sigma0(w15);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0xbef9a3f7b2c67915, w14);
    w15 += sigma1(w13) + w8 + sigma0(w0);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0xc67178f2e372532b, w15);

    w0 += sigma1(w14) + w9 + sigma0(w1);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0xca273eceea26619c, w0);
    w1 += sigma1(w15) + w10 + sigma0(w2);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0xd186b8c721c0c207, w1);
    w2 += sigma1(w0) + w11 + sigma0(w3);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0xeada7dd6cde0eb1e, w2);
    w3 += sigma1(w1) + w12 + sigma0(w4);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0xf57d4f7fee6ed178, w3);
    w4 += sigma1(w2) + w13 + sigma0(w5);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x06f067aa72176fba, w4);
    w5 += sigma1(w3) + w14 + sigma0(w6);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x0a637dc5a2c898a6, w5);
    w6 += sigma1(w4) + w15 + sigma0(w7);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x113f9804bef90dae, w6);
    w7 += sigma1(w5) + w0 + sigma0(w8);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x1b710b35131c471b, w7);
    w8 += sigma1(w6) + w1 + sigma0(w9);
    Round(a, b, c, &mut d, e, f, g, &mut h, 0x28db77f523047d84, w8);
    w9 += sigma1(w7) + w2 + sigma0(w10);
    Round(h, a, b, &mut c, d, e, f, &mut g, 0x32caab7b40c72493, w9);
    w10 += sigma1(w8) + w3 + sigma0(w11);
    Round(g, h, a, &mut b, c, d, e, &mut f, 0x3c9ebe0a15c9bebc, w10);
    w11 += sigma1(w9) + w4 + sigma0(w12);
    Round(f, g, h, &mut a, b, c, d, &mut e, 0x431d67c49c100d4c, w11);
    w12 += sigma1(w10) + w5 + sigma0(w13);
    Round(e, f, g, &mut h, a, b, c, &mut d, 0x4cc5d4becb3e42b6, w12);
    w13 += sigma1(w11) + w6 + sigma0(w14);
    Round(d, e, f, &mut g, h, a, b, &mut c, 0x597f299cfc657e2a, w13);
    w14 += sigma1(w12) + w7 + sigma0(w15);
    Round(c, d, e, &mut f, g, h, a, &mut b, 0x5fcb6fab3ad6faec, w14);
    w15 += sigma1(w13) + w8 + sigma0(w0);
    Round(b, c, d, &mut e, f, g, h, &mut a, 0x6c44198c4a475817, w15);

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}

mod tests {
    use crate::crypto::Hasher;
    use super::CSHA512;
    use hex;
    /*
    template<typename Hasher, typename In, typename Out>
    static void TestVector(const Hasher &h, const In &in, const Out &out) {
        Out hash;
        BOOST_CHECK(out.size() == h.OUTPUT_SIZE);
        hash.resize(out.size());
        {
            // Test that writing the whole input string at once works.
            Hasher(h).Write((const uint8_t*)in.data(), in.size()).Finalize(hash.data());
            BOOST_CHECK(hash == out);
        }
        for (int i=0; i<32; i++) {
            // Test that writing the string broken up in random pieces works.
            Hasher hasher(h);
            size_t pos = 0;
            while (pos < in.size()) {
                size_t len = InsecureRandRange((in.size() - pos + 1) / 2 + 1);
                hasher.Write((const uint8_t*)in.data() + pos, len);
                pos += len;
                if (pos > 0 && pos + 2 * out.size() > in.size() && pos < in.size()) {
                    // Test that writing the rest at once to a copy of a hasher works.
                    Hasher(hasher).Write((const uint8_t*)in.data() + pos, in.size() - pos).Finalize(hash.data());
                    BOOST_CHECK(hash == out);
                }
            }
            hasher.Finalize(hash.data());
            BOOST_CHECK(hash == out);
        }
    } */
    fn TestVector<H: Hasher>(h: &mut H, inStr: &str, outStr: &str) {

        assert!(outStr.len() == H::OUTPUT_SIZE);
        let mut hash: [u8; CSHA512::OUTPUT_SIZE] = [0; CSHA512::OUTPUT_SIZE];



        let mut bytes = vec![];
        bytes.copy_from_slice(inStr.as_bytes());
        let len = bytes.len();
        h.Write(&mut bytes[..], len).Finalize(&mut hash[..]);
        assert!(hex::encode(&hash) == outStr.to_string());
    }

    //static void TestSHA512(const std::string &in, const std::string &hexout) { TestVector(CSHA512(), in, ParseHex(hexout));}
    fn TestSHA512(inStr: &str, hexout: &str) {
        TestVector(&mut CSHA512::new(), inStr, hexout);
    }

    #[test]
    fn test_sha512_testvectors() {

        TestSHA512("",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        TestSHA512("abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        TestSHA512("message digest",
                "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f33\
                09e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c");
        TestSHA512("secure hash algorithm",
                "7746d91f3de30c68cec0dd693120a7e8b04d8073cb699bdce1a3f64127bca7a3\
                d5db502e814bb63c063a7a5043b2df87c61133395f4ad1edca7fcf4b30c3236e");
        TestSHA512("SHA512 is considered to be safe",
                "099e6468d889e1c79092a89ae925a9499b5408e01b66cb5b0a3bd0dfa51a9964\
                6b4a3901caab1318189f74cd8cf2e941829012f2449df52067d3dd5b978456c2");
        TestSHA512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335\
                96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
        TestSHA512("For this sample, this 63-byte string will be used as input data",
                "b3de4afbc516d2478fe9b518d063bda6c8dd65fc38402dd81d1eb7364e72fb6e\
                6663cf6d2771c8f5a6da09601712fb3d2a36c6ffea3e28b0818b05b0a8660766");
        TestSHA512("This is exactly 64 bytes long, not counting the terminating byte",
                "70aefeaa0e7ac4f8fe17532d7185a289bee3b428d950c14fa8b713ca09814a38\
                7d245870e007a80ad97c369d193e41701aa07f3221d15f0e65a1ff970cedf030");
        TestSHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
                501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
        //TestSHA512(std::string(1000000, 'a'),
        //        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
        //        de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
        //TestSHA512(test1,
        //        "40cac46c147e6131c5193dd5f34e9d8bb4951395f27b08c558c65ff4ba2de594\
         //       37de8c3ef5459d76a52cedc02dc499a3c9ed9dedbfb3281afd9653b8a112fafc");

    }
}