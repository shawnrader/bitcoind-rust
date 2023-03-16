use crate::crypto::common::{WriteBE64, WriteBE32, ReadBE32};

pub struct CSHA256
{
    s: [u32; 8],
    buf: [u8; 64],
    bytes: u64,
}

impl CSHA256 {
    pub const OUTPUT_SIZE: usize = 32;

    pub fn new() -> Self {
        let s: [u32; 8];
        Initialize(&mut s);
        let buf: [u8; 64] = [0; 64];
        Self {s, buf,  bytes: 0}
    }

    pub fn Write(self, mut data: &[u8], len: usize) -> Self
    {
        //const unsigned char* end = data + len;
        let bufsize: usize = (self.bytes % 64) as usize;
        //if (bufsize && bufsize + len >= 64) {
        if bufsize > 0 && bufsize + len >= 64 {
            // Fill the buffer, and process it.
            //memcpy(buf + bufsize, data, 64 - bufsize);
            self.buf[bufsize..].copy_from_slice(&data[0..(64 - bufsize)]);
            // bytes += 64 - bufsize;
            self.bytes += 64 - bufsize as u64;
            //data += 64 - bufsize;
            data = &data[(64-bufsize)..];
            Transform(&mut self.s, &mut self.buf, 1);
            bufsize = 0;
        }
        //if (end - data >= 64) {
        if data.len() >= 64
        {
            //size_t blocks = (end - data) / 64;
            let blocks: usize = data.len() / 64;
            Transform(&mut self.s, &mut data, blocks);
            //data += 64 * blocks;
            data = &data[(64 * blocks)..];
            self.bytes += 64 * blocks as u64;
        }
        //if (end > data) {
        if data.len() > 0
        {
            // Fill the buffer with what remains.
            //memcpy(buf + bufsize, data, end - data);
            self.buf[bufsize..].copy_from_slice(data);
            //bytes += end - data;
            self.bytes += data.len() as u64;
        }
        self
    }

    pub fn Finalize(self, hash: &mut [u8; CSHA256::OUTPUT_SIZE])
    {
        //static const unsigned char pad[64] = {0x80};
        let pad: [u8; 64] = [0x80; 64];
        //unsigned char sizedesc[8];
        let mut sizedesc: [u8; 8];
        WriteBE64(&mut sizedesc, self.bytes << 3);
        self.Write(&pad, 1 + ((119 - (self.bytes % 64)) % 64) as usize);
        self.Write(&sizedesc, 8);
        WriteBE32(&mut hash[0..4], self.s[0]);
        WriteBE32(&mut hash[4..8], self.s[1]);
        WriteBE32(&mut hash[8..12], self.s[2]);
        WriteBE32(&mut hash[12..16], self.s[3]);
        WriteBE32(&mut hash[16..20], self.s[4]);
        WriteBE32(&mut hash[20..24], self.s[5]);
        WriteBE32(&mut hash[24..28], self.s[6]);
        WriteBE32(&mut hash[28..32], self.s[7]);
    }

    pub fn Reset(self) -> Self
    {
        self.bytes = 0;
        Initialize(&mut self.s);
        self
    }    

}

//uint32_t inline Ch(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }
fn Ch(x: u32, y: u32, z: u32) -> u32 { z ^ (x & (y ^ z)) }

//uint32_t inline Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (z & (x | y)); }
fn Maj(x: u32, y: u32, z: u32) -> u32 { (x & y) | (z & (x | y)) }

//uint32_t inline Sigma0(uint32_t x) { return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10); }
fn Sigma0(x: u32) -> u32 { (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10) }

//uint32_t inline Sigma1(uint32_t x) { return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7); }
fn Sigma1(x: u32) -> u32 { (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7) }

//uint32_t inline sigma0(uint32_t x) { return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3); }
fn sigma0(x: u32) -> u32 { (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3) }

//uint32_t inline sigma1(uint32_t x) { return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10); }
fn sigma1(x: u32) -> u32 { (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10) }

/** One round of SHA-256. */
//void inline Round(uint32_t a, uint32_t b, uint32_t c, uint32_t& d, uint32_t e, uint32_t f, uint32_t g, uint32_t& h, uint32_t k)
#[inline]
fn Round(a: u32, b: u32, c: u32, d: &u32, e: u32, f: u32, g: u32, h: &u32, k: u32)
{
    let t1: u32 = h + Sigma1(e) + Ch(e, f, g) + k;
    let t2: u32 = Sigma0(a) + Maj(a, b, c);
    *d += t1;
    *h = t1 + t2;
}

/** Initialize SHA-256 state. */
fn Initialize(s: &mut [u32])
{
    s[0] = 0x6a09e667;
    s[1] = 0xbb67ae85;
    s[2] = 0x3c6ef372;
    s[3] = 0xa54ff53a;
    s[4] = 0x510e527f;
    s[5] = 0x9b05688c;
    s[6] = 0x1f83d9ab;
    s[7] = 0x5be0cd19;
}

/** Perform a number of SHA-256 transformations, processing 64-byte chunks. */
//void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks)
fn Transform(s: &mut [u32], chunk: &mut [u8], mut blocks: usize)
{
    while blocks > 0 {
        //uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
        let (a, b, c, d, e, f, g, h) = (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
        //uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;
        let (mut w0, mut w1, mut w2, mut w3, mut w4, mut w5, mut w6, mut w7, mut w8, mut w9, mut w10, mut w11, mut w12, mut w13, mut w14, mut w15) : (u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);

        w0 = ReadBE32(&chunk[0..]);
        Round(a, b, c, &d, e, f, g, &h, 0x428a2f98 + w0);
        w1 = ReadBE32(&chunk[4..]);
        Round(h, a, b, &c, d, e, f, &g, 0x71374491 + w1);
        w2 = ReadBE32(&chunk[8..]);
        Round(g, h, a, &b, c, d, e, &f, 0xb5c0fbcf + w2);
        w3 = ReadBE32(&chunk[12..]);
        Round(f, g, h, &a, b, c, d, &e, 0xe9b5dba5 + w3);
        w4 = ReadBE32(&chunk[16..]);
        Round(e, f, g, &h, a, b, c, &d, 0x3956c25b + w4);
        w5 = ReadBE32(&chunk[20..]);
        Round(d, e, f, &g, h, a, b, &c, 0x59f111f1 + w5);
        w6 = ReadBE32(&chunk[24..]);
        Round(c, d, e, &f, g, h, a, &b, 0x923f82a4 + w6);
        w7 = ReadBE32(&chunk[28..]);
        Round(b, c, d, &e, f, g, h, &a, 0xab1c5ed5 + w7);
        w8 = ReadBE32(&chunk[32..]);
        Round(a, b, c, &d, e, f, g, &h, 0xd807aa98 + w8);
        w9 = ReadBE32(&chunk[36..]);
        Round(h, a, b, &c, d, e, f, &g, 0x12835b01 + w9);
        w10 = ReadBE32(&chunk[40..]);
        Round(g, h, a, &b, c, d, e, &f, 0x243185be + w10);
        w11 = ReadBE32(&chunk[44..]);
        Round(f, g, h, &a, b, c, d, &e, 0x550c7dc3 + w11);
        w12 = ReadBE32(&chunk[48..]);
        Round(e, f, g, &h, a, b, c, &d, 0x72be5d74 + w12);
        w13 = ReadBE32(&chunk[52..]);
        Round(d, e, f, &g, h, a, b, &c, 0x80deb1fe + w13);
        w14 = ReadBE32(&chunk[56..]);
        Round(c, d, e, &f, g, h, a, &b, 0x9bdc06a7 + w14);
        w15 = ReadBE32(&chunk[60..]);
        Round(b, c, d, &e, f, g, h, &a, 0xc19bf174 + w15);

        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, &d, e, f, g, &h, 0xe49b69c1 + w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, &c, d, e, f, &g, 0xefbe4786 + w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, &b, c, d, e, &f, 0x0fc19dc6 + w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, &a, b, c, d, &e, 0x240ca1cc + w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, &h, a, b, c, &d, 0x2de92c6f + w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, &g, h, a, b, &c, 0x4a7484aa + w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, &f, g, h, a, &b, 0x5cb0a9dc + w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, &e, f, g, h, &a, 0x76f988da + w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, &d, e, f, g, &h, 0x983e5152 + w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, &c, d, e, f, &g, 0xa831c66d + w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, &b, c, d, e, &f, 0xb00327c8 + w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, &a, b, c, d, &e, 0xbf597fc7 + w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, &h, a, b, c, &d, 0xc6e00bf3 + w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, &g, h, a, b, &c, 0xd5a79147 + w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, &f, g, h, a, &b, 0x06ca6351 + w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, &e, f, g, h, &a, 0x14292967 + w15);
        
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, &d, e, f, g, &h, 0x27b70a85 + w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, &c, d, e, f, &g, 0x2e1b2138 + w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, &b, c, d, e, &f, 0x4d2c6dfc + w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, &a, b, c, d, &e, 0x53380d13 + w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, &h, a, b, c, &d, 0x650a7354 + w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, &g, h, a, b, &c, 0x766a0abb + w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, &f, g, h, a, &b, 0x81c2c92e + w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, &e, f, g, h, &a, 0x92722c85 + w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, &d, e, f, g, &h, 0xa2bfe8a1 + w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, &c, d, e, f, &g, 0xa81a664b + w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, &b, c, d, e, &f, 0xc24b8b70 + w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, &a, b, c, d, &e, 0xc76c51a3 + w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, &h, a, b, c, &d, 0xd192e819 + w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, &g, h, a, b, &c, 0xd6990624 + w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, &f, g, h, a, &b, 0xf40e3585 + w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, &e, f, g, h, &a, 0x106aa070 + w15);

        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, &d, e, f, g, &h, 0x19a4c116 + w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, &c, d, e, f, &g, 0x1e376c08 + w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, &b, c, d, e, &f, 0x2748774c + w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, &a, b, c, d, &e, 0x34b0bcb5 + w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, &h, a, b, c, &d, 0x391c0cb3 + w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, &g, h, a, b, &c, 0x4ed8aa4a + w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, &f, g, h, a, &b, 0x5b9cca4f + w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, &e, f, g, h, &a, 0x682e6ff3 + w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, &d, e, f, g, &h, 0x748f82ee + w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, &c, d, e, f, &g, 0x78a5636f + w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, &b, c, d, e, &f, 0x84c87814 + w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, &a, b, c, d, &e, 0x8cc70208 + w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, &h, a, b, c, &d, 0x90befffa + w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, &g, h, a, b, &c, 0xa4506ceb + w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, &f, g, h, a, &b, 0xbef9a3f7 + w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, &e, f, g, h, &a, 0xc67178f2 + w15);

        s[0] += a;
        s[1] += b;
        s[2] += c;
        s[3] += d;
        s[4] += e;
        s[5] += f;
        s[6] += g;
        s[7] += h;
        //chunk += 64;
        chunk = &mut chunk[64..];

        blocks -= 1;
    }
}