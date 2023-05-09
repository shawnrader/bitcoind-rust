use crate::crypto::common::{WriteBE64, WriteBE32, ReadBE32};
use wrapping_arithmetic::wrappit;

pub struct CSHA256
{
    s: [u32; 8],
    buf: [u8; 64],
    bytes: u64,
}

impl CSHA256 {
    pub const OUTPUT_SIZE: usize = 32;

    pub fn new() -> Self {
        let mut s = [0 as u32; 8];
        Initialize(&mut s);
        let buf: [u8; 64] = [0; 64];
        Self {s, buf,  bytes: 0}
    }

    pub fn Write(&mut self, mut data: &[u8], len: usize) -> &mut Self
    {
        //const unsigned char* end = data + len;
        let mut end = len;
        let mut bufsize: usize = (self.bytes % 64) as usize;
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
            self.buf[bufsize..(bufsize + data.len())].copy_from_slice(data);
            //bytes += end - data;
            self.bytes += data.len() as u64;
        }
        self
    }

    pub fn Finalize(&mut self, hash: &mut [u8; CSHA256::OUTPUT_SIZE])
    {
        //static const unsigned char pad[64] = {0x80};
        let mut pad: [u8; 64] = [0x80; 64];
        //unsigned char sizedesc[8];
        let mut sizedesc: [u8; 8] = [0; 8];
        WriteBE64(&mut sizedesc, self.bytes << 3);
        self.Write(&mut pad, 1 + ((119 - (self.bytes % 64)) % 64) as usize);
        self.Write(&mut sizedesc, 8);
        WriteBE32(&mut hash[0..4], self.s[0]);
        WriteBE32(&mut hash[4..8], self.s[1]);
        WriteBE32(&mut hash[8..12], self.s[2]);
        WriteBE32(&mut hash[12..16], self.s[3]);
        WriteBE32(&mut hash[16..20], self.s[4]);
        WriteBE32(&mut hash[20..24], self.s[5]);
        WriteBE32(&mut hash[24..28], self.s[6]);
        WriteBE32(&mut hash[28..32], self.s[7]);
    }

    pub fn Reset(&mut self) -> &mut Self
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
#[wrappit]
fn Round(a: u32, b: u32, c: u32, d: &mut u32, e: u32, f: u32, g: u32, h: &mut u32, k: u32)
{
    let t1: u32 = h + Sigma1(e) + Ch(e, f, g) + k;
    let t2: u32 = Sigma0(a) + Maj(a, b, c);
    *d = d + t1;
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
#[wrappit]
fn Transform(s: &mut [u32], mut chunk: &[u8], mut blocks: usize)
{
    while blocks > 0 {
        //uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
        //uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;
        let (mut w0, mut w1, mut w2, mut w3, mut w4, mut w5, mut w6, mut w7, mut w8, mut w9, mut w10, mut w11, mut w12, mut w13, mut w14, mut w15) : (u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);

        w0 = ReadBE32(&chunk[0..]);
        Round(a, b, c, &mut d, e, f, g, &mut h, 0x428a2f98_u32 + w0);
        w1 = ReadBE32(&chunk[4..]);
        Round(h, a, b, &mut c, d, e, f, &mut g, 0x71374491_u32 + w1);
        w2 = ReadBE32(&chunk[8..]);
        Round(g, h, a, &mut b, c, d, e, &mut f, 0xb5c0fbcf_u32 + w2);
        w3 = ReadBE32(&chunk[12..]);
        Round(f, g, h, &mut a, b, c, d, &mut e, 0xe9b5dba5_u32 + w3);
        w4 = ReadBE32(&chunk[16..]);
        Round(e, f, g, &mut h, a, b, c, &mut d, 0x3956c25b_u32 + w4);
        w5 = ReadBE32(&chunk[20..]);
        Round(d, e, f, &mut g, h, a, b, &mut c, 0x59f111f1_u32 + w5);
        w6 = ReadBE32(&chunk[24..]);
        Round(c, d, e, &mut f, g, h, a, &mut b, 0x923f82a4_u32 + w6);
        w7 = ReadBE32(&chunk[28..]);
        Round(b, c, d, &mut e, f, g, h, &mut a, 0xab1c5ed5_u32 + w7);
        w8 = ReadBE32(&chunk[32..]);
        Round(a, b, c, &mut d, e, f, g, &mut h, 0xd807aa98_u32 + w8);
        w9 = ReadBE32(&chunk[36..]);
        Round(h, a, b, &mut c, d, e, f, &mut g, 0x12835b01_u32 + w9);
        w10 = ReadBE32(&chunk[40..]);
        Round(g, h, a, &mut b, c, d, e, &mut f, 0x243185be_u32 + w10);
        w11 = ReadBE32(&chunk[44..]);
        Round(f, g, h, &mut a, b, c, d, &mut e, 0x550c7dc3_u32 + w11);
        w12 = ReadBE32(&chunk[48..]);
        Round(e, f, g, &mut h, a, b, c, &mut d, 0x72be5d74_u32 + w12);
        w13 = ReadBE32(&chunk[52..]);
        Round(d, e, f, &mut g, h, a, b, &mut c, 0x80deb1fe_u32 + w13);
        w14 = ReadBE32(&chunk[56..]);
        Round(c, d, e, &mut f, g, h, a, &mut b, 0x9bdc06a7_u32 + w14);
        w15 = ReadBE32(&chunk[60..]);
        Round(b, c, d, &mut e, f, g, h, &mut a, 0xc19bf174_u32 + w15);

        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, &mut d, e, f, g, &mut h, 0xe49b69c1_u32 + w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, &mut c, d, e, f, &mut g, 0xefbe4786_u32 + w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, &mut b, c, d, e, &mut f, 0x0fc19dc6_u32 + w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, &mut a, b, c, d, &mut e, 0x240ca1cc_u32 + w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, &mut h, a, b, c, &mut d, 0x2de92c6f_u32 + w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, &mut g, h, a, b, &mut c, 0x4a7484aa_u32 + w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, &mut f, g, h, a, &mut b, 0x5cb0a9dc_u32 + w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, &mut e, f, g, h, &mut a, 0x76f988da_u32 + w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, &mut d, e, f, g, &mut h, 0x983e5152_u32 + w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, &mut c, d, e, f, &mut g, 0xa831c66d_u32 + w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, &mut b, c, d, e, &mut f, 0xb00327c8_u32 + w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, &mut a, b, c, d, &mut e, 0xbf597fc7_u32 + w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, &mut h, a, b, c, &mut d, 0xc6e00bf3_u32 + w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, &mut g, h, a, b, &mut c, 0xd5a79147_u32 + w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, &mut f, g, h, a, &mut b, 0x06ca6351_u32 + w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, &mut e, f, g, h, &mut a, 0x14292967_u32 + w15);
        
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, &mut d, e, f, g, &mut h, 0x27b70a85_u32 + w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, &mut c, d, e, f, &mut g, 0x2e1b2138_u32 + w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, &mut b, c, d, e, &mut f, 0x4d2c6dfc_u32 + w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, &mut a, b, c, d, &mut e, 0x53380d13_u32 + w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, &mut h, a, b, c, &mut d, 0x650a7354_u32 + w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, &mut g, h, a, b, &mut c, 0x766a0abb_u32 + w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, &mut f, g, h, a, &mut b, 0x81c2c92e_u32 + w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, &mut e, f, g, h, &mut a, 0x92722c85_u32 + w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, &mut d, e, f, g, &mut h, 0xa2bfe8a1_u32 + w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, &mut c, d, e, f, &mut g, 0xa81a664b_u32 + w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, &mut b, c, d, e, &mut f, 0xc24b8b70_u32 + w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, &mut a, b, c, d, &mut e, 0xc76c51a3_u32 + w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, &mut h, a, b, c, &mut d, 0xd192e819_u32 + w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, &mut g, h, a, b, &mut c, 0xd6990624_u32 + w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, &mut f, g, h, a, &mut b, 0xf40e3585_u32 + w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, &mut e, f, g, h, &mut a, 0x106aa070_u32 + w15);

        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, &mut d, e, f, g, &mut h, 0x19a4c116_u32 + w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, &mut c, d, e, f, &mut g, 0x1e376c08_u32 + w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, &mut b, c, d, e, &mut f, 0x2748774c_u32 + w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, &mut a, b, c, d, &mut e, 0x34b0bcb5_u32 + w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, &mut h, a, b, c, &mut d, 0x391c0cb3_u32 + w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, &mut g, h, a, b, &mut c, 0x4ed8aa4a_u32 + w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, &mut f, g, h, a, &mut b, 0x5b9cca4f_u32 + w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, &mut e, f, g, h, &mut a, 0x682e6ff3_u32 + w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, &mut d, e, f, g, &mut h, 0x748f82ee_u32 + w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, &mut c, d, e, f, &mut g, 0x78a5636f_u32 + w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, &mut b, c, d, e, &mut f, 0x84c87814_u32 + w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, &mut a, b, c, d, &mut e, 0x8cc70208_u32 + w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, &mut h, a, b, c, &mut d, 0x90befffa_u32 + w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, &mut g, h, a, b, &mut c, 0xa4506ceb_u32 + w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, &mut f, g, h, a, &mut b, 0xbef9a3f7_u32 + w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, &mut e, f, g, h, &mut a, 0xc67178f2_u32 + w15);

        s[0] += a;
        s[1] += b;
        s[2] += c;
        s[3] += d;
        s[4] += e;
        s[5] += f;
        s[6] += g;
        s[7] += h;
        //chunk += 64;
        chunk = &chunk[64..];

        blocks -= 1;
    }
}

mod tests {

    fn TestSHA256(inStr: &str, hexout: &str) {
        todo!();
        //TestVector(&CSHA256::new(), inStr, hexout);
    }

    #[test]
    fn test_sha256_testvectors() {
        TestSHA256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        TestSHA256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        TestSHA256("message digest",
                "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
        TestSHA256("secure hash algorithm",
                "f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d");
        TestSHA256("SHA256 is considered to be safe",
                "6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630");
        TestSHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        TestSHA256("For this sample, this 63-byte string will be used as input data",
                "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342");
        TestSHA256("This is exactly 64 bytes long, not counting the terminating byte",
                "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8");
        TestSHA256("As Bitcoin relies on 80 byte header hashes, we want to have an example for that.",
                "7406e8de7d6e4fffc573daef05aefb8806e7790f55eab5576f31349743cca743");
        /* TestSHA256(std::string(1000000, 'a'),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
        TestSHA256(test1, "a316d55510b49662420f49d145d42fb83f31ef8dc016aa4e32df049991a91e26");
        */
    }
}