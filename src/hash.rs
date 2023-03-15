use primitive_types::{U256, H256, H160};
use std::cmp::min;
use std::ops::{Shl, Shr};
use zerocopy::AsBytes;
use crate::crypto::sha256::CSHA256;

//inline uint32_t ROTL32(uint32_t x, int8_t r)
fn ROTL32(x: u32, r: i8) -> u32
{
    return (x << r) | (x >> (32 - r));
}

//TODO check replacing with rust Murmur3Hasher_x86_32
//unsigned int MurmurHash3(unsigned int nHashSeed, Span<const unsigned char> vDataToHash)
pub fn MurmurHash3(nHashSeed: u32, vDataToHash: Vec<u8>) -> u32
{
    // The following is MurmurHash3 (x86_32), see https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
    let h1: u32 = nHashSeed;
    let c1: u32 = 0xcc9e2d51;
    let c2: u32 = 0x1b873593;

    let nblocks: usize = vDataToHash.len() / 4;

    //----------
    // body
    //const uint8_t* blocks = vDataToHash.data();

    let b = vDataToHash.iter();
    
    for i in 0 .. nblocks {
        // uint32_t k1 = ReadLE32(blocks + i*4);
        let k1: u32 =  (vDataToHash[i*4 + 3] as u32) << 24 | (vDataToHash[i*4 + 2] as u32) << 16 |
            (vDataToHash[i*4 + 1] as u32) << 8 | vDataToHash[i*4] as u32;
        
        k1 *= c1;
        k1 = ROTL32(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1 = ROTL32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    //----------
    // tail

    //const uint8_t* tail = vDataToHash.data() + nblocks * 4;
    let tail = &vDataToHash[nblocks * 4 ..];
    let k1: u32 = 0;

    if (vDataToHash.len() & 3) == 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if (vDataToHash.len() & 3) == 2 {
        k1 ^= (tail[1] as u32 )<< 8;
    }
    if (vDataToHash.len() & 3) == 1 {
        k1 ^= tail[0] as u32;
        k1 *= c1;
        k1 = ROTL32(k1, 15);
        k1 *= c2;
        h1 ^= k1;
    }

    //----------
    // finalization
    h1 ^= vDataToHash.len() as u32;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}


struct CHash256 {
    sha: CSHA256,
}

impl CHash256 {
    const OUTPUT_SIZE:usize = CSHA256::OUTPUT_SIZE;

    pub fn new() -> Self {
        Self { sha: CSHA256::new() }
    }

    // void Finalize(Span<unsigned char> output) {
    pub fn finalize(self, output: &mut [u8]) {
        assert!(output.len() == CHash256::OUTPUT_SIZE);
        let mut buf: [u8; CSHA256::OUTPUT_SIZE];
        self.sha.Finalize(&mut buf);
        self.sha.Reset().Write(&buf, CSHA256::OUTPUT_SIZE).Finalize(&mut buf);

    }

    //CHash256& Write(Span<const unsigned char> input) {
    pub fn write(self, input: &[u8]) -> Self {
        //self.sha.Write(input.data(), input.size());
        self.sha.Write(input, input.len());
        self
    }

    // CHash256& Reset() {
    pub fn reset(self) -> Self {
        self.sha.Reset();
        self
    }        
}

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
struct CHash160 {
    sha: CSHA256,
}

impl CHash160 {
    const OUTPUT_SIZE:usize = 20;
    //void Finalize(Span<unsigned char> output) {
    pub fn finalize(self, output: &mut [u8]) {
        assert!(output.len() == CHash256::OUTPUT_SIZE);
        // unsigned char buf[CSHA256::OUTPUT_SIZE];
        let mut buf: [u8; CSHA256::OUTPUT_SIZE];
        self.sha.Finalize(&mut buf);
        todo!();
        //CRIPEMD160::Write(buf, CSHA256::OUTPUT_SIZE).Finalize(output.data());
    }

    //CHash160& Write(Span<const unsigned char> input) {
    pub fn write(self, input: &[u8]) -> Self {
        self.sha.Write(input, input.len());
        self
    }

    //CHash160& Reset() {
    pub fn reset(self) -> Self {
        self.sha.Reset();
        self
    } 
}

/** Compute the 256-bit hash of an object. */
//template<typename T>
//inline uint256 Hash(const T& in1)
fn Hash<T: AsBytes>(in1:&T) -> U256
{
    let h256 = CHash256::new();
    let mut result: [u8; 64] = [0; 64];
    h256.write(&in1.as_bytes()).finalize(&mut result);
    U256::from_little_endian(&result)
}

/** Compute the 256-bit hash of the concatenation of two objects. */
//template<typename T1, typename T2>
//inline uint256 Hash(const T1& in1, const T2& in2) {
fn HashCat<T1: AsBytes,T2: AsBytes>(in1: &T1, in2: &T2) -> U256 {
    let mut result: [u8; 64] = [0; 64];
    let h256 = CHash256::new();
    // Hash256().Write(MakeUCharSpan(in1)).Write(MakeUCharSpan(in2)).Finalize(result);
    h256.write(&in1.as_bytes());
    h256.write(&in2.as_bytes());
    h256.finalize(&mut result);
    U256::from_little_endian(&result)
}

/** Compute the 160-bit hash an object. */
//template<typename T1>
//inline uint160 Hash160(const T1& in1)
fn Hash160<T1: AsBytes>(in1: &T1) -> H160
{
    let mut result: [u8; 64] = [0; 64];
    //Hash160().Write(MakeUCharSpan(in1)).Finalize(result);
    let h160 :CHash160;
    h160.write(&in1.as_bytes()).finalize(&mut result);
    H160::from_slice(&result)
}

struct HashWriter {
    ctx: CSHA256,
}

impl HashWriter {
    //void write(Span<const std::byte> src)
    pub fn write(self, src: Vec<u8>)
    {
        //self.ctx.Write(UCharCast(src.data()), src.size());
        self.ctx.update(src)
    }

    /** Compute the double-SHA256 hash of all data written to this object.
     *
     * Invalidates this object.
     */
    //uint256 GetHash() {
    pub fn GetHash(self) -> H256 {
        let result = self.ctx.finalize_reset();
        self.ctx.update(result);
        let result = self.ctx.finalize();
        return H256::from(result);

        //self.ctx.Finalize(result.begin());
        //self.ctx.Reset().Write(result.begin(), Sha256::output_size()).Finalize(result.begin());
        //return result;
    }

    /** Compute the SHA256 hash of all data written to this object.
     *
     * Invalidates this object.
     */
    //uint256 GetSHA256() {
    pub fn GetSHA256(self) -> H256 {
        H256::from(self.ctx.finalize());
    }

    /**
     * Returns the first 64 bits from the resulting hash.
     */
    //inline uint64_t GetCheapHash() {
    pub fn GetCheapHash(self) -> u64 {
        let result = self.GetHash();
        //return ReadLE64(result.begin());
        result.to_low_u64_le();
    }

    // TODO: implement
    //template <typename T>
    //HashWriter& operator<<(const T& obj)
    //{
    //    ::Serialize(*this, obj);
    //    return *this;
    //}

}

impl<T> Shl<T> for HashWriter {
    type Output = Self;

    fn shl(self, rhs:T) -> Self::Output
    {
        // TODO: figure out what to do here
        //Serialize(self.S, rhs);
        Self
    } 

}

struct CHashWriter {
    hash_writer: HashWriter,
    n_type: i32,
    n_version: i32,
    //source: S,
}

impl CHashWriter {
    pub fn GetType(self) -> i32
    {
        return self.nType;
    }

    pub fn GetVersion(self) -> i32
    {
        return self.nVersion;
    }

    //template<typename T>
    //CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
    //    ::Serialize(*this, obj);
    //    return (*this);
    //}
}

impl<T> Shl<T> for CHashWriter {
    type Output = Self;

    fn shl(self, rhs:T) -> Self::Output
    {
        // TODO: figure out what to do here
        //Serialize(self.S, rhs);
        Self
    } 

}

struct CHashVerifier<'a, T> {
    source:&'a T,
}

impl <'a, T>CHashVerifier<'a, T>  {
    //void read(Span<std::byte> dst)
    pub fn read(self, dst: Vec<u8>)
    {
        self.source.read(dst);
        self.write(dst);
    }

    //void ignore(size_t nSize)
    fn ignore (self, nSize: usize)
    {
        //std::byte data[1024];
        let mut data: [u8; 1024] = [0; 1024];
        while nSize > 0 {
            let now:usize = min(nSize, 1024);
            self.read(data, now);
            nSize -= now;
        }
    }

    //template<typenameT>
    //CHashVerifier<Source>& operator>>(T&& obj)
    // {
    //    // Unserialize from this stream
    //    ::Unserialize(*this, obj);
    //    return (*this);
    //}


}

impl<T> Shr<T> for CHashVerifier<'_, T> {
    type Output = Self;

    fn shr(self, rhs:T) -> Self::Output
    {
        // TODO: figure out what to do here
        //Unserialize(self.S, rhs);
        Self
    } 

}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2+2, 4);
    }
}



