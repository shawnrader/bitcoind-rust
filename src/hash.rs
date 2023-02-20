use sha2::{Sha256, Digest};
use primitive_types::{U256, H256, H160};
use std::cmp::min;
use std::ops::{Shl, Shr};

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

    let nblocks: usize = vDataToHash.size() / 4;

    //----------
    // body
    //const uint8_t* blocks = vDataToHash.data();

    let b = vDataToHash.iter();
    
    for i in 0 .. nblocks {
        // uint32_t k1 = ReadLE32(blocks + i*4);
        let k1: u32 =  vDataToHash[i*4 + 3] << 24 | vDataToHash[i*4 + 2] << 16 | vDataToHash[i*4 + 1] << 8 | vDataToHash[i*4];
        
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
    let tail = vDataToHash[nblocks * 4 ..];
    let k1: u32 = 0;

    if (vDataToHash.size() & 3) == 3 {
        k1 ^= tail[2] << 16;
    }
    if (vDataToHash.size() & 3) == 2 {
        k1 ^= tail[1] << 8;
    }
    if (vDataToHash.size() & 3) == 1 {
        k1 ^= tail[0];
        k1 *= c1;
        k1 = ROTL32(k1, 15);
        k1 *= c2;
        h1 ^= k1;
    }

    //----------
    // finalization
    h1 ^= vDataToHash.size();
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}


struct Hash256 {
    sha: Sha256,
}

impl Hash256 {
    const OUTPUT_SIZE:usize = Sha256::output_size();

    pub fn Hash256(self) {
        self.sha = Sha256::new();
    }

    // void Finalize(Span<unsigned char> output) {
    pub fn finalize(self, output: Vec<u8>) {
        assert!(output.size() == self.sha.output_size());
        //unsigned char buf[CSHA256::OUTPUT_SIZE];
        let mut buf: [u8; Sha256::output_size()] = [0; Sha256::output_size()];
        self.sha.finalize_into_reset(output);
    }

    //CHash256& Write(Span<const unsigned char> input) {
    pub fn write<'a>(self, input: Vec<u8>) -> &'a Hash256 {
        //self.sha.Write(input.data(), input.size());
        self.sha.update(input);
        &self
    }

    // CHash256& Reset() {
    pub fn reset<'a>(self) -> Self {
        self.sha.reset();
        &self
    }        
}

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
struct Hash160 {
    sha: Sha256,
}

impl Hash160 {
    const OUTPUT_SIZE:usize = 20;
    //void Finalize(Span<unsigned char> output) {
    pub fn finalize(self, output: Vec<u8>) {
        assert!(output.size() == self.OUTPUT_SIZE);
        let empty_array: [u32; 0] = [];
        // unsigned char buf[CSHA256::OUTPUT_SIZE];
        let mut buf: [u8; Sha256::output_size()] = [0; Sha256::output_size()];
        self.sha.finalize_into_reset(buf);
    }

    //CHash160& Write(Span<const unsigned char> input) {
    pub fn write<'a>(self, input: Vec<u8>) -> &'a Hash160 {
        self.sha.Write(input.data(), input.size());
        return &self
    }

    //CHash160& Reset() {
    pub fn reset<'a>(self) -> &'a Hash160 {
        self.sha.Reset();
        return &self;
    } 
}

/** Compute the 256-bit hash of an object. */
//template<typename T>
//inline uint256 Hash(const T& in1)
fn Hash<T>(in1:&T) -> U256
{
    let result: U256;
    let h256 = Hash256::new();
    h256.write(&in1.try_into()).finalize(result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of two objects. */
//template<typename T1, typename T2>
//inline uint256 Hash(const T1& in1, const T2& in2) {
fn HashCat<T1,T2>(in1: &T1, in2: &T2) -> U256 {
    let result: U256;
    let h256 = Hash256::new();
    // Hash256().Write(MakeUCharSpan(in1)).Write(MakeUCharSpan(in2)).Finalize(result);
    h256.write(&in1.try_into());
    h256.write(&in2.try_into());
    h256.finalize(result);
    return result;
}

/** Compute the 160-bit hash an object. */
//template<typename T1>
//inline uint160 Hash160(const T1& in1)
fn Hash160<T1>(in1: &T1) -> H160
{
    let result: H160;
    //Hash160().Write(MakeUCharSpan(in1)).Finalize(result);
    let h160 = Hash160::new();
    h160.write(&in1.try_into()).finalize(result);
    return result;
}

struct HashWriter {
    ctx: U256,
}

impl HashWriter {
    //void write(Span<const std::byte> src)
    pub fn write(self, src: Vec<u8>)
    {
        self.ctx.Write(UCharCast(src.data()), src.size());
    }

    /** Compute the double-SHA256 hash of all data written to this object.
     *
     * Invalidates this object.
     */
    //uint256 GetHash() {
    pub fn get_hash(self) -> H256 {
        let result: H256;
        self.ctx.Finalize(result.begin());
        self.ctx.Reset().Write(result.begin(), Sha256::output_size()).Finalize(result.begin());
        return result;
    }

    /** Compute the SHA256 hash of all data written to this object.
     *
     * Invalidates this object.
     */
    //uint256 GetSHA256() {
    pub fn GetSHA256(self) -> H256 {
        let result: H256;
        self.ctx.Finalize(result.begin());
        result
    }

    /**
     * Returns the first 64 bits from the resulting hash.
     */
    //inline uint64_t GetCheapHash() {
    pub fn GetCheapHash() -> u64 {
        let result = GetHash();
        return ReadLE64(result.begin());
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



