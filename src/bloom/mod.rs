
mod Bloom {

enum bloomflags
{
    BLOOM_UPDATE_NONE = 0,
    BLOOM_UPDATE_ALL = 1,
    // Only adds outpoints to the filter if the output is a pay-to-pubkey/pay-to-multisig script
    BLOOM_UPDATE_P2PUBKEY_ONLY = 2,
    BLOOM_UPDATE_MASK = 3,
}

struct BloomFilter {
    vData: Vec<u8>,
    nHashFuncs: u32,
    nTweak: u32,
    nFlags: u8,
}


impl BloomFilter {
    //SERIALIZE_METHODS(CBloomFilter, obj) { READWRITE(obj.vData, obj.nHashFuncs, obj.nTweak, obj.nFlags); }

    // inline unsigned int CBloomFilter::Hash(unsigned int nHashNum, Span<const unsigned char> vDataToHash) const
    fn Hash(nHashNum:u32, vDataToHash: Span<u8>) -> i32
    {
        // 0xFBA4C795 chosen as it guarantees a reasonable bit difference between nHashNum values.
        return MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash) % (vData.size() * 8);
    }

    //void insert(Span<const unsigned char> vKey);
    pub fn insert(self, vKey: u8) {
        if (self.vData.empty()) {// Avoid divide-by-zero (CVE-2013-5700)
            return;
        }
        //for (unsigned int i = 0; i < nHashFuncs; i++)
        for i in (0..self.nHashFuncs)
        {
            let nIndex: u32 = Hash(i, vKey);
            // Sets bit nIndex of vData
            vData[self.nIndex >> 3] |= (1 << (7 & self.nIndex));
        }
    }

    //void insert(const COutPoint& outpoint);
    pub fn insert(outpoint: &COutPoint);

    //bool contains(Span<const unsigned char> vKey) const;
    pub fn contains(vKey: Span<u8>) -> bool;

    //bool contains(const COutPoint& outpoint) const;
    pub fn contains(outpoint: OutPoint) -> bool;

    /// True if the size is <= MAX_BLOOM_FILTER_SIZE and the number of hash functions is <= MAX_HASH_FUNCS
    /// (catch a filter which was just deserialized which was too big)
    //bool IsWithinSizeConstraints() const;
    pub fn is_in_size_contraints(self) -> bool;

    /// Also adds any outputs which match the filter to the filter (to match their spending txes)
    //bool IsRelevantAndUpdate(const CTransaction& tx);
    pub fn is_relevant_and_update(tx: &CTransaction) -> bool;


}

}