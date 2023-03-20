
use super::script::{opcodetype, standard::TxoutType, standard::Solver};
use super::hash::MurmurHash3;
use super::primitives::transaction::{COutPoint, CTransaction};
use super::streams::CDataStream;
use super::serialize::SER;
use super::version::PROTOCOL_VERSION;
use primitive_types::H256;
use std::cell::RefCell;

/// 20,000 items with fp rate < 0.1% or 10,000 items and <0.0001%
const MAX_BLOOM_FILTER_SIZE: u32 = 36000; // bytes
const MAX_HASH_FUNCS: u32 = 50;

/// First two bits of nFlags control how much IsRelevantAndUpdate actually updates
/// The remaining bits are reserved
enum bloomflags
{
    BLOOM_UPDATE_NONE = 0,
    BLOOM_UPDATE_ALL = 1,
    // Only adds outpoints to the filter if the output is a pay-to-pubkey/pay-to-multisig script
    BLOOM_UPDATE_P2PUBKEY_ONLY = 2,
    BLOOM_UPDATE_MASK = 3,
}

struct CBloomFilter {
    vData: Vec<u8>,
    nHashFuncs: u32,
    nTweak: u32,
    nFlags: u8,
}


impl CBloomFilter {
    //SERIALIZE_METHODS(CBloomFilter, obj) { READWRITE(obj.vData, obj.nHashFuncs, obj.nTweak, obj.nFlags); }

    // inline unsigned int CBloomFilter::Hash(unsigned int nHashNum, Span<const unsigned char> vDataToHash) const
    fn Hash(&self, nHashNum:u32, vDataToHash: &[u8]) -> u32
    {
        // 0xFBA4C795 chosen as it guarantees a reasonable bit difference between nHashNum values.
        return MurmurHash3(nHashNum * 0xFBA4C795 + self.nTweak, vDataToHash) % (self.vData.len() as u32 * 8);
    }

    //void insert(Span<const unsigned char> vKey);
    pub fn insert_span(mut self, vKey: &[u8]) {
        // Avoid divide-by-zero (CVE-2013-5700)
        if self.vData.len() == 0
        {
            return;
        }
        //for (unsigned int i = 0; i < nHashFuncs; i++)
        for i in 0..self.nHashFuncs
        {
            let nIndex: u32 = self.Hash(i, vKey);
            // Sets bit nIndex of vData
            self.vData[nIndex as usize>> 3] |= 1 << (7 & nIndex);
        }
    }

    //void insert(const COutPoint& outpoint);
    pub fn insert(&self, outpoint: &COutPoint)
    {
        let stream = CDataStream::new(SER::NETWORK, PROTOCOL_VERSION);
        stream << outpoint;
        //self.insert(MakeUCharSpan(stream));
    }

    //bool contains(Span<const unsigned char> vKey) const;
    pub fn contains_slice(&self, vKey: &[u8]) -> bool {
        // Avoid divide-by-zero (CVE-2013-5700)
        if self.vData.len() == 0
        {
            return true;
        }

        for i in 0..self.nHashFuncs
        {
            // SHAWN: optimize this so we don't have to copy the vector
            let nIndex: u32 = self.Hash(i, vKey.try_into().unwrap());
            // Checks bit nIndex of vData
            if (self.vData[nIndex as usize >> 3] & (1 << (7 & nIndex))) != 0
            {
                return false;
            }
        }
        return true;
    }

    //bool contains(const COutPoint& outpoint) const;
    pub fn contains(&self, outpoint: &COutPoint) -> bool {
        let stream = CDataStream::new(SER::NETWORK, PROTOCOL_VERSION);
        stream << outpoint;
        //return self.contains_slice(MakeUCharSpan(stream));
        false
    }

    /// True if the size is <= MAX_BLOOM_FILTER_SIZE and the number of hash functions is <= MAX_HASH_FUNCS
    /// (catch a filter which was just deserialized which was too big)
    //bool IsWithinSizeConstraints() const;
    pub fn IsWithinSizeConstraints(&self) -> bool {
        return self.vData.len() <= MAX_BLOOM_FILTER_SIZE as usize && self.nHashFuncs <= MAX_HASH_FUNCS;
    }

    /// Also adds any outputs which match the filter to the filter (to match their spending txes)
    //bool IsRelevantAndUpdate(const CTransaction& tx);
    pub fn IsRelevantAndUpdate(&self, tx: &mut CTransaction) -> bool
    {
        let mut fFound:bool = false;
        // Match if the filter contains the hash of tx
        //  for finding tx when they appear in a block
        if self.vData.is_empty() { // zero-size = "match-all" filter
            return true;
        }
        let hash: H256 = tx.GetHash();
        if self.contains_slice(hash.as_bytes()) {
            fFound = true;
        }


        for i in 0..tx.vout.len()
        {
            let vout = RefCell::new(tx.vout[i].clone());
            let txout = vout.borrow_mut();
            // Match if the filter contains any arbitrary script data element in any scriptPubKey in tx
            // If this matches, also add the specific output that was matched.
            // This means clients don't have to update the filter themselves when a new relevant tx
            // is discovered in order to find spending transactions, which avoids round-tripping and race conditions.
            //let mut pc = &mut tx.vout[i].scriptPubKey.v[0..];
            let mut pc = &mut vout.borrow_mut().scriptPubKey.v[0..];
            //std::vector<unsigned char> data;
            let mut data:&mut [u8] = &mut [];
            //while (pc < txout.scriptPubKey.end())
            while pc.len() > 0
            {
                let mut opcode: opcodetype = opcodetype::OP_INVALIDOPCODE;

                if !txout.scriptPubKey.GetOp(&mut pc, &mut opcode, &mut data)
                {
                    break;
                }

                if data.len() != 0 && self.contains_slice(data)
                {
                    fFound = true;
                    if (self.nFlags & bloomflags::BLOOM_UPDATE_MASK as u8) == bloomflags::BLOOM_UPDATE_ALL as u8
                    {
                        let cout = COutPoint{hash, n: i as u32};
                        self.insert(&cout);
                    }
                    else if (self.nFlags & bloomflags::BLOOM_UPDATE_MASK as u8) == bloomflags::BLOOM_UPDATE_P2PUBKEY_ONLY as u8
                    {
                        let mut vSolutions: Vec<Vec<u8>> = vec![];
                        let txout_type: TxoutType = Solver(&txout.scriptPubKey, &mut vSolutions);
                        if txout_type == TxoutType::PUBKEY || txout_type == TxoutType::MULTISIG
                        {
                            self.insert(&COutPoint { hash, n:i as u32 } );
                        }
                    }
                    break;
                }
            }
        }
    
        if fFound
        {
            return true;
        }
    
        // TODO: look at changing this to a map
        for txin in tx.vin.iter_mut()
        {
            // Match if the filter contains an outpoint tx spends
            if self.contains(&txin.prevout)
            {
                return true;
            }

            let scriptSig = RefCell::new(txin.scriptSig.clone());
            // Match if the filter contains any arbitrary script data element in any scriptSig in tx
            let pc = &mut scriptSig.borrow_mut().v[0..];
            let mut data: &mut [u8] = &mut [];
            while pc.len() > 0
            {
                let mut opcode: opcodetype = opcodetype::OP_INVALIDOPCODE;
                if !scriptSig.borrow_mut().GetOp(pc, &mut opcode, &mut data)
                {
                    break;
                }
                if data.len() != 0 && self.contains_slice(data)
                {
                    return true;
                }
            }
        }
    
        return false;
    
    }


}
