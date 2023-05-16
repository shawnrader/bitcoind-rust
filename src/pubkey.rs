// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
use primitive_types::U256;
use crate::script::CScript;

//const unsigned int BIP32_EXTKEY_SIZE = 74;
pub const BIP32_EXTKEY_SIZE: u32 = 74;
//const unsigned int BIP32_EXTKEY_WITH_VERSION_SIZE = 78;
pub const BIP32_EXTKEY_WITH_VERSION_SIZE: u32 = 78;


/** A reference to a CKey: the Hash160 of its serialized public key */
//class CKeyID : public uint160
//{
//public:
//    CKeyID() : uint160() {}
//    explicit CKeyID(const uint160& in) : uint160(in) {}
//};

//typedef uint256 ChainCode;
type ChainCode = U256;



/** An encapsulated public key. */
pub struct CPubKey {
    pub vch: [u8; 65],
}

impl CPubKey {
    pub const SIZE: usize = 65;
    pub const COMPRESSED_SIZE: usize = 33;
    pub const SIGNATURE_SIZE: usize = 72;
    pub const COMPACT_SIGNATURE_SIZE: usize = 65;

    /// Compute the length of a pubkey with a given first byte.
    // unsigned int static GetLen(unsigned char chHeader)
    fn GetLen(chHeader: u8) -> usize
    {
        if chHeader == 2 || chHeader == 3
        {
            return Self::COMPRESSED_SIZE;
        }
        if chHeader == 4 || chHeader == 6 || chHeader == 7
        {
            return Self::SIZE;
        }
        0
    }


    //bool static ValidSize(const std::vector<unsigned char> &vch) {
    pub fn ValidSize(vch: &Vec<u8>) -> bool
    {
        vch.len() > 0 && Self::GetLen(vch[0]) == vch.len()
    }

    /// Simple read-only vector-like interface to the pubkey data.
    pub fn size(&self) -> usize { Self::GetLen(self.vch[0]) }
    pub fn data(&self) -> &[u8] { &self.vch[0..] }

}

pub struct XOnlyPubKey {
    m_keydata: U256,
}

impl XOnlyPubKey {
    pub fn cs(&self) -> CScript {
        let mut buf = [0u8; 32];
        self.m_keydata.to_little_endian(&mut buf);
        CScript::new(buf.to_vec())
    }
}