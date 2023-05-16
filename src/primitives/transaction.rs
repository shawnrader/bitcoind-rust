// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use primitive_types::H256;
use super::super::consensus::amount::CAmount;
use crate::script::CScript;

/** An outpoint - a combination of a transaction hash and an index n into its vout */
pub struct COutPoint
{
    hash: H256,
    n: u32,
}

impl COutPoint
{
    const NULL_INDEX: u32 = u32::MAX;

    // COutPoint(const uint256& hashIn, uint32_t nIn): hash(hashIn), n(nIn) { }
    pub fn new(hashIn: H256, nIn: u32) -> Self
    {
        Self { hash: hashIn, n: nIn}
    }

    // TODO: SERIALIZE_METHODS(COutPoint, obj) { READWRITE(obj.hash, obj.n); }

    // void SetNull() { hash.SetNull(); n = NULL_INDEX; }
    pub fn SetNull(&mut self)
    {
        self.hash = H256::zero();
        self.n = COutPoint::NULL_INDEX;
        
    }

    // bool IsNull() const { return (hash.IsNull() && n == NULL_INDEX); }
    pub fn IsNull(self) -> bool {
        self.hash.is_zero() && self.n == COutPoint::NULL_INDEX
    }
}

pub struct CTxIn {
    pub prevout: COutPoint,
    pub scriptSig: CScript,
    pub nSequence: u32,
    //pub scriptWitness: CScriptWitness,
}

impl CTxIn {
    /**
     * Setting nSequence to this value for every input in a transaction
     * disables nLockTime/IsFinalTx().
     * It fails OP_CHECKLOCKTIMEVERIFY/CheckLockTime() for any input that has
     * it set (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    pub const SEQUENCE_FINAL: u32 = 0xffffffff;
    /**
     * This is the maximum sequence number that enables both nLockTime and
     * OP_CHECKLOCKTIMEVERIFY (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    pub const MAX_SEQUENCE_NONFINAL: u32 = CTxIn::SEQUENCE_FINAL - 1;

    // Below flags apply in the context of BIP 68. BIP 68 requires the tx
    // version to be set to 2, or higher.
    /**
     * If this flag is set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time.
     * It skips SequenceLocks() for any input that has it set (BIP 68).
     * It fails OP_CHECKSEQUENCEVERIFY/CheckSequence() for any input that has
     * it set (BIP 112).
     */
    pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = (1 << 31);

    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = (1 << 22);

    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;

    /**
     * In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    pub const SEQUENCE_LOCKTIME_GRANULARITY:i32 = 9;


}

#[derive(Clone)]
pub struct CTxOut {
    nValue: CAmount,
    pub scriptPubKey: CScript,
}

impl CTxOut {
    pub fn SetNull(mut self)
    {
        self.nValue = -1;
        self.scriptPubKey.clear();
    }
}

pub struct CTransaction {
    pub vin: Vec<CTxIn>,
    pub vout: Vec<CTxOut>,
    pub nVersion: i32,
    pub nLockTime: u32,
    hash: H256
}

impl CTransaction {
    const CURRENT_VERSION: i32 = 2;

    pub fn GetHash(&self) -> H256
    {
        self.hash.clone()
    }
}