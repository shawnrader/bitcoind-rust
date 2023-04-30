// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::script::{CScript, CScriptNum, OP_FALSE};
use crate::script::interpreter::*;
use crate::script::opcodetype::{self, *};
use crate::pubkey::{self, XOnlyPubKey};
use primitive_types::{H160, H256};
use std::cell::RefCell;

#[derive(PartialEq)]
pub enum TxoutType {
    NONSTANDARD,
    // 'standard' transaction types:
    PUBKEY,
    PUBKEYHASH,
    SCRIPTHASH,
    MULTISIG,
    /// unspendable OP_RETURN script that carries data
    NULL_DATA,
    WITNESS_V0_SCRIPTHASH,
    WITNESS_V0_KEYHASH,
    WITNESS_V1_TAPROOT,
    /// Only for Witness versions not already defined above
    WITNESS_UNKNOWN,
}


/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * PKHash: TxoutType::PUBKEYHASH destination (P2PKH)
 *  * ScriptHash: TxoutType::SCRIPTHASH destination (P2SH)
 *  * WitnessV0ScriptHash: TxoutType::WITNESS_V0_SCRIPTHASH destination (P2WSH)
 *  * WitnessV0KeyHash: TxoutType::WITNESS_V0_KEYHASH destination (P2WPKH)
 *  * WitnessV1Taproot: TxoutType::WITNESS_V1_TAPROOT destination (P2TR)
 *  * WitnessUnknown: TxoutType::WITNESS_UNKNOWN destination (P2W???)
 *  A CTxDestination is the internal data type encoded in a bitcoin address
 */
//using CTxDestination = std::variant<CNoDestination, PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash, WitnessV1Taproot, WitnessUnknown>;
pub enum CTxDestination {
    CNoDestination,
    PKHash(H160),
    ScriptHash(H160),
    WitnessV0ScriptHash(H256),
    WitnessV0KeyHash(H160),
    WitnessV1Taproot(XOnlyPubKey),
    WitnessUnknown,
}

/*
struct ScriptHash : public BaseHash<uint160>
{
    ScriptHash() : BaseHash() {}
    // These don't do what you'd expect.
    // Use ScriptHash(GetScriptForDestination(...)) instead.
    explicit ScriptHash(const WitnessV0KeyHash& hash) = delete;
    explicit ScriptHash(const PKHash& hash) = delete;

    explicit ScriptHash(const uint160& hash) : BaseHash(hash) {}
    explicit ScriptHash(const CScript& script);
    explicit ScriptHash(const CScriptID& script);
};

ScriptHash::ScriptHash(const CScript& in) : BaseHash(Hash160(in)) {}
ScriptHash::ScriptHash(const CScriptID& in) : BaseHash(static_cast<uint160>(in)) {}

*/

/*
namespace {
    class CScriptVisitor
    {
    public:
        CScript operator()(const CNoDestination& dest) const
        {
            return CScript();
        }
    
        CScript operator()(const PKHash& keyID) const
        {
            return CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        }
    
        CScript operator()(const ScriptHash& scriptID) const
        {
            return CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        }
    
        CScript operator()(const WitnessV0KeyHash& id) const
        {
            return CScript() << OP_0 << ToByteVector(id);
        }
    
        CScript operator()(const WitnessV0ScriptHash& id) const
        {
            return CScript() << OP_0 << ToByteVector(id);
        }
    
        CScript operator()(const WitnessV1Taproot& tap) const
        {
            return CScript() << OP_1 << ToByteVector(tap);
        }
    
        CScript operator()(const WitnessUnknown& id) const
        {
            return CScript() << CScript::EncodeOP_N(id.version) << std::vector<unsigned char>(id.program, id.program + id.length);
        }
    };
    } // namespace
    
    CScript GetScriptForDestination(const CTxDestination& dest)
    {
        return std::visit(CScriptVisitor(), dest);
    }
*/
pub fn GetScriptForDestination(dest: &CTxDestination) -> CScript {
    let mut script = CScript::new(Vec::new());
    match dest {
        CTxDestination::CNoDestination => script,
        CTxDestination::PKHash(keyID) => OP_DUP.cs() << OP_HASH160.cs() << CScript::push_data(keyID.as_bytes()) << OP_EQUALVERIFY.cs() << OP_CHECKSIG.cs(),
        CTxDestination::ScriptHash(scriptID) => OP_HASH160.cs() << CScript::push_data(scriptID.as_bytes()) << OP_EQUAL.cs(),
        CTxDestination::WitnessV0KeyHash(id) => OP_0.cs() << CScript::push_data(id.as_bytes()),
        CTxDestination::WitnessV0ScriptHash(id) => OP_0.cs() << CScript::push_data(id.as_bytes()),
        CTxDestination::WitnessV1Taproot(tap) => OP_1.cs() << tap.cs(),
        CTxDestination::WitnessUnknown => script,
    }
}


fn IsPushdataOp(opcode: opcodetype) -> bool
{
    opcode > OP_FALSE && opcode <= opcodetype::OP_PUSHDATA4
}

//typedef std::vector<unsigned char> valtype;
type valtype = Vec<u8>;

//static bool MatchPayToPubkey(const CScript& script, valtype& pubkey)
fn MatchPayToPubkey(script: &CScript, pubkey: &mut valtype) -> bool
{
    if script.v.len() == pubkey::SIZE + 2 && script.v[0] == pubkey::SIZE as u8 && *script.v.last().unwrap() == opcodetype::OP_CHECKSIG as u8
    {
        //pubkey = valtype(script.begin() + 1, script.begin() + pubkey::SIZE + 1);
        pubkey.copy_from_slice(&script.v[0..pubkey::SIZE + 1]);
        return pubkey::ValidSize(pubkey);
    }
    if script.v.len() == pubkey::COMPRESSED_SIZE + 2 && script.v[0] == pubkey::COMPRESSED_SIZE as u8 && *script.v.last().unwrap() == opcodetype::OP_CHECKSIG as u8
    {
        //pubkey = valtype(script.begin() + 1, script.begin() + pubkey::COMPRESSED_SIZE + 1);
        pubkey.copy_from_slice(&script.v[1..pubkey::COMPRESSED_SIZE + 1]);
        return pubkey::ValidSize(pubkey);
    }
    return false;
}

fn MatchPayToPubkeyHash(script: &CScript, pubkeyhash: &mut valtype) -> bool
{
    if script.v.len() == 25 && script.v[0] == opcodetype::OP_DUP as u8 && script.v[1] == opcodetype::OP_HASH160 as u8 &&
        script.v[2] == 20 && script.v[23] == opcodetype::OP_EQUALVERIFY as u8 && script.v[24] == opcodetype::OP_CHECKSIG as u8 {
        *pubkeyhash = script.v[3..23].to_vec();
        return true;
    }
    return false;
}

/** Test for "small positive integer" script opcodes - OP_1 through OP_16. */
fn IsSmallInteger(opcode: opcodetype) -> bool
{
    return opcode >= opcodetype::OP_1 && opcode <= opcodetype::OP_16;
}

/** Retrieve a minimally-encoded number in range [min,max] from an (opcode, data) pair,
 *  whether it's OP_n or through a push. */
//static std::optional<int> GetScriptNumber(opcodetype opcode, valtype data, int min, int max)
fn GetScriptNumber(opcode: &opcodetype, data: &valtype, min: i32, max: i32) -> Option<i32>
{
    let count: i32;
    if IsSmallInteger(opcode.clone()) {
        count = CScript::DecodeOP_N(opcode.clone());
    } else if IsPushdataOp(opcode.clone()) {
        if !super::CheckMinimalPush(&data[0..], opcode.clone()) {
            return None;
        }
        let cnum = CScriptNum::new(&data, /* fRequireMinimal = */ true, None).unwrap();
        count = cnum.getint();

    } else {
        return None;
    }
    if count < min || count > max { return None; };

    return Some(count);
}

fn MatchMultisig(script: &mut CScript, required_sigs: &mut i32, pubkeys: &mut Vec<valtype>) -> bool
{
    let mut opcode = opcodetype::OP_INVALIDOPCODE;
    let mut data: valtype = vec![];
    //let mut it = script.v.as_mut_slice();
    let v = RefCell::new(script.v.clone());

    if script.v.len() < 1
    {
        return false;
    }

    let last = script.v.last();
    if last == None || *last.unwrap() != opcodetype::OP_CHECKMULTISIG as u8 {
        return false;
    }

    let binding = v.borrow_mut();
    let mut it = binding.as_slice();
    let mut out: &[u8] = &[];
    if !CScript::GetOp(&mut it, &mut opcode, &mut out) {
        return false;
    }
    data.copy_from_slice(out);

    let req_sigs = GetScriptNumber(&opcode, &data, 1, super::MAX_PUBKEYS_PER_MULTISIG);
    if req_sigs == None {
        return false;
    }
    *required_sigs = req_sigs.unwrap();
    while CScript::GetOp(&mut it, &mut opcode, &mut &data[0..]) && pubkey::ValidSize(&data)
    {
        pubkeys.push(data.clone());
    }
    let num_keys = GetScriptNumber(&opcode, &data, *required_sigs, super::MAX_PUBKEYS_PER_MULTISIG);
    if num_keys == None
    {
        return false;
    }
    if pubkeys.len() != num_keys.unwrap() as usize {
        return false;
    }

    return it.len() == 0;
}

//TxoutType Solver(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& vSolutionsRet)
pub fn Solver(scriptPubKey: &mut CScript, vSolutionsRet: &mut Vec<Vec<u8>>) -> TxoutType
{
    vSolutionsRet.clear();
 
    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if scriptPubKey.IsPayToScriptHash()
    {
        //std::vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        let hashBytes: &[u8] = &scriptPubKey.v[2..22];
        vSolutionsRet.push(hashBytes.to_vec());
        return TxoutType::SCRIPTHASH;
    }
    let mut witnessversion: i32 = 0;
    let mut witnessprogram: Vec<u8> = vec![];
    if scriptPubKey.IsWitnessProgram(&mut witnessversion, &mut witnessprogram) {
        if witnessversion == 0 && witnessprogram.len() == WITNESS_V0_KEYHASH_SIZE {
            //vSolutionsRet.push_back(std::move(witnessprogram));
            vSolutionsRet.push(witnessprogram);
            return TxoutType::WITNESS_V0_KEYHASH;
        }
        if witnessversion == 0 && witnessprogram.len() == WITNESS_V0_SCRIPTHASH_SIZE {
            vSolutionsRet.push(witnessprogram);
            return TxoutType::WITNESS_V0_SCRIPTHASH;
        }
        if witnessversion == 1 && witnessprogram.len() == WITNESS_V1_TAPROOT_SIZE {
            vSolutionsRet.push(witnessprogram);
            return TxoutType::WITNESS_V1_TAPROOT;
        }
        if witnessversion != 0 {
            //vSolutionsRet.push_back(std::vector<unsigned char>{(unsigned char)witnessversion});
            let wv = vec![witnessversion as u8];
            vSolutionsRet.push(wv);
            vSolutionsRet.push(witnessprogram);
            return TxoutType::WITNESS_UNKNOWN;
        }
        return TxoutType::NONSTANDARD;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if scriptPubKey.v.len() >= 1 && scriptPubKey.v[0] == opcodetype::OP_RETURN as u8 && CScript::IsPushOnly(&mut  &scriptPubKey.v[0..1])
    {
        return TxoutType::NULL_DATA;
    }

    let mut data: Vec<u8> = vec![];
    if MatchPayToPubkey(scriptPubKey, &mut data) {
        vSolutionsRet.push(data);
        return TxoutType::PUBKEY;
    }

    if MatchPayToPubkeyHash(scriptPubKey, &mut data) {
        vSolutionsRet.push(data);
        return TxoutType::PUBKEYHASH;
    }

    let mut required: i32 = 0;
    //std::vector<std::vector<unsigned char>> keys;
    let mut keys: Vec<Vec<u8>> = vec![];
    if MatchMultisig(scriptPubKey, &mut required, &mut keys) {
        //vSolutionsRet.push_back({static_cast<unsigned char>(required)}); // safe as required is in range 1..20
        vSolutionsRet.push(vec![required as u8]); // safe as required is in range 1..20
        //vSolutionsRet.insert(vSolutionsRet.end(), keys.begin(), keys.end());
        vSolutionsRet.extend_from_slice(&keys[0..]);
        //vSolutionsRet.push_back({static_cast<unsigned char>(keys.size())}); // safe as size is in range 1..20
        vSolutionsRet.push(vec![keys.len() as u8]);
        return TxoutType::MULTISIG;
    }

    vSolutionsRet.clear();
    return TxoutType::NONSTANDARD;
}