// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::script::CScript;
use crate::script::interpreter::*;
use crate::script::opcodetype;
use crate::pubkey;

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
    if script.v.len() == pubkey::COMPRESSED_SIZE + 2 && script.v[0] == pubkey::COMPRESSED_SIZE as u8 && script.v.last().unwrap() == opcodetype::OP_CHECKSIG
    {
        //pubkey = valtype(script.begin() + 1, script.begin() + pubkey::COMPRESSED_SIZE + 1);
        pubkey.copy_from_slice(&script.v[1..pubkey::COMPRESSED_SIZE + 1]);
        return pubkey::ValidSize(pubkey);
    }
    return false;
}

fn MatchMultisig(script: &CScript, required_sigs: &mut i32, pubkeys: &Vec<valtype>) -> bool
{
    let opcode: opcodetype;
    let data: valtype;

    CScript::const_iterator it = script.begin();
    if (script.size() < 1 || script.back() != OP_CHECKMULTISIG) return false;

    if (!script.GetOp(it, opcode, data)) return false;
    auto req_sigs = GetScriptNumber(opcode, data, 1, MAX_PUBKEYS_PER_MULTISIG);
    if (!req_sigs) return false;
    required_sigs = *req_sigs;
    while (script.GetOp(it, opcode, data) && CPubKey::ValidSize(data)) {
        pubkeys.emplace_back(std::move(data));
    }
    auto num_keys = GetScriptNumber(opcode, data, required_sigs, MAX_PUBKEYS_PER_MULTISIG);
    if (!num_keys) return false;
    if (pubkeys.size() != static_cast<unsigned long>(*num_keys)) return false;

    return (it + 1 == script.end());
}

//TxoutType Solver(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& vSolutionsRet)
pub fn Solver(scriptPubKey: &CScript, vSolutionsRet: &mut Vec<Vec<u8>>) -> TxoutType
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
    let mut witnessversion: u32;
    let mut witnessprogram: Vec<u8>;
    if scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram) {
        if witnessversion == 0 && witnessprogram.len() == WITNESS_V0_KEYHASH_SIZE {
            //vSolutionsRet.push_back(std::move(witnessprogram));
            vSolutionsRet.push(witnessprogram);
            TxoutType::WITNESS_V0_KEYHASH
        }
        if witnessversion == 0 && witnessprogram.len() == WITNESS_V0_SCRIPTHASH_SIZE {
            vSolutionsRet.append(witnessprogram);
            (TxoutType::WITNESS_V0_SCRIPTHASH, vSolutionsRet)
        }
        if witnessversion == 1 && witnessprogram.len() == WITNESS_V1_TAPROOT_SIZE {
            vSolutionsRet.push(witnessprogram);
            (TxoutType::WITNESS_V1_TAPROOT, vSolutionsRet)
        }
        if witnessversion != 0 {
            //vSolutionsRet.push_back(std::vector<unsigned char>{(unsigned char)witnessversion});
            let wv = vec![witnessversion as u8];
            vSolutionsRet.push(wv);
            vSolutionsRet.push(witnessprogram);
            (TxoutType::WITNESS_UNKNOWN, vSolutionsRet)
        }
        (TxoutType::NONSTANDARD, vSolutionsRet)
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if scriptPubKey.v.len() >= 1 && scriptPubKey.v[0] == opcodetype::OP_RETURN as u8 && scriptPubKey.IsPushOnly(scriptPubKey.v[0..1])
    {
        return TxoutType::NULL_DATA;
    }

    let mut data: Vec<u8>;
    if MatchPayToPubkey(scriptPubKey, data) {
        vSolutionsRet.push_back(data);
        return TxoutType::PUBKEY;
    }

    if MatchPayToPubkeyHash(scriptPubKey, data) {
        vSolutionsRet.push_back(data);
        return TxoutType::PUBKEYHASH;
    }

    let mut required: i32;
    //std::vector<std::vector<unsigned char>> keys;
    let mut keys: Vec<Vec<u8>>;
    if MatchMultisig(scriptPubKey, required, keys) {
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