pub mod standard;
pub mod interpreter;
use std::ops::Shl;


// Maximum number of bytes pushable to the stack
const MAX_SCRIPT_ELEMENT_SIZE:i32 = 520;

// Maximum number of non-push operations per script
const MAX_OPS_PER_SCRIPT:i32 = 201;

// Maximum number of public keys per multisig
const MAX_PUBKEYS_PER_MULTISIG:i32 = 20;

// The limit of keys in OP_CHECKSIGADD-based scripts. It is due to the stack limit in BIP342.
const MAX_PUBKEYS_PER_MULTI_A:u32 = 999;

// Maximum script length in bytes
const MAX_SCRIPT_SIZE:i32 = 10000;

// Maximum number of values on script interpreter stack
const MAX_STACK_SIZE:i32 = 1000;

// Threshold for nLockTime: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
const LOCKTIME_THRESHOLD:u32 = 500000000; // Tue Nov  5 00:53:20 1985 UTC

// Maximum nLockTime. Since a lock time indicates the last invalid timestamp, a
// transaction with this lock time will never be valid unless lock time
// checking is disabled (by setting all input sequence numbers to
// SEQUENCE_FINAL).
const LOCKTIME_MAX:u32 = 0xFFFFFFFF;

// Tag for input annex. If there are at least two witness elements for a transaction input,
// and the first byte of the last element is 0x50, this last element is called annex, and
// has meanings independent of the script
const ANNEX_TAG:u32 = 0x50;

// Validation weight per passing signature (Tapscript only, see BIP 342).
const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

// How much weight budget is added to the witness size (Tapscript only, see BIP 342).
const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Script opcodes
pub enum opcodetype
{
    // push value
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    //OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    //OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // Opcode added by BIP 342 (Tapscript)
    OP_CHECKSIGADD = 0xba,

    OP_INVALIDOPCODE = 0xff,
}

const OP_FALSE: opcodetype = opcodetype::OP_0;
const OP_TRUE: opcodetype = opcodetype::OP_1;


//bool GetScriptOp(CScriptBase::const_iterator& pc, CScriptBase::const_iterator end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet)
/// Return opcode, slice to start of next op, slice to push data
fn GetScriptOp(pc: &[u8]) -> Result<(opcodetype, &[u8], &[u8]), bool>
{
    let mut opcodeRet: opcodetype = OP_INVALIDOPCODE;
    let mut slice = pc;
    let mut nSize: u32 = 0;

    //if (pvchRet)
    //    pvchRet->clear();
    if pc.is_empty() {
        Err(false)
    }

    // Read instruction
    //if (end - pc < 1)
    //    return false;
    //unsigned int opcode = *pc++;
    let opcode: opcodetype = pc[0];
    slice = &pc[1..];

    // Immediate operand
    if opcode <= OP_PUSHDATA4
    {
        if opcode < OP_PUSHDATA1
        {
            nSize = opcode;
        }
        else if opcode == OP_PUSHDATA1
        {
            if slice.size() < 1
            {
                Err(false)
            }
            //nSize = *pc++;
            nSize = *slice;
            slice = &slice[1..];
        }
        else if opcode == OP_PUSHDATA2
        {
            if slice.size() < 2
            {
                Err(false)
            }
            //nSize = ReadLE16(&pc[0]);
            nSize = u32::from(u16::from_le_bytes(slice[0..2]));
            //pc += 2;
            slice = &slice[2..];
        }
        else if opcode == OP_PUSHDATA4
        {
            if slice.size() < 4
            {
                Err(false)
            }
            //nSize = ReadLE32(&pc[0]);
            nSize = u32::from_le_bytes(slice[0..2]);
            //pc += 4;
            slice = &slice[2..];
        }
        //if (end - pc < 0 || (unsigned int)(end - pc) < nSize)
        //    return false;
        if slice.size() < nSize
        {
            Err(false)
        }
        
        //if (pvchRet)
        //    pvchRet->assign(pc, pc + nSize);
        //pc += nSize;
    }

    //opcodeRet = static_cast<opcodetype>(opcode);
    //return true;
    Ok((opcode, slice, &slice[nSize as usize..]))
}

/**
 * We use a prevector for the script to reduce the considerable memory overhead
 *  of vectors in cases where they normally contain a small number of small elements.
 * Tests in October 2015 showed use of this reduced dbcache memory usage by 23%
 *  and made an initial sync 13% faster.
 */
//typedef prevector<28, unsigned char> CScriptBase;

/// Serialized script, used inside transaction inputs and outputs
//class CScript : public CScriptBase
pub struct CScript {

    pub v: Vec<u8>,
}

use opcodetype::*;

impl CScript
{


    // CScript& push_int64(int64_t n)
    fn push_int64(self, n: i64)
    {
        if n == -1 || (n >= 1 && n <= 16)
        {
            self.v.push_back(n + (OP_1 - 1));
        }
        else if n == 0
        {
            self.v.push_back(OP_0);
        }
        else
        {
            self.v << CScriptNum::serialize(n);
        }
    }

// public:
//    CScript() { }
//    CScript(const_iterator pbegin, const_iterator pend) : CScriptBase(pbegin, pend) { }
//    CScript(std::vector<unsigned char>::const_iterator pbegin, std::vector<unsigned char>::const_iterator pend) : CScriptBase(pbegin, pend) { }
//    CScript(const unsigned char* pbegin, const unsigned char* pend) : CScriptBase(pbegin, pend) { }

// TODO: SerializeMethods trait?
//    SERIALIZE_METHODS(CScript, obj) { READWRITEAS(CScriptBase, obj); }

    //explicit CScript(int64_t b) { operator<<(b); }
    //explicit CScript(opcodetype b)     { operator<<(b); }
    //explicit CScript(const CScriptNum& b) { operator<<(b); }
    // delete non-existent constructor to defend against future introduction
    // e.g. via prevector
    //explicit CScript(const std::vector<unsigned char>& b) = delete;

    pub fn new<T>(self, b: T)
    {
        self.v << b
    }

    /** Delete non-existent operator to defend against future introduction */
    //CScript& operator<<(const CScript& b) = delete;

 
    /*bool GetOp(const_iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>& vchRet) const
    {
        return GetScriptOp(pc, end(), opcodeRet, &vchRet);
    }*/

    pub fn GetOp(self, pc: &[u8]) -> Result<(opcodetype, &[u8], &[u8]), bool>
    {
        GetScriptOp(pc)
    }

    //bool GetOp(const_iterator& pc, opcodetype& opcodeRet) const
    //{
    //    return GetScriptOp(pc, end(), opcodeRet, nullptr);
    //}

    /** Encode/decode small integers: */
    //static int DecodeOP_N(opcodetype opcode)
    pub fn DecodeOP_N(opcode: opcodetype) -> i32
    {
        if opcode == OP_0
        {
            0
        }
        assert!(opcode >= OP_1 && opcode <= OP_16);
        i32::from(opcode) - i32::from(OP_1 - 1)
    }

    //static opcodetype EncodeOP_N(int n)
    pub fn EncodeOP_N(n: i32) -> opcodetype
    {
        assert!(n >= 0 && n <= 16);
        if n == 0
        {
            OP_0
        }
        opcodetype::from(OP_1+n-1)
    }

    /**
     * Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
     * as 20 sigops. With pay-to-script-hash, that changed:
     * CHECKMULTISIGs serialized in scriptSigs are
     * counted more accurately, assuming they are of the form
     *  ... OP_N CHECKMULTISIG ...
     */
    //unsigned int CScript::GetSigOpCount(bool fAccurate) const
    pub fn GetSigOpCount(self, fAccurate: bool) -> i32
    {
        let mut n: i32 = 0;
        //const_iterator pc = begin();
        let mut pc = &self.v[0..];
        //opcodetype lastOpcode = OP_INVALIDOPCODE;
        let mut lastOpcode: opcodetype = OP_INVALIDOPCODE;
        while pc.size() > 0
        {
            let r = self.GetOp(pc);
            match r {
                Ok((opcode, slice, size)) => {
                    if opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY
                    {
                        n += 1;
                    }
                    else if opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY
                    {
                        if fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16
                        {
                            n += self.DecodeOP_N(lastOpcode);
                        }
                        else
                        {
                            n += MAX_PUBKEYS_PER_MULTISIG;
                        }
                    }
                    lastOpcode = opcode;
        
                }
                Err(b) => {
                    break;
                }
            }

        }
        return n;
    }
    

    /**
     * Accurately count sigOps, including sigOps in
     * pay-to-script-hash transactions:
     */
    //unsigned int GetSigOpCount(const CScript& scriptSig) const;

    //bool IsPayToScriptHash() const;
    pub fn IsPayToScriptHash(self) -> bool
    {
        // Extra-fast test for pay-to-script-hash CScripts:
        self.v.len() == 23 &&
        self.v[0] == opcodetype::OP_HASH160 as u8 &&
        self.v[1] == 0x14 &&
        self.v[22] == opcodetype::OP_EQUAL as u8
    }
    
    //bool IsPayToWitnessScriptHash() const;
    pub fn IsPayToWitnessScriptHash(self) -> bool
    {
        // Extra-fast test for pay-to-witness-script-hash CScripts:
        self.v.len() == 34 &&
        self.v[0] == opcodetype::OP_0 as u8 &&
        self.v[1] == 0x20
    }
 
    // A witness program is any valid CScript that consists of a 1-byte push opcode
    // followed by a data push between 2 and 40 bytes.
    //bool CScript::IsWitnessProgram(int& version, std::vector<unsigned char>& program) const
    pub fn IsWitnessProgram(self, version: i32, program: &mut [u8] ) -> bool
    {
        if self.v.len() < 4 || self.v.len() > 42
        {
            False
        }
        if self.v[0] != opcodetype::OP_0 as u8 &&
           (self.v[0] < opcodetype::OP_1 as u8 ||
            self.v[0] > opcodetype::OP_16 as u8)
        {
            false
        }
        if (self.v[1] as usize + 2) == self.v.len()
        {
            version = self.DecodeOP_N(self.v[0].try_into());
            //program = std::vector<unsigned char>(this->begin() + 2, this->end());
            program.clone_from_slice(&self.v[2.. ]);
            true
        }
        false
    }

    /** Called by IsStandardTx and P2SH/BIP62 VerifyScript (which makes it consensus-critical). */
    //bool IsPushOnly() const;
    //bool CScript::IsPushOnly(const_iterator pc) const
    pub fn IsPushOnly(self, mut pc: &[u8]) -> bool
    {
        while pc.len() > 0
        {
            let mut opcode: opcodetype;
            let r = self.GetOp(pc);
            match r {
                Ok((opcode, slice, size)) => {
                    // Note that IsPushOnly() *does* consider OP_RESERVED to be a
                    // push-type opcode, however execution of OP_RESERVED fails, so
                    // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
                    // the P2SH special validation code being executed.
                    if opcode > OP_16 as u8
                    {
                        return false;
                    }
                }
                Err(b) => {
                    false;
                }
            }
        }
        return true;
    }

    /** Check if the script contains valid OP_CODES */
    //bool HasValidOps() const;

    /**
     * Returns whether the script is guaranteed to fail at execution,
     * regardless of the initial stack. This allows outputs to be pruned
     * instantly when entering the UTXO set.
     */
    //bool IsUnspendable() const
    pub fn IsUnspendable(self) -> bool
    {
        (self.v.size() > 0 && self.v[0] == OP_RETURN) || (self.v.size() > MAX_SCRIPT_SIZE)
    }

    pub fn clear(self)
    {
        // The default prevector::clear() does not release memory
        self.v.clear();
    }
}



   //CScript& operator<<(int64_t b) LIFETIMEBOUND { return push_int64(b); }
/*
   CScript& operator<<(opcodetype opcode) LIFETIMEBOUND
   {
       if (opcode < 0 || opcode > 0xff)
           throw std::runtime_error("CScript::operator<<(): invalid opcode");
       insert(end(), (unsigned char)opcode);
       return *this;
   }

   CScript& operator<<(const CScriptNum& b) LIFETIMEBOUND
   {
       *this << b.getvch();
       return *this;
   }

   CScript& operator<<(const std::vector<unsigned char>& b) LIFETIMEBOUND
   {
       if (b.size() < OP_PUSHDATA1)
       {
           insert(end(), (unsigned char)b.size());
       }
       else if (b.size() <= 0xff)
       {
           insert(end(), OP_PUSHDATA1);
           insert(end(), (unsigned char)b.size());
       }
       else if (b.size() <= 0xffff)
       {
           insert(end(), OP_PUSHDATA2);
           uint8_t _data[2];
           WriteLE16(_data, b.size());
           insert(end(), _data, _data + sizeof(_data));
       }
       else
       {
           insert(end(), OP_PUSHDATA4);
           uint8_t _data[4];
           WriteLE32(_data, b.size());
           insert(end(), _data, _data + sizeof(_data));
       }
       insert(end(), b.begin(), b.end());
       return *this;
   }
*/
impl<T> Shl<T> for CScript {
    type Output = Self;

    fn shl(self, rhs:T) -> Self::Output
    {
        // TODO: figure out what to do here
        //Serialize(self.S, rhs);
        Self
    } 

}
