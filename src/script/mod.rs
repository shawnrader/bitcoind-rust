pub mod standard;
pub mod interpreter;
use crate::serialize::AsBytes;
use std::ops::{Shl, ShlAssign};

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

// Script opcodes
#[repr(u8)]
#[derive(Clone, PartialEq, PartialOrd)]
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

pub const OP_FALSE: opcodetype = opcodetype::OP_0;
pub const OP_TRUE: opcodetype = opcodetype::OP_1;


impl opcodetype {
    pub fn cs(self) -> CScript {
        let v = vec![self as u8];
        CScript::new(v)
    }

    pub fn from_u8(n: u8) -> Option<opcodetype> {
        match n {
            0x00 => Some(opcodetype::OP_0),
            0x4c => Some(opcodetype::OP_PUSHDATA1),
            0x4d => Some(opcodetype::OP_PUSHDATA2),
            0x4e => Some(opcodetype::OP_PUSHDATA4),
            0x4f => Some(opcodetype::OP_1NEGATE),
            0x50 => Some(opcodetype::OP_RESERVED),
            0x51 => Some(opcodetype::OP_1),
            0x52 => Some(opcodetype::OP_2),
            0x53 => Some(opcodetype::OP_3),
            0x54 => Some(opcodetype::OP_4),
            0x55 => Some(opcodetype::OP_5),
            0x56 => Some(opcodetype::OP_6),
            0x57 => Some(opcodetype::OP_7),
            0x58 => Some(opcodetype::OP_8),
            0x59 => Some(opcodetype::OP_9),
            0x5a => Some(opcodetype::OP_10),
            0x5b => Some(opcodetype::OP_11),
            0x5c => Some(opcodetype::OP_12),
            0x5d => Some(opcodetype::OP_13),
            0x5e => Some(opcodetype::OP_14),
            0x5f => Some(opcodetype::OP_15),
            0x60 => Some(opcodetype::OP_16),
            0x61 => Some(opcodetype::OP_NOP),
            0x62 => Some(opcodetype::OP_VER),
            0x63 => Some(opcodetype::OP_IF),
            0x64 => Some(opcodetype::OP_NOTIF),
            0x65 => Some(opcodetype::OP_VERIF),
            0x66 => Some(opcodetype::OP_VERNOTIF),
            0x67 => Some(opcodetype::OP_ELSE),
            0x68 => Some(opcodetype::OP_ENDIF),
            0x69 => Some(opcodetype::OP_VERIFY),
            0x6a => Some(opcodetype::OP_RETURN),
            0x6b => Some(opcodetype::OP_TOALTSTACK),
            0x6c => Some(opcodetype::OP_FROMALTSTACK),
            0x6d => Some(opcodetype::OP_2DROP),
            0x6e => Some(opcodetype::OP_2DUP),
            0x6f => Some(opcodetype::OP_3DUP),
            0x70 => Some(opcodetype::OP_2OVER),
            0x71 => Some(opcodetype::OP_2ROT),
            0x72 => Some(opcodetype::OP_2SWAP),
            0x73 => Some(opcodetype::OP_IFDUP),
            0x74 => Some(opcodetype::OP_DEPTH),
            0x75 => Some(opcodetype::OP_DROP),
            0x76 => Some(opcodetype::OP_DUP),
            0x77 => Some(opcodetype::OP_NIP),
            0x78 => Some(opcodetype::OP_OVER),
            0x79 => Some(opcodetype::OP_PICK),
            0x7a => Some(opcodetype::OP_ROLL),
            0x7b => Some(opcodetype::OP_ROT),
            0x7c => Some(opcodetype::OP_SWAP),
            0x7d => Some(opcodetype::OP_TUCK),
            0x7e => Some(opcodetype::OP_CAT),
            0x7f => Some(opcodetype::OP_SUBSTR),
            0x80 => Some(opcodetype::OP_LEFT),
            0x81 => Some(opcodetype::OP_RIGHT),
            0x82 => Some(opcodetype::OP_SIZE),
            0x83 => Some(opcodetype::OP_INVERT),
            0x84 => Some(opcodetype::OP_AND),
            0x85 => Some(opcodetype::OP_OR),
            0x86 => Some(opcodetype::OP_XOR),
            0x87 => Some(opcodetype::OP_EQUAL),
            0x88 => Some(opcodetype::OP_EQUALVERIFY),
            0x89 => Some(opcodetype::OP_RESERVED1),
            0x8a => Some(opcodetype::OP_RESERVED2),
            0x8b => Some(opcodetype::OP_1ADD),
            0x8c => Some(opcodetype::OP_1SUB),
            0x8d => Some(opcodetype::OP_2MUL),
            0x8e => Some(opcodetype::OP_2DIV),
            0x8f => Some(opcodetype::OP_NEGATE),
            0x90 => Some(opcodetype::OP_ABS),
            0x91 => Some(opcodetype::OP_NOT),
            0x92 => Some(opcodetype::OP_0NOTEQUAL),
            0x93 => Some(opcodetype::OP_ADD),
            0x94 => Some(opcodetype::OP_SUB),
            0x95 => Some(opcodetype::OP_MUL),
            0x96 => Some(opcodetype::OP_DIV),
            0x97 => Some(opcodetype::OP_MOD),
            0x98 => Some(opcodetype::OP_LSHIFT),
            0x99 => Some(opcodetype::OP_RSHIFT),
            0x9a => Some(opcodetype::OP_BOOLAND),
            0x9b => Some(opcodetype::OP_BOOLOR),
            0x9c => Some(opcodetype::OP_NUMEQUAL),
            0x9d => Some(opcodetype::OP_NUMEQUALVERIFY),
            0x9e => Some(opcodetype::OP_NUMNOTEQUAL),
            0x9f => Some(opcodetype::OP_LESSTHAN),
            0xa0 => Some(opcodetype::OP_GREATERTHAN),
            0xa1 => Some(opcodetype::OP_LESSTHANOREQUAL),
            0xa2 => Some(opcodetype::OP_GREATERTHANOREQUAL),
            0xa3 => Some(opcodetype::OP_MIN),
            0xa4 => Some(opcodetype::OP_MAX),
            0xa5 => Some(opcodetype::OP_WITHIN),
            0xa6 => Some(opcodetype::OP_RIPEMD160),
            0xa7 => Some(opcodetype::OP_SHA1),
            0xa8 => Some(opcodetype::OP_SHA256),
            0xa9 => Some(opcodetype::OP_HASH160),
            0xaa => Some(opcodetype::OP_HASH256),
            0xab => Some(opcodetype::OP_CODESEPARATOR),
            0xac => Some(opcodetype::OP_CHECKSIG),
            0xad => Some(opcodetype::OP_CHECKSIGVERIFY),
            0xae => Some(opcodetype::OP_CHECKMULTISIG),
            0xaf => Some(opcodetype::OP_CHECKMULTISIGVERIFY),
            0xb0 => Some(opcodetype::OP_NOP1),
            0xb1 => Some(opcodetype::OP_CHECKLOCKTIMEVERIFY),
            0xb2 => Some(opcodetype::OP_CHECKSEQUENCEVERIFY),
            0xb3 => Some(opcodetype::OP_NOP4),
            0xb4 => Some(opcodetype::OP_NOP5),
            0xb5 => Some(opcodetype::OP_NOP6),
            0xb6 => Some(opcodetype::OP_NOP7),
            0xb7 => Some(opcodetype::OP_NOP8),
            0xb8 => Some(opcodetype::OP_NOP9),
            0xb9 => Some(opcodetype::OP_NOP10),
            0xfa => Some(opcodetype::OP_CHECKSIGADD),
            0xff => Some(opcodetype::OP_INVALIDOPCODE),
            _ => None,
        }
    }
}

/**
 * Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
 * The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
 * but results may overflow (and are valid as long as they are not used in a subsequent
 * numeric operation). CScriptNum enforces those semantics by storing results as
 * an int64 and allowing out-of-range values to be returned as a vector of bytes but
 * throwing an exception if arithmetic is done or the result is interpreted as an integer.
 */
struct CScriptNum {
    m_value: i64,
}

impl CScriptNum {
    const nDefaultMaxNumSize: usize = 4;

    fn new(vch: &Vec<u8>, fRequireMinimal: bool, nSize: Option<usize>) -> Result<Self, String>
    {
        let nMaxNumSize = nSize.unwrap_or(CScriptNum::nDefaultMaxNumSize);
        if vch.len() > nMaxNumSize {
            return Err("script number overflow".to_string());
        }
        if fRequireMinimal && vch.len() > 0 {
            // Check that the number is encoded with the minimum possible
            // number of bytes.
            //
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. Note how this test also rejects the
            // negative-zero encoding, 0x80.
           if (vch.last().unwrap() & 0x7f) == 0 {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set
                // it would conflict with the sign bit. An example of this case
                // is +-255, which encode to 0xff00 and 0xff80 respectively.
                // (big-endian).
          //      if vch.len() <= 1 || (vch[vch.len() - 2] & 0x80) == 0 {
                    return Err("non-minimally encoded script number".to_string());
         //       }
            }
        }
        let m = Self::set_vch(vch);
        Ok(Self {m_value: m})
    }

    pub fn GetInt64(self) -> i64 { return self.m_value; }

    pub fn getint(self) -> i32
    {
        if self.m_value > i32::MAX as i64 {
            return i32::MAX;
        }
        else if self.m_value < i32::MIN as i64 {
            return i32::MIN;
        }
        return self.m_value as i32;
    }

    pub fn getvch(self) -> Vec<u8>
    {
        return CScriptNum::serialize(self.m_value);
    }

    //static int64_t set_vch(const std::vector<unsigned char>& vch)
    fn set_vch(vch: &Vec<u8>) -> i64
    {
        if vch.len() == 0 {
            return 0;
        }

        let mut result: i64 = 0;
        //for (size_t i = 0; i != vch.size(); ++i)
        for i in 0..vch.len() {
            result |= (vch[i] as i64) << 8 * i as i64;
        }
        // If the input vector's most significant byte is 0x80, remove it from
        // the result's msb and return a negative.
        if *vch.last().unwrap() & 0x80 != 0 {
            return -(result & !((0x80 as i64) << (8 * (vch.len() - 1))));
        }
        return result;
    }

    //static std::vector<unsigned char> serialize(const int64_t& value)
    pub fn serialize(value: i64) -> Vec<u8>
    {
        let mut result: Vec<u8> = Vec::new();

        if value == 0
        {
            return result;
        }

        let neg: bool = value < 0;
        let mut absvalue: u64 = if neg { !(value as u64) + 1 } else { value as u64 };

        while absvalue != 0
        {
            result.push((absvalue & 0xff) as u8);
            absvalue >>= 8;
        }

//    - If the most significant byte is >= 0x80 and the value is positive, push a
//    new zero-byte to make the significant byte < 0x80 again.

//    - If the most significant byte is >= 0x80 and the value is negative, push a
//    new 0x80 byte that will be popped off when converting to an integral.

//    - If the most significant byte is < 0x80 and the value is negative, add
//    0x80 to it, since it will be subtracted and interpreted as a negative when
//    converting to an integral.

        if *result.last().unwrap() & 0x80 != 0
        {
            if neg {
                result.push(0x80);
            }
            else {
                result.push(0);
            }
        }
        else if neg {
            let last = result.last_mut().unwrap();
            *last |= 0x80;
        }

        return result;
    }

}

#[allow(unused_assignments)]
//bool GetScriptOp(CScriptBase::const_iterator& pc, CScriptBase::const_iterator end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet)
/// Return opcode, slice to start of next op, slice to push data
fn GetScriptOp<'a>(pc: &mut &'a [u8], opcodeRet: &mut u8, pvchRet: &mut &'a [u8]) -> bool
{
    let mut nSize: u32 = 0;
   
    *opcodeRet = OP_INVALIDOPCODE as u8;

    //if (pvchRet)
    //    pvchRet->clear();
    if pc.is_empty() {
        return false;
    }

    // Read instruction
    //if (end - pc < 1)
    //    return false;
    //unsigned int opcode = *pc++;
    let opcode_raw = pc[0];
    let opcode_reg = opcodetype::from_u8(pc[0]);
    *pc = &pc[1..];

    // Immediate operand
    if opcode_raw <= OP_PUSHDATA4 as u8
    {
        if opcode_raw < OP_PUSHDATA1 as u8
        {
            nSize = opcode_raw.clone() as u32;
        }
        else if opcode_raw == OP_PUSHDATA1 as u8
        {
            if pc.len() < 1
            {
                return false;
            }
            //nSize = *pc++;
            nSize = pc[0] as u32;
            *pc = &pc[1..];
        }
        else if opcode_raw == OP_PUSHDATA2 as u8
        {
            if pc.len() < 2
            {
                return false;
            }
            //nSize = ReadLE16(&pc[0]);
            nSize = u32::from(u16::from_le_bytes(pc[0..2].try_into().unwrap()));
            //pc += 2;
            *pc = &pc[2..];
        }
        else if opcode_raw == OP_PUSHDATA4 as u8
        {
            if pc.len() < 4
            {
                return false;
            }
            //nSize = ReadLE32(&pc[0]);
            nSize = u32::from_le_bytes(pc[0..2].try_into().unwrap());
            //pc += 4;
            *pc = &pc[2..];
        }
        //if (end - pc < 0 || (unsigned int)(end - pc) < nSize)
        //    return false;
        if pc.len() < nSize as usize
        {
            return false;
        }
        
        //if (pvchRet)
        //    pvchRet->assign(pc, pc + nSize);
        //pc += nSize;
        *pvchRet = &pc[0..nSize as usize];
        *pc = &pc[nSize as usize..];
    }
    *opcodeRet = opcode_raw;

    return true;

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
#[derive(Debug, Clone)]
pub struct CScript {

    pub v: Vec<u8>,
}

use opcodetype::*;


impl CScript
{
    // CScript& push_int64(int64_t n)
    fn push_int64(&mut self, n: i64) -> &mut CScript
    {
        if n == -1 || (n >= 1 && n <= 16)
        {
            self.v.push(n as u8 + (OP_1 as u8 - 1));
        }
        else if n == 0
        {
            self.v.push(OP_0 as u8);
        }
        else
        {
            *self <<= CScriptNum::serialize(n);
        }
        self
    }

    pub fn append(&mut self, s: &CScript)
    {
        println!("append: {:?} and {:?}", self.v, s.to_vec());
        self.v.append(&mut s.to_vec());
        println!("append result: {:?}", self.v);
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.v.clone()
    }

    pub fn new(v: Vec<u8>) -> CScript {
        CScript { v }
    }

    pub fn push_data(b: &[u8]) -> CScript {
        let mut v = Vec::new();

        if b.len() < OP_PUSHDATA1 as usize
        {
            v.push(b.len() as u8);
        }
        else if b.len() <= 0xff
        {
            v.push(OP_PUSHDATA1 as u8);
            v.push(b.len() as u8);
        }
        else if b.len() <= 0xffff
        {
            v.push(OP_PUSHDATA2 as u8);
            v.extend_from_slice(&u16::to_le_bytes(b.len() as u16));
        }
        else
        {
            v.push(OP_PUSHDATA4 as u8);
            v.extend_from_slice(&u32::to_le_bytes(b.len() as u32));
        }
        v.extend_from_slice(b);
        return CScript::new(v)
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

    pub fn from_i64(b: i64)
    {
       let mut s = Self{v:vec![]};
       s <<= b;
    }

    /** Delete non-existent operator to defend against future introduction */
    //CScript& operator<<(const CScript& b) = delete;

 
    /*bool GetOp(const_iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>& vchRet) const
    {
        return GetScriptOp(pc, end(), opcodeRet, &vchRet);
    }*/
    #[allow(unused_mut)]
    pub fn GetOp<'a>(pc: &mut &'a [u8], opcodeRet: &mut u8, pvchRet: &mut &'a [u8]) -> bool
    {
        GetScriptOp(pc, opcodeRet, pvchRet)
    }

    //bool GetOp(const_iterator& pc, opcodetype& opcodeRet) const
    //{
    //    return GetScriptOp(pc, end(), opcodeRet, nullptr);
    //}

    /** Encode/decode small integers: */
    //static int DecodeOP_N(opcodetype opcode)
    pub fn DecodeOP_N(opcode: u8) -> i32
    {
        if opcode == OP_0 as u8
        {
            return 0;
        }
        assert!(opcode >= OP_1 as u8 && opcode <= OP_16 as u8);
        opcode as i32 - (OP_1 as i32 - 1)
    }

    //static opcodetype EncodeOP_N(int n)
    pub fn EncodeOP_N(n: i32) -> opcodetype
    {
        assert!(n >= 0 && n <= 16);
        if n == 0
        {
            return OP_0;
        }

        opcodetype::from_u8(OP_1 as u8 + (n as u8 - 1)).unwrap()
    }

    /**
     * Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
     * as 20 sigops. With pay-to-script-hash, that changed:
     * CHECKMULTISIGs serialized in scriptSigs are
     * counted more accurately, assuming they are of the form
     *  ... OP_N CHECKMULTISIG ...
     */
    //unsigned int CScript::GetSigOpCount(bool fAccurate) const
    pub fn GetSigOpCount(&self, fAccurate: bool) -> i32
    {
        let mut n: i32 = 0;
        //const_iterator pc = begin();
        let pc = &mut &self.v[0..];
        //opcodetype lastOpcode = OP_INVALIDOPCODE;
        let mut lastOpcode = OP_INVALIDOPCODE as u8;
        while pc.len() > 0
        {
            let mut pvchRet: &[u8] = &[];
            let mut opcode = opcodetype::OP_INVALIDOPCODE as u8;
            if CScript::GetOp(pc, &mut opcode, &mut pvchRet) == false
            {
                break;
            }
            if opcode == OP_CHECKSIG as u8 || opcode == OP_CHECKSIGVERIFY as u8
            {
                n += 1;
            }
            else if opcode == OP_CHECKMULTISIG as u8 || opcode == OP_CHECKMULTISIGVERIFY as u8
            {
                if fAccurate && lastOpcode >= OP_1 as u8 && lastOpcode <= OP_16 as u8
                {
                    n += CScript::DecodeOP_N(lastOpcode);
                }
                else
                {
                    n += MAX_PUBKEYS_PER_MULTISIG;
                }
            }
            lastOpcode = opcode;
        }
        return n;
    }
    

    /* 
    unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
    {
        if (!IsPayToScriptHash())
            return GetSigOpCount(true);

        // This is a pay-to-script-hash scriptPubKey;
        // get the last item that the scriptSig
        // pushes onto the stack:
        const_iterator pc = scriptSig.begin();
        std::vector<unsigned char> vData;
        while (pc < scriptSig.end())
        {
            opcodetype opcode;
            if (!scriptSig.GetOp(pc, opcode, vData))
                return 0;
            if (opcode > OP_16)
                return 0;
        }

        /// ... and return its opcount:
        CScript subscript(vData.begin(), vData.end());
        return subscript.GetSigOpCount(true);
    }
    */
    pub fn GetScriptSigOpCount(&mut self, scriptSig: &CScript) -> i32 {
        if !self.IsPayToScriptHash() {
            return self.GetSigOpCount(true);
        }

        // This is a pay-to-script-hash scriptPubKey;
        // get the last item that the scriptSig
        // pushes onto the stack:
        let mut pc = &mut &scriptSig.v[0..];
        let mut vData: &[u8] = &[];
        while pc.len() > 0 {
            let mut opcode = opcodetype::OP_INVALIDOPCODE as u8;
            if CScript::GetOp(pc, &mut opcode, &mut vData) == false {
                return 0;
            }
            if opcode > OP_16 as u8{
                return 0;
            }
        }

        // ... and return its opcount:
        let subscript = CScript::new(vData.to_vec());
        return subscript.GetSigOpCount(true);
    }


    /**
     * Accurately count sigOps, including sigOps in
     * pay-to-script-hash transactions:
     */
    //unsigned int GetSigOpCount(const CScript& scriptSig) const;

    //bool IsPayToScriptHash() const;
    pub fn IsPayToScriptHash(&self) -> bool
    {
        // Extra-fast test for pay-to-script-hash CScripts:
        self.v.len() == 23 &&
        self.v[0] == opcodetype::OP_HASH160 as u8 &&
        self.v[1] == 0x14 &&
        self.v[22] == opcodetype::OP_EQUAL as u8
    }
    
    //bool IsPayToWitnessScriptHash() const;
    pub fn IsPayToWitnessScriptHash(&self) -> bool
    {
        // Extra-fast test for pay-to-witness-script-hash CScripts:
        self.v.len() == 34 &&
        self.v[0] == opcodetype::OP_0 as u8 &&
        self.v[1] == 0x20
    }
 
    // A witness program is any valid CScript that consists of a 1-byte push opcode
    // followed by a data push between 2 and 40 bytes.
    //bool CScript::IsWitnessProgram(int& version, std::vector<unsigned char>& program) const
    pub fn IsWitnessProgram(&self, version: &mut i32, program: &mut [u8] ) -> bool
    {
        if self.v.len() < 4 || self.v.len() > 42
        {
            return false;
        }
        if self.v[0] != opcodetype::OP_0 as u8 &&
           (self.v[0] < opcodetype::OP_1 as u8 ||
            self.v[0] > opcodetype::OP_16 as u8)
        {
            return false;
        }
        if (self.v[1] as usize + 2) == self.v.len()
        {
            let opcode = self.v[0];
            *version = CScript::DecodeOP_N(opcode);
            //program = std::vector<unsigned char>(this->begin() + 2, this->end());
            program.clone_from_slice(&self.v[2.. ]);
            return true;
        }
        false
    }

    /** Called by IsStandardTx and P2SH/BIP62 VerifyScript (which makes it consensus-critical). */
    //bool IsPushOnly() const;
    //bool CScript::IsPushOnly(const_iterator pc) const
    pub fn IsPushOnly(pc: &[u8]) -> bool
    {
        while pc.len() > 0
        {
            let mut opcode = opcodetype::OP_INVALIDOPCODE as u8;
            let mut pvchRet: &[u8] = &[];
            let mut pc = pc;
            if CScript::GetOp(&mut pc, &mut opcode, &mut pvchRet)
            {
                // Note that IsPushOnly() *does* consider OP_RESERVED to be a
                // push-type opcode, however execution of OP_RESERVED fails, so
                // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
                // the P2SH special validation code being executed.
                if opcode > OP_16 as u8
                {
                    return false;
                }
            }
            else
            {
                return false;
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
    pub fn IsUnspendable(&self) -> bool
    {
        (self.v.len() > 0 && self.v[0] == OP_RETURN as u8) || (self.v.len() > MAX_SCRIPT_SIZE as usize)
    }

    pub fn clear(&mut self)
    {
        // The default prevector::clear() does not release memory
        self.v.clear();
    }
}

impl AsBytes for CScript {
    fn as_bytes(&self) -> &[u8] {
        self.v.as_slice()
    }
}

impl Shl for CScript {
    type Output = CScript;
    fn shl(self, s: CScript) -> CScript
    {
        let mut result = CScript::new(self.to_vec());
        result.append(&s);
        result
    }
}

impl ShlAssign<CScript> for CScript {
    fn shl_assign(&mut self, s: CScript) {
        self.append(&s);
    }
}

//CScript& operator<<(int64_t b) LIFETIMEBOUND { return push_int64(b); }
impl ShlAssign<i64> for CScript {

    fn shl_assign(&mut self, b: i64) {
        self.push_int64(b);
    }
}

/*
   CScript& operator<<(opcodetype opcode) LIFETIMEBOUND
   {
       if (opcode < 0 || opcode > 0xff)
           throw std::runtime_error("CScript::operator<<(): invalid opcode");
       insert(end(), (unsigned char)opcode);
       return *this;
   }
*/
impl ShlAssign<opcodetype> for CScript {

    fn shl_assign(&mut self, opcode: opcodetype)
    {
        let code = opcode as u8;
        assert!((code < 0) || (code as u8 > 0xff));
        self.v.insert(0, code);
    }
}


/*
   CScript& operator<<(const CScriptNum& b) LIFETIMEBOUND
   {
       *this << b.getvch();
       return *this;
   }
*/

impl ShlAssign<CScriptNum> for CScript {

    fn shl_assign(&mut self, b: CScriptNum)
    {
        *self <<= b.getvch();
    }
}

/*
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
impl ShlAssign<Vec<u8>> for CScript {

    fn shl_assign(&mut self, b: Vec<u8>)
    {
        if b.len() < OP_PUSHDATA1 as usize
        {
            //insert(end(), (unsigned char)b.size());
            self.v.push(b.len() as u8)

        }
        else if b.len() <= 0xff as usize
        {
            //insert(end(), OP_PUSHDATA1);
            //insert(end(), (unsigned char)b.size());
            self.v.push(OP_PUSHDATA1 as u8);
            self.v.push(b.len() as u8)
        }
        else if b.len() <= 0xffff as usize
        {
            //insert(end(), OP_PUSHDATA2);
            self.v.push(OP_PUSHDATA2 as u8);
            //uint8_t _data[2];
            //WriteLE16(_data, b.size());
            //insert(end(), _data, _data + sizeof(_data));
            self.v.append(&mut b.clone());
        }
        else
        {
            //insert(end(), OP_PUSHDATA4);
            self.v.push(OP_PUSHDATA4 as u8);
            //uint8_t _data[4];
            //WriteLE32(_data, b.size());
            //insert(end(), _data, _data + sizeof(_data));
            self.v.append(&mut b.clone());
        }
        //insert(end(), b.begin(), b.end());
        //return *this;
    }
}


// bool CheckMinimalPush(const std::vector<unsigned char>& data, opcodetype opcode) {
pub fn CheckMinimalPush(data: &[u8], opcode: u8) -> bool
{
    // Excludes OP_1NEGATE, OP_1-16 since they are by definition minimal
    assert!(0 <= opcode.clone() as u8 && opcode <= OP_PUSHDATA4 as u8);
    if data.len() == 0 {
        // Should have used OP_0.
        return opcode == OP_0 as u8;
    } else if data.len() == 1 && data[0] >= 1 && data[0] <= 16 {
        // Should have used OP_1 .. OP_16.
        return false;
    } else if data.len() == 1 && data[0] == 0x81 {
        // Should have used OP_1NEGATE.
        return false;
    } else if data.len() <= 75 {
        // Must have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode as u8 == data.len() as u8;
    } else if data.len() <= 255 {
        // Must have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1 as u8;
    } else if data.len() <= 65535 {
        // Must have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2 as u8;
    }
    return true;
}

#[cfg(test)]

mod tests {
    use super::CScript;
    use primitive_types::H160;
    use crate::{hash::Hash160, serialize::AsBytes};
    use super::opcodetype::*;
    use crate::script::standard::{GetScriptForDestination, CTxDestination};
    use crate::pubkey::CPubKey;
    
    #[test]
    fn test_GetSigOpCount() {
        let mut s1: CScript = CScript{v: vec![]};
        assert_eq!(s1.GetSigOpCount(false), 0);
        assert_eq!(s1.GetSigOpCount(true), 0);

        let mut dummy = H160::zero();
        //s1 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << OP_2 << OP_CHECKMULTISIG;
        s1 = OP_1.cs() << CScript::push_data(dummy.as_bytes()) << CScript::push_data(dummy.as_bytes()) << OP_2.cs() << OP_CHECKMULTISIG.cs();
        assert_eq!(s1.GetSigOpCount(true), 2);
        s1 <<= OP_IF.cs() << OP_CHECKSIG.cs() << OP_ENDIF.cs();
        let opcount = s1.GetSigOpCount(true);
        assert_eq!(opcount, 3);
        assert_eq!(s1.GetSigOpCount(false), 21);

        //CScript p2sh = GetScriptForDestination(ScriptHash(s1));
        let hash = Hash160(&s1);
        let mut p2sh = GetScriptForDestination(&CTxDestination::ScriptHash(hash));
        //CScript scriptSig;
        let mut scriptSig: CScript = CScript{v: vec![]};
        //scriptSig << OP_0 << Serialize(s1);
        scriptSig = OP_0.cs() << CScript::push_data(s1.as_bytes());
        //BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig), 3U);
        assert_eq!(p2sh.GetScriptSigOpCount(&scriptSig), 3);

        let keys: Vec<CPubKey> = vec![];
        for i in 0..3 {
            let k: CKey;
            k.MakeNewKey(true);
            keys.push_back(k.GetPubKey());
        }
    }
}