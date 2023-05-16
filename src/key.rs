// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::random::GetStrongRandBytes;
use crate::secp256k1::{secp256k1_ec_seckey_verify, secp256k1_ec_seckey_negate, secp256k1_ec_pubkey_create, secp256k1_ec_pubkey_serialize,
                       secp256k1_context, secp256k1_pubkey, SECP256K1_EC_COMPRESSED, SECP256K1_EC_UNCOMPRESSED,};
use crate::pubkey::CPubKey;

/** These functions are taken from the libsecp256k1 distribution and are very ugly. */

/**
 * This parses a format loosely based on a DER encoding of the ECPrivateKey type from
 * section C.4 of SEC 1 <https://www.secg.org/sec1-v2.pdf>, with the following caveats:
 *
 * * The octet-length of the SEQUENCE must be encoded as 1 or 2 octets. It is not
 *   required to be encoded as one octet if it is less than 256, as DER would require.
 * * The octet-length of the SEQUENCE must not be greater than the remaining
 *   length of the key encoding, but need not match it (i.e. the encoding may contain
 *   junk after the encoded SEQUENCE).
 * * The privateKey OCTET STRING is zero-filled on the left to 32 octets.
 * * Anything after the encoding of the privateKey OCTET STRING is ignored, whether
 *   or not it is validly encoded DER.
 *
 * out32 must point to an output buffer of length at least 32 bytes.
 */
//int ec_seckey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *seckey, size_t seckeylen) {
fn ec_seckey_import_der(ctx: &secp256k1_context, out32: &mut [u8; 32], mut seckey: &[u8]) -> bool {
    //const unsigned char *end = seckey + seckeylen;

    //memset(out32, 0, 32);
    *out32 = [0u8; 32];
 
    /* sequence header */
    //if (end - seckey < 1 || *seckey != 0x30u) {
    if seckey.len() < 1 || seckey[0] != 0x30u8 {
        return false;
    }
    //seckey++;
    seckey = &seckey[1..];
    /* sequence length constructor */
    //if (end - seckey < 1 || !(*seckey & 0x80u)) {
    if seckey.len() < 1 || 0 == (seckey[0] & 0x80u8) {
        return false;
    }
    //ptrdiff_t lenb = *seckey & ~0x80u; seckey++;
    let lenb = seckey[0] as usize & !0x80_usize;
    if lenb < 1 || lenb > 2 {
        return false;
    }
    //if (end - seckey < lenb) {
    if seckey.len() < lenb as usize {
        return false;
    }
    /* sequence length */
    //ptrdiff_t len = seckey[lenb-1] | (lenb > 1 ? seckey[lenb-2] << 8 : 0u);
    let len = seckey[lenb-1] as usize | if lenb > 1 { (seckey[lenb-2] as usize) << 8 } else { 0_usize };
    //seckey += lenb;
    seckey = &seckey[lenb..];
    //if (end - seckey < len) {
    if seckey.len() < len {
        return false;
    }
    /* sequence element 0: version number (=1) */
    //if (end - seckey < 3 || seckey[0] != 0x02u || seckey[1] != 0x01u || seckey[2] != 0x01u) {
    if seckey.len() < 3 || seckey[0] != 0x02u8 || seckey[1] != 0x01u8 || seckey[2] != 0x01u8 {
        return false;
    }
    //seckey += 3;
    seckey = &seckey[3..];
    /* sequence element 1: octet string, up to 32 bytes */
    //if (end - seckey < 2 || seckey[0] != 0x04u) {
    if seckey.len() < 2 || seckey[0] != 0x04u8 {
        return false;
    }
    let oslen = seckey[1] as usize;
    //seckey += 2;
    seckey = &seckey[2..];
    //if (oslen > 32 || end - seckey < oslen) {
    if oslen > 32 || seckey.len() < oslen {
        return false;
    }
    //memcpy(out32 + (32 - oslen), seckey, oslen);
    out32[32 - oslen..].copy_from_slice(&seckey[..oslen]);
    if !secp256k1_ec_seckey_verify(ctx, out32) {
        //memset(out32, 0, 32);
        *out32 = [0u8; 32];
        return false;
    }
    return true;
}

/**
 * This serializes to a DER encoding of the ECPrivateKey type from section C.4 of SEC 1
 * <https://www.secg.org/sec1-v2.pdf>. The optional parameters and publicKey fields are
 * included.
 *
 * seckey must point to an output buffer of length at least CKey::SIZE bytes.
 * seckeylen must initially be set to the size of the seckey buffer. Upon return it
 * will be set to the number of bytes used in the buffer.
 * key32 must point to a 32-byte raw private key.
 */
//int ec_seckey_export_der(const secp256k1_context *ctx, unsigned char *seckey, size_t *seckeylen, const unsigned char *key32, bool compressed) {
fn ec_seckey_export_der(ctx: &secp256k1_context, seckey: &mut [u8], seckeylen: &mut usize, key32: &[u8; 32], compressed: bool) -> bool {
    assert!(*seckeylen >= CKey::SIZE);
    let mut pubkey: secp256k1_pubkey;
    let mut pubkeylen: usize = 0;
    if !secp256k1_ec_pubkey_create(ctx, &mut pubkey, key32) {
        *seckeylen = 0;
        return false;
    }
    if compressed {
        //static const unsigned char begin[] = {
        let begin: [u8; 8] = [ 0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20 ];
        let middle: [u8; 141] = [
            0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
        ];
        //unsigned char *ptr = seckey;
        let mut ptr = seckey;
        //memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        ptr.copy_from_slice(&begin[..]); ptr = &mut ptr[begin.len()..];
        //memcpy(ptr, key32, 32); ptr += 32;
        ptr.copy_from_slice(&key32[..]); ptr = &mut ptr[key32.len()..];
        //memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        ptr.copy_from_slice(&middle[..]); ptr = &mut ptr[middle.len()..];

        pubkeylen = CPubKey::COMPRESSED_SIZE;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &mut pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
        //ptr += pubkeylen;
        ptr = &mut ptr[pubkeylen..];
        //*seckeylen = ptr - seckey;
        *seckeylen = ptr.as_ptr() as usize - seckey.as_ptr() as usize;
        assert!(*seckeylen == CKey::COMPRESSED_SIZE);
    } else {
        let begin: [u8; 9] = [
            0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20
        ];
        let middle: [u8; 173] = [
            0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
            0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
            0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
        ];
        //unsigned char *ptr = seckey;
        let mut ptr = seckey;
        //memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        ptr.copy_from_slice(&begin[..]); ptr = &mut ptr[begin.len()..];
        //memcpy(ptr, key32, 32); ptr += 32;
        ptr.copy_from_slice(&key32[..]); ptr = &mut ptr[key32.len()..];
        //memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        ptr.copy_from_slice(&middle[..]); ptr = &mut ptr[middle.len()..];
        pubkeylen = CPubKey::SIZE;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &mut pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        //ptr += pubkeylen;
        ptr = &mut ptr[pubkeylen..];
        *seckeylen = ptr.len() - seckey.len();
        assert!(*seckeylen == CKey::SIZE);
    }
    return true;
}

pub struct CKey {
    fValid: bool,
    fCompressed: bool,
    keydata: [u8; 32],
    secp256k1_context_sign: secp256k1_context,
}

impl CKey {
    const SIZE: usize = 279;
    const COMPRESSED_SIZE: usize = 214;

    fn new() -> CKey {
        CKey {
            fValid: false,
            fCompressed: false,
            keydata: [0; 32],
            secp256k1_context_sign: secp256k1_context::new(),
        }
    }

    pub fn set(&mut self, vch: &[u8; 32], fCompressedIn: bool) {
        if vch.len() != self.keydata.len() {
            self.fValid = false;
        } else if self.Check(vch) {
            self.keydata.copy_from_slice(vch);
            self.fValid = true;
            self.fCompressed = fCompressedIn;
        } else {
            self.fValid = false;
        }
    }

    pub fn Check(&self, vch: &[u8; 32]) -> bool {
        secp256k1_ec_seckey_verify(&self.secp256k1_context_sign, vch)
    }

    pub fn MakeNewKey(&mut self, fCompressedIn: bool) {
        loop  {
            GetStrongRandBytes(&mut self.keydata[..]);
            if !self.Check(&self.keydata) {
                break;
            }
        };
        self.fValid = true;
        self.fCompressed = fCompressedIn;   
    }

    pub fn Negate(&self) -> bool
    {
        assert!(self.fValid);
        return secp256k1_ec_seckey_negate(&self.secp256k1_context_sign, &mut self.keydata) == 0;
    }
    

    fn GetPrivKey(&self) -> CPrivKey {
        assert!(self.fValid);
        let mut seckey: CPrivKey;
        let mut seckeylen: usize;

        seckey.resize(Self::SIZE);
        seckeylen = Self::SIZE;
        let ret = ec_seckey_export_der(&self.secp256k1_context_sign, seckey.data(), &mut seckeylen, &self.keydata, self.fCompressed);
        assert!(ret);
        seckey.resize(seckeylen);
        return seckey;
    }
    
    fn GetPubKey(&self) -> CPubKey {
        assert!(self.fValid);
        let mut pubkey: secp256k1_pubkey;
        let mut clen: usize = CPubKey::SIZE;
        let mut result: CPubKey;
        let ret = secp256k1_ec_pubkey_create(&self.secp256k1_context_sign, &mut pubkey, &self.keydata);
        assert!(ret);
        let flags = if self.fCompressed { SECP256K1_EC_COMPRESSED } else { SECP256K1_EC_UNCOMPRESSED };
        secp256k1_ec_pubkey_serialize(&self.secp256k1_context_sign, &mut result.data, &mut clen, &pubkey, flags);
        //assert(result.size() == clen);
        //assert(result.IsValid());
        return result;
    }
    
}
