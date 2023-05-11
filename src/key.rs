use crate::random::GetStrongRandBytes;
use crate::secp256k1::{secp256k1_ec_seckey_verify, secp256k1_context};

struct CKey {
    fValid: bool,
    fCompressed: bool,
    keydata: [u8; 32],
    secp256k1_context_sign: secp256k1_context,
}

impl CKey {
    const SIZE: i32 = 279;
    const COMPRESSED_SIZE: i32 = 214;

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
        secp256k1_ec_seckey_verify(&self.secp256k1_context_sign, vch) == 0
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
    
}
