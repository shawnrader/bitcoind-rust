
struct CKey {
    fValid: bool,
    fCompressed: bool,
    keydata: Vec<u8>,
}

impl CKey {
    const SIZE: i32 = 279;
    const COMPRESSED_SIZE: i32 = 214;

    fn new() -> CKey {
        CKey {
            fValid: false,
            value: String::new(),
        }
    }

    pub fn set(&mut self, vch: &[u8], fCompressedIn: bool) {
        if vch.len() != self.keydata.len() {
            self.fValid = false;
        } else if (Check(vch)) {
            self.keydata = vch;
            self.fValid = true;
            self.fCompressed = fCompressedIn;
        } else {
            self.fValid = false;
        }
    }

    pub fn Check(vch: &Vec<u8>) -> bool {
        todo!();
        //secp256k1_ec_seckey_verify(secp256k1_context_sign, vch)
    }

    pub fn MakeNewKey(fCompressed: bool) {
        loop  {
            GetStrongRandBytes(keydata);
            if !Check(self.keydata) {
                break;
            }
        };
        self.fValid = true;
        self.fCompressed = fCompressedIn;   
    }
    
}
