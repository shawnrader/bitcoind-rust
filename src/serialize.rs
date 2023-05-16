// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use std::ops::{Shl, ShlAssign};
use std::ops::Add;

pub enum SER {
    // primary actions
    NETWORK         = (1 << 0),
    DISK            = (1 << 1),
    GETHASH         = (1 << 2),
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

#[derive(Debug)]
struct Wrapper<T> {
    value: T,
}

impl<T> Wrapper<T>
where
    T: Add<Output = T>,
{
    fn new(value: T) -> Self {
        Wrapper { value }
    }
}

impl<T> Add for Wrapper<T>
where
    T: Add<Output = T>,
{
    type Output = Wrapper<T>;

    fn add(self, other: Wrapper<T>) -> Wrapper<T> {
        Wrapper {
            value: self.value + other.value,
        }
    }
}

#[derive(Debug, Clone)]
struct Ser {
    v: Vec<u8>,
}

impl Ser {
    fn new() -> Self {
        Ser { v: Vec::new() }
    }

    pub fn append(&mut self, s: &Ser)
    {
        println!("append: {:?} and {:?}", self.v, s.to_vec());
        self.v.append(&mut s.to_vec());
        println!("append result: {:?}", self.v);
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.v.clone()
    }

    pub fn from_u32(x: u32) -> Self {
        Ser { v: x.to_le_bytes().to_vec() }
    }
}

impl Shl for Ser {
    type Output = Ser;
    fn shl(self, s: Ser) -> Ser
    {
        let mut result = Ser::new();
        result.append(&self);
        result.append(&s);
        result
    }
}


trait Serializer {
    fn ser(&self) -> Ser;
    fn deser(&mut self, data: &[u8]) -> Result<(), String>;
    fn ser_push(&mut self, s: &Ser);
}

impl<T> ShlAssign<T> for Ser  where T: Serializer {

    fn shl_assign(&mut self, s: T)
    {
        self.append(&mut s.ser());
    }
}

mod tests {
    use super::Serializer;
    use super::Ser;

    
    struct TestSer {
        v: u32,
        ser: Ser,
    }

    impl TestSer {
        fn new(v: u32) -> Self {
            TestSer { v, ser: Ser::new() }
        }
    }

    impl Serializer for TestSer {
        fn ser(&self) -> Ser {
            Ser::from_u32(self.v)
        }

        fn deser(&mut self, data: &[u8]) -> Result<(), String> {
            if data.len() != 4 {
                return Err("Invalid data length".to_string());
            }
            self.v = u32::from_le_bytes(data.try_into().unwrap());
            Ok(())
        }

        fn ser_push(&mut self, s: &Ser) {
            self.ser.append(s);
        }
    }

    #[test]
    fn test_serializer() {
        assert!(2 + 2 == 4);
        let a = TestSer::new(42);
        let b = TestSer::new(69);
        let c = TestSer::new(7);
        let mut d = Ser::new();
        //c <<= a;
        //c <<= b;
        //assert!(c.to_vec() == vec![42, 0, 0, 0, 69, 0, 0, 0]);
        d = a.ser() << b.ser() << c.ser();
        assert!(d.to_vec() == vec![42, 0, 0, 0, 69, 0, 0, 0, 7, 0, 0, 0]);
    }

}