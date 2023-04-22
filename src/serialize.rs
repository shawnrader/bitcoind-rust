use std::ops::ShlAssign;
use std::ops::Add;

pub enum SER {
    // primary actions
    NETWORK         = (1 << 0),
    DISK            = (1 << 1),
    GETHASH         = (1 << 2),
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

    pub fn from_u32(&mut self, x: u32) {
        self.v = x.to_le_bytes().to_vec();
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
    use std::ops::Shl;
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
            let mut s = Ser::new();
            self.ser.from_u32(self.v);
            self.ser()
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

    impl Shl for TestSer {
        type Output = Ser;
        fn shl(self, s: TestSer) -> Ser
        {
            self.ser();
            self.ser_push(&s.ser());
            self.ser()   
        }
    }

    #[test]
    fn test_serializer() {
        assert!(2 + 2 == 4);
        let a = TestSer::new(42);
        let b = TestSer::new(69);
        let mut c = Ser::new();
        c <<= a;
        c <<= b;
        assert!(c.to_vec() == vec![42, 0, 0, 0, 69, 0, 0, 0]);
        c = Ser::new();
        c <<= a <<= b;
    
    }

}