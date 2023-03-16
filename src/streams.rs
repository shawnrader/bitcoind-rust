use super::serialize::SER;
use std::ops::Shl;

pub struct CDataStream {
    nType: SER,
    nVersion: i32,
}

impl CDataStream {
    pub fn new(nTypeIn: SER, nVersionIn: i32) -> CDataStream
    {
        CDataStream {nType: nTypeIn, nVersion: nVersionIn}
    }
}

impl<T> Shl<T> for CDataStream {
    type Output = Self;

    fn shl(self, rhs:T) -> Self::Output
    {
        // TODO: figure out what to do here
        //Serialize(self.S, rhs);
        self
    } 

}