// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

    fn shl(self, _rhs:T) -> Self::Output
    {
        // TODO: figure out what to do here
        //Serialize(self.S, rhs);
        self
    } 

}