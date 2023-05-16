// Copyright (c) 2014-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

pub mod common;
pub mod sha256;
pub mod sha512;


pub trait Hasher {
    const OUTPUT_SIZE: usize;
    fn Write(&mut self, data: &mut [u8], len: usize) -> &mut Self;
    fn Finalize(&mut self, data: &mut [u8]);
    fn Reset(&mut self) -> &mut Self;
    fn Size(&self) -> usize;
}