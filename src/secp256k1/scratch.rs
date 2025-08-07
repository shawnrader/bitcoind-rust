#![allow(warnings)]
/* The typedef is used internally; the struct name is used in the public API
 * (where it is exposed as a different typedef) */
pub struct secp256k1_scratch<'a> {
    magic: [u8; 8],
    data: &'a mut [u8],
    alloc_size: usize,
    max_size: usize,
}