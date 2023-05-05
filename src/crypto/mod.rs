pub mod common;
pub mod sha256;
pub mod sha512;


pub trait Hasher {
    const OUTPUT_SIZE: usize;
    fn Write(&mut self, data: &[u8], len: usize) -> &mut Self;
    fn Finalize(&mut self, data: &mut [u8]);
    fn Reset(&mut self) -> &mut Self;
}