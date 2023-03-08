use primitive_types::U256;

//const unsigned int BIP32_EXTKEY_SIZE = 74;
pub const BIP32_EXTKEY_SIZE: u32 = 74;
//const unsigned int BIP32_EXTKEY_WITH_VERSION_SIZE = 78;
pub const BIP32_EXTKEY_WITH_VERSION_SIZE: u32 = 78;

pub const SIZE: usize = 65;
pub const COMPRESSED_SIZE: usize = 33;
pub const SIGNATURE_SIZE: usize = 72;
pub const COMPACT_SIGNATURE_SIZE: usize = 65;

/** A reference to a CKey: the Hash160 of its serialized public key */
//class CKeyID : public uint160
//{
//public:
//    CKeyID() : uint160() {}
//    explicit CKeyID(const uint160& in) : uint160(in) {}
//};

//typedef uint256 ChainCode;
type ChainCode = U256;

/* unsigned int static GetLen(unsigned char chHeader)
{
    if (chHeader == 2 || chHeader == 3)
        return COMPRESSED_SIZE;
    if (chHeader == 4 || chHeader == 6 || chHeader == 7)
        return SIZE;
    return 0;
} */
/// Compute the length of a pubkey with a given first byte.
// unsigned int static GetLen(unsigned char chHeader)
pub fn GetLen(chHeader: u8) -> usize
{
    if chHeader == 2 || chHeader == 3
    {
        COMPRESSED_SIZE
    }
    if chHeader == 4 || chHeader == 6 || chHeader == 7
    {
        SIZE
    }
    0
}

//bool static ValidSize(const std::vector<unsigned char> &vch) {
pub fn ValidSize(vch: &Vec<u8>) -> bool
{
    vch.len() > 0 && GetLen(vch[0]) == vch.len()
}

/** An encapsulated public key. */
pub struct CPubKey {
    vch: [u8; SIZE],
}