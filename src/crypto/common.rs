use std::io::Cursor;
use byteorder::{ByteOrder, BigEndian, LittleEndian, WriteBytesExt};

//uint16_t static inline ReadLE16(const unsigned char* ptr)
/*{
    uint16_t x;
    memcpy((char*)&x, ptr, 2);
    return le16toh(x);
} */

fn ReadLE16(ptr: &u8) -> u16
{
    let mut rdr = Cursor::new(ptr);
    rdr.read_u16::<LittleEndian>().unwrap()
}

/*
uint32_t static inline ReadLE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy((char*)&x, ptr, 4);
    return le32toh(x);
} */

/*
uint64_t static inline ReadLE64(const unsigned char* ptr)
{
    uint64_t x;
    memcpy((char*)&x, ptr, 8);
    return le64toh(x);
} */

/* 
void static inline WriteLE16(unsigned char* ptr, uint16_t x)
{
    uint16_t v = htole16(x);
    memcpy(ptr, (char*)&v, 2);
} */

/*
void static inline WriteLE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htole32(x);
    memcpy(ptr, (char*)&v, 4);
} */

/*
void static inline WriteLE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htole64(x);
    memcpy(ptr, (char*)&v, 8);
}

uint16_t static inline ReadBE16(const unsigned char* ptr)
{
    uint16_t x;
    memcpy((char*)&x, ptr, 2);
    return be16toh(x);
}

uint32_t static inline ReadBE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy((char*)&x, ptr, 4);
    return be32toh(x);
}

uint64_t static inline ReadBE64(const unsigned char* ptr)
{
    uint64_t x;
    memcpy((char*)&x, ptr, 8);
    return be64toh(x);
}
*/

/* void static inline WriteBE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htobe32(x);
    memcpy(ptr, (char*)&v, 4);
} */
pub fn WriteBE32(ptr: &mut [u8], x: u32)
{
    //let v = x.to_be();
    BigEndian::write_u32(ptr, x);
}

/* void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htobe64(x);
    memcpy(ptr, (char*)&v, 8);
} */
pub fn WriteBE64(ptr: &mut [u8], x: u64)
{
    let v = x.to_be();
    let mut cursor = std::io::Cursor::new(ptr);
    cursor.write_u64::<BigEndian>(v).unwrap();
}
