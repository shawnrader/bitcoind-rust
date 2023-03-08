
pub type valtype = Vec<u8>;

/* Signature hash sizes */
pub const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;
pub const WITNESS_V0_KEYHASH_SIZE: usize = 20;
pub const WITNESS_V1_TAPROOT_SIZE: usize = 32;

pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
pub const TAPROOT_CONTROL_MAX_SIZE: usize = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;
