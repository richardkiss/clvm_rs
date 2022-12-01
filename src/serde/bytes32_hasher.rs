use std::hash::{BuildHasher, Hasher};

#[derive(Debug)]
pub struct Bytes32Hasher {
    the_hash: [u8; 8],
}

impl Bytes32Hasher {
    fn new() -> Self {
        let the_hash = [0; 8];
        Bytes32Hasher { the_hash }
    }
}

impl BuildHasher for Bytes32Hasher {
    type Hasher = Bytes32Hasher;
    fn build_hasher(&self) -> <Self as BuildHasher>::Hasher {
        Bytes32Hasher::default()
    }
}

impl Default for Bytes32Hasher {
    fn default() -> Self {
        Bytes32Hasher::new()
    }
}

impl Hasher for Bytes32Hasher {
    fn finish(&self) -> u64 {
        u64::from_le_bytes(self.the_hash)
    }
    fn write(&mut self, bytes: &[u8]) {
        for (i, byte) in bytes.iter().enumerate() {
            self.the_hash[i % 8] ^= byte;
        }
    }
}
