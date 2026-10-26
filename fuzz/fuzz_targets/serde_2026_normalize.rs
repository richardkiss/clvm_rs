#![no_main]

use clvmr::Allocator;
use clvmr::serde::{ObjectCache, treehash};
use clvmr::serde_2026::{SERDE_2026_MAGIC_PREFIX, deserialize_2026, normalize_varints};
use libfuzzer_sys::fuzz_target;

const FUZZ_MAX_ATOM_LEN: usize = 1 << 20;

fn hash(blob: &[u8]) -> Option<[u8; 32]> {
    let mut a = Allocator::new();
    let node = deserialize_2026(&mut a, blob, FUZZ_MAX_ATOM_LEN, false).ok()?;
    let mut cache = ObjectCache::new(treehash);
    Some(*cache.get_or_calculate(&a, &node, None)?)
}

fuzz_target!(|data: &[u8]| {
    let blob = [&SERDE_2026_MAGIC_PREFIX[..], data].concat();
    let Ok(normalized) = normalize_varints(&blob) else {
        return;
    };
    assert!(normalized.len() <= blob.len());
    assert_eq!(normalize_varints(&normalized).unwrap(), normalized);
    if let Some(h) = hash(&blob) {
        assert_eq!(hash(&normalized), Some(h));
    }
});
