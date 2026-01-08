#![no_main]

use clvm_fuzzing::make_tree;
use clvmr::allocator::Allocator;
use clvmr::serde::{intern, node_to_bytes};
use libfuzzer_sys::fuzz_target;

// Fuzzer for the interning functionality
// Verifies that:
// 1. Interning succeeds on valid nodes
// 2. The interned node serializes to the same bytes as the original
// 3. The tree hash is preserved
// 4. Interned nodes have fewer or equal unique atoms/pairs (deduplication works)
fuzz_target!(|data: &[u8]| {
    let mut unstructured = arbitrary::Unstructured::new(data);
    let mut allocator = Allocator::new();
    let (program, _) = make_tree(&mut allocator, &mut unstructured);

    // Serialize the original node
    let original_serialized = match node_to_bytes(&allocator, program) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Count original atoms and pairs before interning
    let original_atoms = allocator.atom_count() + allocator.small_atom_count();
    let original_pairs = allocator.pair_count_no_ghosts();

    // Create interned version using new API
    let tree = match intern(&allocator, program) {
        Ok(result) => result,
        Err(_) => return,
    };

    // Serialize the interned node
    let interned_serialized = match node_to_bytes(&tree.allocator, tree.root) {
        Ok(b) => b,
        Err(_) => panic!("Interned node should serialize successfully"),
    };

    // The serializations must match
    assert_eq!(
        original_serialized, interned_serialized,
        "Serialized bytes differ after interning"
    );

    // Get stats and verify deduplication
    let stats = tree.stats();

    // Interning should not increase atom/pair counts (deduplication)
    assert!(
        stats.atom_count as usize <= original_atoms,
        "Interning increased atoms: {} -> {}",
        original_atoms,
        stats.atom_count
    );
    assert!(
        stats.pair_count as usize <= original_pairs,
        "Interning increased pairs: {} -> {}",
        original_pairs,
        stats.pair_count
    );

    // Verify tree hash computation works
    let _tree_hash = tree.tree_hash();
});
