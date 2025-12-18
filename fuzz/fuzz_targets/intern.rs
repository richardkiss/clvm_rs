#![no_main]

use clvm_fuzzing::make_tree;
use clvmr::allocator::Allocator;
use clvmr::serde::{create_interned_node, node_to_bytes};
use clvmr::serde::{treehash, ObjectCache};
use libfuzzer_sys::fuzz_target;

// Fuzzer for the interning functionality
// Verifies that:
// 1. Interning succeeds on valid nodes
// 2. The interned node serializes to the same bytes as the original
// 3. Interned nodes have fewer or equal unique atoms/pairs (deduplication works)
fuzz_target!(|data: &[u8]| {
    let mut unstructured = arbitrary::Unstructured::new(data);
    let mut allocator = Allocator::new();
    let (program, _) = make_tree(&mut allocator, &mut unstructured);

    // Serialize the original node
    let original_serialized = match node_to_bytes(&allocator, program) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Calculate tree hash for the original node
    fn treehash_for_node(allocator: &Allocator, node: clvmr::allocator::NodePtr) -> [u8; 32] {
        let mut object_cache = ObjectCache::new(treehash);
        let stop_token = None;
        *object_cache
            .get_or_calculate(allocator, &node, stop_token)
            .unwrap()
    }
    let original_treehash = treehash_for_node(&allocator, program);

    // Create interned version
    let (new_allocator, interned_node, intern_atom_count, intern_pair_count) =
        match create_interned_node(&allocator, program) {
            Ok(result) => result,
            Err(_) => return,
        };

    // Serialize the interned node
    let interned_serialized = match node_to_bytes(&new_allocator, interned_node) {
        Ok(b) => b,
        Err(_) => panic!("Interned node should serialize successfully"),
    };

    // The serializations must match
    assert_eq!(
        original_serialized, interned_serialized,
        "Serialized bytes differ after interning"
    );

    // Calculate tree hash for the interned node
    let interned_treehash: [u8; 32] = treehash_for_node(&new_allocator, interned_node);

    // The tree hashes must match
    assert_eq!(
        original_treehash, interned_treehash,
        "Tree hashes differ after interning"
    );

    // Interning should not increase atom/pair counts (deduplication)
    let original_atoms = allocator.atom_count() + allocator.small_atom_count();
    let original_pairs = allocator.pair_count_no_ghosts();

    assert!(
        intern_atom_count <= original_atoms,
        "Interning increased atoms: {} -> {}",
        original_atoms,
        intern_atom_count
    );
    assert!(
        intern_pair_count <= original_pairs,
        "Interning increased pairs: {} -> {}",
        original_pairs,
        intern_pair_count
    );
});
