//! Temporary cost calculation module.
//! Should eventually move to chia_rs.

use crate::allocator::{Allocator, NodePtr};
use crate::error::Result;
use crate::serde::de_br::node_from_bytes_backrefs;
use crate::serde::intern::create_interned_node;
use crate::serde::object_cache::{treehash, ObjectCache};
use crate::serde::serialized_length_atom;

/// Cost per 64-byte SHA256 block processed during treehashing.
/// This represents the computational cost of processing one block through SHA256.
const COST_PER_SHA_BLOCK: u64 = 3;

/// Cost per SHA256 finalization (invocation).
/// This represents the overhead cost of calling SHA256 finalization.
const COST_PER_SHA_INVOCATION: u64 = 10;

/// Cost per byte in the serialized representation.
/// This represents the cost of storing and processing serialized data.
const COST_PER_SERIALIZED_BYTE: u64 = 1;

/// Calculates the SHA256 processing cost for treehashing interned nodes.
///
/// Returns `(sha_block_count, sha_invocation_count)` where:
/// - `sha_block_count` is the total number of 64-byte SHA256 blocks processed.
/// - `sha_invocation_count` is the number of times SHA256 finalization is called.
///
/// Uses visit counts from the interned tree traversal.
pub fn tree_hash_cost(allocator: &Allocator, node_info: &[(NodePtr, usize)]) -> (usize, usize) {
    let mut sha_block_count = 0usize;
    let mut sha_invocation_count = 0usize;

    for (node, count) in node_info.iter() {
        if node.is_atom() {
            let size = allocator.atom_len(*node);
            // +9 bytes for SHA256 padding overhead (0x80 marker + 8-byte length)
            let blocks = (size + 9) / 64;
            sha_block_count += blocks * (*count);
        } else {
            // Serialized pairs are small enough to always fit in 2 SHA256 blocks
            sha_block_count += 2 * (*count);
        }
        sha_invocation_count += *count;
    }

    (sha_block_count, sha_invocation_count)
}
/// Counts serialization-related statistics for a node and its children.
///
/// Analyzes the structure of interned nodes to determine serialization costs.
///
/// # Arguments
/// * `allocator` - The allocator containing the interned nodes
/// * `node_info` - Slice of (NodePtr, visit_count) pairs representing the node structure
///
/// # Returns
/// A tuple of `(total_atom_serialization, atom_backref_count, pair_count)` where:
/// - `total_atom_serialization` is the total bytes needed to serialize all atoms
/// - `atom_backref_count` is the number of atom back-references (duplicates)
/// - `pair_count` is the number of pair nodes
fn counts_for_serialization(
    allocator: &Allocator,
    node_info: &[(NodePtr, usize)],
) -> (u64, u64, u64) {
    let mut total_atom_serialization = 0u64;
    let mut atom_backref_count = 0u64;
    let mut pair_count = 0u64;
    for (node, count) in node_info.iter() {
        if node.is_atom() {
            let size = serialized_length_atom(allocator.atom(*node).as_ref()) as u64;
            // we don't multiple by count here because
            // we're charging for compressed amounts
            total_atom_serialization += size;
            atom_backref_count += (*count - 1) as u64;
        } else {
            pair_count += 1;
        }
    }
    (total_atom_serialization, atom_backref_count, pair_count)
}

/// Calculates an upper bound for the size cost of serializing a node structure.
///
/// This function estimates the cost based on the serialized representation,
/// accounting for atom data, back-references, and pair structures.
/// The bound assumes maximum size for length prefixes (0xfd format with 3 bytes).
///
/// # Arguments
/// * `allocator` - The allocator containing the interned nodes
/// * `node_info` - Slice of (NodePtr, visit_count) pairs representing the node structure
///
/// # Returns
/// An upper bound on the total serialization cost in bytes
fn upper_bound_size_cost(allocator: &Allocator, node_info: &[(NodePtr, usize)]) -> u64 {
    let (atom_serialization_byte_count, atom_backrefs, pair_count) =
        counts_for_serialization(allocator, node_info);
    let mut total = 0;
    total += 4; // for the count of atoms
    total += atom_serialization_byte_count; // for the serialized atoms
    total += 4 * atom_backrefs; // for the backref indices. 0xfd + up to three bytes
    total += 4; // for the count of pairs
    total += 8 * pair_count; // for the pairs themselves (4 bytes each for left and right)
    total
}

/// Computes the total cost estimate and treehash for a CLVM-serialized byte blob.
///
/// This function deserializes a CLVM blob, interns it to identify duplicate structures,
/// and calculates the total cost based on:
/// - SHA256 processing cost for treehashing
/// - Serialization overhead cost
/// - Per-byte cost of the serialized representation
///
/// # Arguments
/// * `blob` - A slice containing CLVM-serialized data (with back-references)
///
/// # Returns
/// A result containing:
/// - `u64` - The calculated cost estimate
/// - `[u8; 32]` - The SHA256 treehash of the structure
///
/// # Errors
/// Returns an error if:
/// - The blob cannot be deserialized
/// - Interning the node fails
/// - Treehash calculation fails (panics via expect)
pub fn cost_and_tree_hash_for_bytes(blob: &[u8]) -> Result<(u64, [u8; 32])> {
    let mut allocator = Allocator::new();
    let node = node_from_bytes_backrefs(&mut allocator, blob)?;
    let (interned_allocator, interned_node, node_info) = create_interned_node(&allocator, node)?;

    let mut obj_cache = ObjectCache::new(treehash);
    let th = obj_cache
        .get_or_calculate(&interned_allocator, &interned_node, None)
        .expect("treehash calculation failed");

    let (sha_blocks, sha_invocations) = tree_hash_cost(&interned_allocator, &node_info);

    let mut cost = 0u64;
    cost += COST_PER_SHA_BLOCK * (sha_blocks as u64);
    cost += COST_PER_SHA_INVOCATION * (sha_invocations as u64);

    let byte_count = upper_bound_size_cost(&interned_allocator, &node_info);
    cost += COST_PER_SERIALIZED_BYTE * byte_count;

    Ok((cost, *th))
}
