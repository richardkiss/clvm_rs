//! Generator processing API for Chia consensus.
//!
//! This module provides the main entry point for processing CLVM generators:
//! - Intern the tree (deduplicate atoms and pairs)
//! - Compute SHA256 tree hash
//! - Extract statistics for cost calculation
//!
//! ## Cost Formula (Post-Hardfork)
//!
//! The cost formula is designed to protect against both memory and CPU DoS attacks
//! by splitting cost 50/50 between size-based and SHA256-based components:
//!
//! ```text
//! size_component = B×atom_bytes + A×atom_count + P×pair_count
//! sha_component  = S×sha_blocks + I×sha_invocations
//!
//! total_cost = size_component × SIZE_COST_PER_BYTE
//!            + sha_component × SHA_COST_PER_UNIT
//! ```
//!
//! Where:
//! - B=1, A=2, P=2 (size coefficients)
//! - S=1, I=8 (SHA coefficients, ratio from empirical benchmarking)
//! - SIZE_COST_PER_BYTE = 6000 (half of old COST_PER_BYTE)
//! - SHA_COST_PER_UNIT = 4500 (fitted to maintain backward compatibility)
//!
//! ## Note
//!
//! This module is Chia-specific and will migrate to `chia_rs`.

use crate::allocator::{Allocator, NodePtr};
use crate::serde::bytes32::Bytes32;
use crate::serde::intern::{intern, InternedStats, InternedTree};
use crate::serde::node_from_bytes_backrefs;
use crate::serde::EvalErr;

type Result<T> = std::result::Result<T, EvalErr>;

// =============================================================================
// Chia-specific Cost Formula Constants
// =============================================================================

/// Size coefficient for atom bytes (B).
/// Each byte of atom data contributes 1 unit to size component.
pub const COEF_B: u64 = 1;

/// Size coefficient for atom count (A).
/// Per-atom overhead (length prefix, structural overhead).
pub const COEF_A: u64 = 2;

/// Size coefficient for pair count (P).
/// Per-pair structural overhead.
pub const COEF_P: u64 = 2;

/// SHA coefficient for block count (S).
/// Cost per SHA256 64-byte block processed.
pub const COEF_S: u64 = 1;

/// SHA coefficient for invocation count (I).
/// Cost per SHA256 invocation (setup/finalize overhead).
/// Ratio of ~8× vs block cost determined by empirical benchmarking.
pub const COEF_I: u64 = 8;

/// Cost multiplier for size component.
/// This is half of the old COST_PER_BYTE (12000) to achieve 50% size / 50% SHA split.
pub const SIZE_COST_PER_BYTE: u64 = 6000;

/// Cost multiplier for SHA component.
/// Fitted against real generators to maintain backward compatibility
/// (total cost ≈ old cost for typical generators).
pub const SHA_COST_PER_UNIT: u64 = 4500;

// =============================================================================
// Chia-specific Cost Calculation Functions
// =============================================================================

/// Compute the size component of the cost formula.
///
/// Formula: `B×atom_bytes + A×atom_count + P×pair_count`
#[inline]
pub fn size_cost(stats: &InternedStats) -> u64 {
    COEF_B * stats.atom_bytes + COEF_A * stats.atom_count + COEF_P * stats.pair_count
}

/// Compute the SHA256 component of the cost formula.
///
/// Formula: `S×sha_blocks + I×sha_invocations`
#[inline]
pub fn sha_cost(stats: &InternedStats) -> u64 {
    COEF_S * stats.sha_blocks() + COEF_I * stats.sha_invocations()
}

/// Compute the total cost using the blended formula.
///
/// Formula:
/// ```text
/// total_cost = size_cost × SIZE_COST_PER_BYTE
///            + sha_cost × SHA_COST_PER_UNIT
/// ```
#[inline]
pub fn total_cost(stats: &InternedStats) -> u64 {
    size_cost(stats) * SIZE_COST_PER_BYTE + sha_cost(stats) * SHA_COST_PER_UNIT
}

// =============================================================================
// Generator Processing API
// =============================================================================

/// Result of processing a generator.
///
/// Contains everything needed for validation and cost calculation:
/// - The interned tree (canonical representation)
/// - The SHA256 tree hash (identity)
/// - Statistics for fee calculation
#[derive(Debug)]
pub struct GeneratorInfo {
    /// The interned tree containing only unique nodes
    pub tree: InternedTree,
    /// SHA256 tree hash of the generator
    pub tree_hash: Bytes32,
    /// Statistics for cost calculation
    pub stats: InternedStats,
}

impl GeneratorInfo {
    /// Compute the total cost for this generator.
    #[inline]
    pub fn total_cost(&self) -> u64 {
        total_cost(&self.stats)
    }
}

/// Process a generator: intern, hash, and extract statistics.
///
/// This is the main entry point for generator validation. It:
/// 1. Interns the tree (single pass - deduplicates atoms and pairs)
/// 2. Computes the SHA256 tree hash
/// 3. Extracts statistics for cost calculation
///
/// # Arguments
/// * `allocator` - The source allocator containing the deserialized generator
/// * `node` - The root node of the generator
///
/// # Returns
/// A `GeneratorInfo` containing the interned tree, hash, and statistics.
pub fn process_generator(allocator: &Allocator, node: NodePtr) -> Result<GeneratorInfo> {
    let tree = intern(allocator, node)?;
    let stats = tree.stats();
    let tree_hash = tree.tree_hash();

    Ok(GeneratorInfo {
        tree,
        tree_hash,
        stats,
    })
}

/// Get just the interned statistics (for cost calculation without tree hash).
///
/// This is a lighter-weight version of `process_generator` that skips
/// computing the tree hash.
pub fn intern_stats(allocator: &Allocator, node: NodePtr) -> Result<InternedStats> {
    let tree = intern(allocator, node)?;
    Ok(tree.stats())
}

/// Simplest API: compute generator cost and tree hash.
///
/// This is the primary function for post-hardfork validation.
///
/// # Returns
/// A tuple of `(total_cost, tree_hash)`.
pub fn generator_cost_and_hash(allocator: &Allocator, node: NodePtr) -> Result<(u64, Bytes32)> {
    let info = process_generator(allocator, node)?;
    Ok((info.total_cost(), info.tree_hash))
}

/// Compute cost and tree hash directly from serialized bytes.
///
/// This is a convenience function that deserializes (with backrefs),
/// interns, and computes cost + tree hash in one call.
///
/// # Arguments
/// * `blob` - CLVM-serialized bytes (with backref support)
///
/// # Returns
/// A tuple of `(total_cost, tree_hash)`.
pub fn cost_and_tree_hash_for_bytes(blob: &[u8]) -> Result<(u64, Bytes32)> {
    let mut allocator = Allocator::new();
    let node = node_from_bytes_backrefs(&mut allocator, blob)?;
    generator_cost_and_hash(&allocator, node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serde::node_from_bytes;

    #[test]
    fn test_empty_atom() {
        let allocator = Allocator::new();
        let node = allocator.nil();

        let info = process_generator(&allocator, node).unwrap();

        assert_eq!(info.stats.atom_count, 1);
        assert_eq!(info.stats.pair_count, 0);
        assert_eq!(info.stats.atom_bytes, 0);
        assert_eq!(info.stats.sha_atom_blocks, 1);
        assert_eq!(info.stats.sha_invocations(), 1);
    }

    #[test]
    fn test_simple_pair() {
        let mut allocator = Allocator::new();
        let left = allocator.new_atom(&[1, 2, 3]).unwrap();
        let right = allocator.new_atom(&[4, 5, 6]).unwrap();
        let node = allocator.new_pair(left, right).unwrap();

        let info = process_generator(&allocator, node).unwrap();

        assert_eq!(info.stats.atom_count, 2);
        assert_eq!(info.stats.pair_count, 1);
        assert_eq!(info.stats.atom_bytes, 6);
        assert_eq!(info.stats.sha_pair_blocks(), 2);
        assert_eq!(info.stats.sha_invocations(), 3);
    }

    #[test]
    fn test_shared_subtree() {
        let mut allocator = Allocator::new();
        let atom = allocator.new_atom(&[42]).unwrap();
        let node = allocator.new_pair(atom, atom).unwrap();

        let info = process_generator(&allocator, node).unwrap();

        assert_eq!(info.stats.atom_count, 1);
        assert_eq!(info.stats.pair_count, 1);
        assert_eq!(info.stats.atom_bytes, 1);
    }

    #[test]
    fn test_intern_stats_only() {
        let mut allocator = Allocator::new();
        let atom = allocator.new_atom(&[1, 2, 3, 4, 5]).unwrap();
        let node = allocator.new_pair(atom, allocator.nil()).unwrap();

        let stats = intern_stats(&allocator, node).unwrap();

        assert_eq!(stats.atom_count, 2);
        assert_eq!(stats.pair_count, 1);
        assert_eq!(stats.atom_bytes, 5);
    }

    #[test]
    fn test_large_atom_sha_blocks() {
        let mut allocator = Allocator::new();
        let atom = allocator.new_atom(&[0u8; 100]).unwrap();

        let stats = intern_stats(&allocator, atom).unwrap();

        assert_eq!(stats.atom_count, 1);
        assert_eq!(stats.atom_bytes, 100);
        assert_eq!(stats.sha_atom_blocks, 2);
    }

    #[test]
    fn test_tree_hash_deterministic() {
        let mut alloc1 = Allocator::new();
        let a1 = alloc1.new_atom(&[1, 2, 3]).unwrap();
        let b1 = alloc1.new_atom(&[4, 5, 6]).unwrap();
        let node1 = alloc1.new_pair(a1, b1).unwrap();

        let mut alloc2 = Allocator::new();
        let a2 = alloc2.new_atom(&[1, 2, 3]).unwrap();
        let b2 = alloc2.new_atom(&[4, 5, 6]).unwrap();
        let node2 = alloc2.new_pair(a2, b2).unwrap();

        let info1 = process_generator(&alloc1, node1).unwrap();
        let info2 = process_generator(&alloc2, node2).unwrap();

        assert_eq!(info1.tree_hash, info2.tree_hash);
        assert_eq!(info1.stats, info2.stats);
    }

    #[test]
    fn test_from_serialized_bytes() {
        let bytes = hex::decode("ff8568656c6c6f85776f726c64").unwrap();
        let mut allocator = Allocator::new();
        let node = node_from_bytes(&mut allocator, &bytes).unwrap();

        let info = process_generator(&allocator, node).unwrap();

        assert_eq!(info.stats.atom_count, 2);
        assert_eq!(info.stats.pair_count, 1);
        assert_eq!(info.stats.atom_bytes, 10);
    }
}
