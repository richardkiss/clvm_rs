//! Generator processing API for Chia consensus.
//!
//! This module provides the main entry point for processing CLVM generators:
//! - Intern the tree (deduplicate atoms and pairs)
//! - Compute SHA256 tree hash
//! - Extract cost components for fee calculation
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
//! This module is Chia-specific and will migrate to `chia_rs`. It depends on:
//! - `crate::serde::intern::intern_node` (core CLVM interning)
//! - `crate::serde::object_cache` (tree hash caching)

use crate::allocator::{Allocator, NodePtr, SExp};
use crate::serde::bytes32::Bytes32;
use crate::serde::intern::intern_node;
use crate::serde::object_cache::{treehash, ObjectCache};
use crate::serde::EvalErr;

type Result<T> = std::result::Result<T, EvalErr>;

/// Raw components for cost calculation.
///
/// These are the building blocks for any cost formula. The actual formula
/// can be tuned separately, and these components can be used for DoS testing
/// to ensure the chosen formula isn't exploitable.
///
/// ## Recommended Formula (as of benchmarking)
///
/// ```ignore
/// estimated_len = atom_bytes + 2×atom_count + 2×pair_count
/// cost = estimated_len × COST_PER_BYTE  // COST_PER_BYTE = 12000
/// ```
///
/// ## Example
///
/// ```ignore
/// let info = process_generator(&allocator, node)?;
/// let c = &info.cost_components;
///
/// // The validated formula:
/// let estimated_len = c.atom_bytes + 2 * c.atom_count + 2 * c.pair_count;
/// let cost = estimated_len * 12000;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CostComponents {
    /// Number of unique atoms in the interned tree
    pub atom_count: u64,
    /// Number of unique pairs in the interned tree
    pub pair_count: u64,
    /// Sum of all unique atom byte lengths: Σ(atom_len)
    pub atom_bytes: u64,
    /// SHA256 blocks needed for atoms: Σ(⌈(atom_len + 10) / 64⌉)
    /// The +10 accounts for: 0x01 prefix (1 byte) + SHA256 padding overhead (9 bytes)
    pub sha_atom_blocks: u64,
    /// SHA256 blocks needed for pairs: 2 × pair_count
    /// Each pair hashes: 0x02 (1) + left_hash (32) + right_hash (32) = 65 bytes
    /// With padding: 74 bytes → always 2 blocks
    pub sha_pair_blocks: u64,
}

impl CostComponents {
    /// Total SHA256 blocks (atom blocks + pair blocks)
    ///
    /// Use this for the "block mixing" portion of SHA256 cost.
    #[inline]
    pub fn sha_blocks(&self) -> u64 {
        self.sha_atom_blocks + self.sha_pair_blocks
    }

    /// Total SHA256 invocations (one per unique node)
    ///
    /// Use this for the "setup/finalize" portion of SHA256 cost.
    #[inline]
    pub fn sha_invocations(&self) -> u64 {
        self.atom_count + self.pair_count
    }

    /// Total unique nodes (atoms + pairs)
    #[inline]
    pub fn node_count(&self) -> u64 {
        self.atom_count + self.pair_count
    }

    /// Compute the size component of the cost formula.
    ///
    /// Formula: `B×atom_bytes + A×atom_count + P×pair_count`
    /// With B=1, A=2, P=2.
    #[inline]
    pub fn size_component(&self) -> u64 {
        COEF_B * self.atom_bytes + COEF_A * self.atom_count + COEF_P * self.pair_count
    }

    /// Compute the SHA256 component of the cost formula.
    ///
    /// Formula: `S×sha_blocks + I×sha_invocations`
    /// With S=1, I=8 (ratio from empirical benchmarking).
    #[inline]
    pub fn sha_component(&self) -> u64 {
        COEF_S * self.sha_blocks() + COEF_I * self.sha_invocations()
    }

    /// Compute estimated serialized length using the old formula.
    ///
    /// Formula: `atom_bytes + 2×atom_count + 2×pair_count`
    ///
    /// This approximates what the backref-serialized size would be.
    /// Kept for backward compatibility and comparison.
    #[inline]
    pub fn estimated_len(&self) -> u64 {
        self.atom_bytes + 2 * self.atom_count + 2 * self.pair_count
    }

    /// Compute the total cost using the blended formula.
    ///
    /// This is the post-hardfork cost that protects against both
    /// memory DoS (via size component) and CPU DoS (via SHA component).
    ///
    /// Formula:
    /// ```text
    /// total_cost = size_component × SIZE_COST_PER_BYTE
    ///            + sha_component × SHA_COST_PER_UNIT
    /// ```
    #[inline]
    pub fn total_cost(&self) -> u64 {
        self.size_component() * SIZE_COST_PER_BYTE + self.sha_component() * SHA_COST_PER_UNIT
    }
}

// =============================================================================
// Cost Formula Constants
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

/// Result of processing a generator.
///
/// Contains everything needed for validation and cost calculation:
/// - The interned tree (canonical representation)
/// - The SHA256 tree hash (identity)
/// - Cost components (for fee calculation)
#[derive(Debug)]
pub struct GeneratorInfo {
    /// The interned allocator containing only unique nodes
    pub allocator: Allocator,
    /// Root node in the interned allocator
    pub node: NodePtr,
    /// SHA256 tree hash of the generator
    pub tree_hash: Bytes32,
    /// Raw components for cost calculation
    pub cost_components: CostComponents,
}

/// Process a generator: intern, hash, and extract cost components.
///
/// This is the main entry point for generator validation. It:
/// 1. Interns the tree (deduplicates atoms and pairs)
/// 2. Computes the SHA256 tree hash
/// 3. Extracts cost components
///
/// The returned `GeneratorInfo` contains the canonical interned representation,
/// which should be used for any subsequent operations (e.g., running the generator).
///
/// # Arguments
/// * `allocator` - The source allocator containing the deserialized generator
/// * `node` - The root node of the generator
///
/// # Returns
/// A `GeneratorInfo` containing the interned tree, hash, and cost components.
///
/// # Errors
/// Returns an error if interning fails (e.g., allocator limits exceeded).
pub fn process_generator(allocator: &Allocator, node: NodePtr) -> Result<GeneratorInfo> {
    // Step 1: Intern the tree
    let (interned_allocator, interned_node) = intern_node(allocator, node)?;

    // Step 2: Compute cost components by collecting unique atoms and pairs
    let (atoms, pairs) = collect_unique_nodes(&interned_allocator, interned_node);
    let cost_components = compute_cost_components(&interned_allocator, &atoms, &pairs);

    // Step 3: Compute tree hash
    let tree_hash = compute_tree_hash(&interned_allocator, interned_node);

    Ok(GeneratorInfo {
        allocator: interned_allocator,
        node: interned_node,
        tree_hash,
        cost_components,
    })
}

/// Get just the cost components (for DoS testing).
///
/// This is a lighter-weight version of `process_generator` that skips
/// computing the tree hash. Use this when you only need cost components,
/// e.g., for testing cost formulas against adversarial inputs.
///
/// # Arguments
/// * `allocator` - The source allocator containing the deserialized generator
/// * `node` - The root node of the generator
///
/// # Returns
/// The cost components for the interned tree.
pub fn cost_components(allocator: &Allocator, node: NodePtr) -> Result<CostComponents> {
    let (interned_allocator, interned_node) = intern_node(allocator, node)?;
    let (atoms, pairs) = collect_unique_nodes(&interned_allocator, interned_node);
    Ok(compute_cost_components(&interned_allocator, &atoms, &pairs))
}

/// Simplest API: compute generator cost and tree hash.
///
/// This is the primary function for post-hardfork validation. It:
/// 1. Interns the generator tree
/// 2. Computes the SHA256 tree hash (new identity)
/// 3. Computes the blended cost (protection against DoS)
///
/// # Arguments
/// * `allocator` - The allocator containing the deserialized generator
/// * `node` - The root node of the generator
///
/// # Returns
/// A tuple of `(total_cost, tree_hash)` where:
/// - `total_cost` is the blended cost for fee calculation
/// - `tree_hash` is the SHA256 tree hash (generator identity)
///
/// # Example
///
/// ```ignore
/// let (cost, hash) = generator_cost_and_hash(&allocator, node)?;
/// if cost > max_cost {
///     return Err("generator cost exceeds block limit");
/// }
/// // Use hash as generator identity for caching, validation, etc.
/// ```
pub fn generator_cost_and_hash(allocator: &Allocator, node: NodePtr) -> Result<(u64, Bytes32)> {
    let info = process_generator(allocator, node)?;
    let cost = info.cost_components.total_cost();
    Ok((cost, info.tree_hash))
}

/// Collect unique atoms and pairs from an interned tree.
///
/// Since the tree is already interned, we just need to traverse it once
/// and collect each unique NodePtr we encounter.
fn collect_unique_nodes(allocator: &Allocator, root: NodePtr) -> (Vec<NodePtr>, Vec<NodePtr>) {
    use std::collections::HashSet;

    let mut atoms = Vec::new();
    let mut pairs = Vec::new();
    let mut seen: HashSet<NodePtr> = HashSet::new();
    let mut stack = vec![root];

    while let Some(node) = stack.pop() {
        if !seen.insert(node) {
            continue; // Already processed
        }

        match allocator.sexp(node) {
            SExp::Atom => atoms.push(node),
            SExp::Pair(left, right) => {
                pairs.push(node);
                stack.push(right);
                stack.push(left);
            }
        }
    }

    (atoms, pairs)
}

/// Compute cost components from lists of unique atoms and pairs.
fn compute_cost_components(
    allocator: &Allocator,
    atoms: &[NodePtr],
    pairs: &[NodePtr],
) -> CostComponents {
    let mut components = CostComponents {
        atom_count: atoms.len() as u64,
        pair_count: pairs.len() as u64,
        atom_bytes: 0,
        sha_atom_blocks: 0,
        sha_pair_blocks: 2 * pairs.len() as u64, // Pairs always need 2 blocks
    };

    for &atom in atoms {
        let len = allocator.atom_len(atom) as u64;
        components.atom_bytes += len;
        // SHA256 blocks: ceil((len + 10) / 64) = (len + 73) / 64
        // The +10 is: 0x01 prefix (1) + padding overhead (9)
        components.sha_atom_blocks += (len + 73) / 64;
    }

    components
}

/// Compute SHA256 tree hash for a node.
fn compute_tree_hash(allocator: &Allocator, node: NodePtr) -> Bytes32 {
    let mut cache: ObjectCache<Bytes32> = ObjectCache::new(treehash);
    *cache
        .get_or_calculate(allocator, &node, None)
        .expect("treehash should not fail")
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

        assert_eq!(info.cost_components.atom_count, 1);
        assert_eq!(info.cost_components.pair_count, 0);
        assert_eq!(info.cost_components.atom_bytes, 0);
        assert_eq!(info.cost_components.sha_atom_blocks, 1); // Empty atom still needs 1 block
        assert_eq!(info.cost_components.sha_invocations(), 1);
    }

    #[test]
    fn test_simple_pair() {
        let mut allocator = Allocator::new();
        let left = allocator.new_atom(&[1, 2, 3]).unwrap();
        let right = allocator.new_atom(&[4, 5, 6]).unwrap();
        let node = allocator.new_pair(left, right).unwrap();

        let info = process_generator(&allocator, node).unwrap();

        assert_eq!(info.cost_components.atom_count, 2);
        assert_eq!(info.cost_components.pair_count, 1);
        assert_eq!(info.cost_components.atom_bytes, 6);
        assert_eq!(info.cost_components.sha_pair_blocks, 2);
        assert_eq!(info.cost_components.sha_invocations(), 3);
    }

    #[test]
    fn test_shared_subtree() {
        // Create (A . A) where A is the same atom
        let mut allocator = Allocator::new();
        let atom = allocator.new_atom(&[42]).unwrap();
        let node = allocator.new_pair(atom, atom).unwrap();

        let info = process_generator(&allocator, node).unwrap();

        // Only 1 unique atom, even though it appears twice
        assert_eq!(info.cost_components.atom_count, 1);
        assert_eq!(info.cost_components.pair_count, 1);
        assert_eq!(info.cost_components.atom_bytes, 1);
    }

    #[test]
    fn test_cost_components_only() {
        let mut allocator = Allocator::new();
        let atom = allocator.new_atom(&[1, 2, 3, 4, 5]).unwrap();
        let node = allocator.new_pair(atom, allocator.nil()).unwrap();

        let components = cost_components(&allocator, node).unwrap();

        assert_eq!(components.atom_count, 2); // The 5-byte atom + nil
        assert_eq!(components.pair_count, 1);
        assert_eq!(components.atom_bytes, 5); // Only the non-nil atom has bytes
    }

    #[test]
    fn test_large_atom_sha_blocks() {
        let mut allocator = Allocator::new();
        // 100 byte atom: ceil((100 + 10) / 64) = ceil(110/64) = 2 blocks
        let atom = allocator.new_atom(&[0u8; 100]).unwrap();

        let components = cost_components(&allocator, atom).unwrap();

        assert_eq!(components.atom_count, 1);
        assert_eq!(components.atom_bytes, 100);
        assert_eq!(components.sha_atom_blocks, 2);
    }

    #[test]
    fn test_tree_hash_deterministic() {
        // Same logical structure should produce same hash
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
        assert_eq!(info1.cost_components, info2.cost_components);
    }

    #[test]
    fn test_from_serialized_bytes() {
        // ff8568656c6c6f85776f726c64 = ("hello" . "world")
        let bytes = hex::decode("ff8568656c6c6f85776f726c64").unwrap();
        let mut allocator = Allocator::new(); // mut required by node_from_bytes
        let node = node_from_bytes(&mut allocator, &bytes).unwrap();

        let info = process_generator(&allocator, node).unwrap();

        assert_eq!(info.cost_components.atom_count, 2);
        assert_eq!(info.cost_components.pair_count, 1);
        assert_eq!(info.cost_components.atom_bytes, 10); // "hello" (5) + "world" (5)
    }

    #[test]
    fn test_estimated_len() {
        let mut allocator = Allocator::new();
        // Create a tree with 2 atoms (10 bytes total) and 3 pairs
        let a = allocator.new_atom(&[1, 2, 3, 4, 5]).unwrap(); // 5 bytes
        let b = allocator.new_atom(&[6, 7, 8, 9, 10]).unwrap(); // 5 bytes
        let p1 = allocator.new_pair(a, b).unwrap();
        let p2 = allocator.new_pair(p1, a).unwrap();
        let p3 = allocator.new_pair(p2, b).unwrap();

        let components = cost_components(&allocator, p3).unwrap();

        // estimated_len = atom_bytes + 2*atom_count + 2*pair_count
        //               = 10 + 2*2 + 2*3 = 10 + 4 + 6 = 20
        assert_eq!(components.estimated_len(), 20);
    }
}
