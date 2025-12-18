use std::collections::HashMap;

use crate::allocator::{Allocator, Atom, NodePtr, SExp};
use crate::error::Result;

/// Type alias for the return value of create_interned_node
type InternedNodeResult = (Allocator, NodePtr, Vec<(NodePtr, usize)>);

/// Raw statistics from interning - all the components needed for cost formulas.
/// These are the building blocks; the actual cost formula can be tuned separately.
#[derive(Debug, Clone, Default)]
pub struct InternedStats {
    /// Number of unique atoms
    pub atom_count: u64,
    /// Number of unique pairs
    pub pair_count: u64,
    /// Sum of all atom byte lengths: Σ(atom_len)
    pub atom_bytes: u64,
    /// SHA256 blocks for atoms: Σ(ceil((atom_len + 10) / 64))
    /// The +10 accounts for 0x01 prefix (1) + padding overhead (9)
    pub sha_atom_blocks: u64,
    /// SHA256 blocks for pairs: 2 * pair_count
    /// Each pair hashes 65 bytes (0x02 + two 32-byte hashes) + 9 padding = 74 bytes = 2 blocks
    pub sha_pair_blocks: u64,
}

impl InternedStats {
    /// Total SHA256 blocks (for block mixing cost)
    pub fn sha_blocks(&self) -> u64 {
        self.sha_atom_blocks + self.sha_pair_blocks
    }

    /// Total SHA256 invocations (for setup/finalize cost)
    pub fn sha_invocations(&self) -> u64 {
        self.atom_count + self.pair_count
    }
}

/// Compute stats given lists of atom and pair NodePtrs from an interned allocator.
pub fn stats_for_interned_nodes(
    allocator: &Allocator,
    atoms: &[NodePtr],
    pairs: &[NodePtr],
) -> InternedStats {
    let mut stats = InternedStats {
        atom_count: atoms.len() as u64,
        pair_count: pairs.len() as u64,
        atom_bytes: 0,
        sha_atom_blocks: 0,
        sha_pair_blocks: 2 * pairs.len() as u64, // pairs always 2 blocks
    };

    for &atom in atoms {
        let len = allocator.atom_len(atom) as u64;
        stats.atom_bytes += len;
        // ceil((len + 10) / 64) = (len + 10 + 63) / 64 = (len + 73) / 64
        stats.sha_atom_blocks += (len + 73) / 64;
    }

    stats
}

/// Creates an interned version of a node, returning only the allocator and root.
/// This is O(n) where n is the number of unique nodes.
/// Use this for serialization when you don't need visit counts.
pub fn intern_node(allocator: &Allocator, node: NodePtr) -> Result<(Allocator, NodePtr)> {
    let mut new_allocator = Allocator::new();
    let mut node_stack = vec![node];
    let mut atom_to_interned_node: HashMap<Atom, NodePtr> = HashMap::new();
    let mut pair_to_interned_node: HashMap<(NodePtr, NodePtr), NodePtr> = HashMap::new();
    let mut node_to_interned_node: HashMap<NodePtr, NodePtr> = HashMap::new();
    let mut result_node: NodePtr = new_allocator.nil();

    while let Some(current_node) = node_stack.pop() {
        // Skip if already processed (important for shared nodes!)
        if node_to_interned_node.contains_key(&current_node) {
            continue;
        }

        match allocator.sexp(current_node) {
            SExp::Atom => {
                let atom = allocator.atom(current_node);
                let atom_bytes = atom.as_ref();
                let existing_atom: Option<&NodePtr> = atom_to_interned_node.get(atom_bytes);
                if let Some(&interned_node) = existing_atom {
                    result_node = interned_node;
                } else {
                    result_node = new_allocator.new_atom(atom.as_ref())?;
                    atom_to_interned_node.insert(atom, result_node);
                }
                node_to_interned_node.insert(current_node, result_node);
            }
            SExp::Pair(left, right) => {
                if let Some(&left_interned) = node_to_interned_node.get(&left) {
                    if let Some(&right_interned) = node_to_interned_node.get(&right) {
                        if let Some(&existing_node) =
                            pair_to_interned_node.get(&(left_interned, right_interned))
                        {
                            result_node = existing_node;
                        } else {
                            result_node = new_allocator.new_pair(left_interned, right_interned)?;
                            pair_to_interned_node
                                .insert((left_interned, right_interned), result_node);
                        }
                        node_to_interned_node.insert(current_node, result_node);
                    } else {
                        node_stack.push(current_node);
                        node_stack.push(right);
                    }
                } else {
                    node_stack.push(current_node);
                    node_stack.push(right);
                    node_stack.push(left);
                }
            }
        }
    }

    Ok((new_allocator, result_node))
}

/// Creates an interned version of a node where duplicate atoms and pairs are deduplicated.
///
/// This function performs two passes over the node structure:
/// 1. **Interning pass**: Traverses the tree depth-first, building a new allocator with deduplicated
///    atoms and pairs. Uses hash maps to track which atoms and pairs have been seen before.
/// 2. **Counting pass**: Traverses the interned tree to count how many times each unique node
///    appears in the final structure, which is useful for cost calculations.
///
/// The algorithm ensures that identical atoms are stored only once and identical pair
/// structures are reused, reducing memory footprint and enabling efficient cost analysis.
///
/// # Arguments
/// * `allocator` - The source allocator containing the original node structure
/// * `node` - The root node to intern
///
/// # Returns
/// A result containing a tuple of:
/// - `Allocator`: The new allocator containing only unique nodes
/// - `NodePtr`: The root node in the new allocator
/// - `Vec<(NodePtr, usize)>`: Visit counts for each unique node in the interned tree
///
/// # Errors
/// Returns an error if node creation fails (e.g., due to allocator memory limits)
pub fn create_interned_node(allocator: &Allocator, node: NodePtr) -> Result<InternedNodeResult> {
    let (new_allocator, result_node) = intern_node(allocator, node)?;

    // Count how many times each interned node appears in the final interned tree
    // Note: This traverses the original tree structure, so it's O(original tree size)
    let mut counter: HashMap<NodePtr, usize> = HashMap::new();
    let mut count_stack = vec![result_node];

    while let Some(current) = count_stack.pop() {
        counter.entry(current).and_modify(|c| *c += 1).or_insert(1);

        match new_allocator.sexp(current) {
            SExp::Pair(left, right) => {
                count_stack.push(left);
                count_stack.push(right);
            }
            SExp::Atom => {}
        }
    }

    let mut counts = vec![];
    for (node, count) in counter.iter() {
        counts.push((*node, *count));
    }
    Ok((new_allocator, result_node, counts))
}
