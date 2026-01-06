use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use crate::allocator::{Allocator, NodePtr, SExp};
use crate::error::{EvalErr, Result};

use super::intern::intern_node;
use super::varint::{decode_varint, encode_varint};

/// Collected unique atoms and pairs from an interned allocator.
/// Stores NodePtrs rather than copying data - use the allocator to access content.
struct InternedNodes {
    atoms: Vec<NodePtr>,
    pairs: Vec<NodePtr>,
}

/// Extract unique atoms and pairs from an interned allocator via post-order traversal.
/// Returns (nodes, root_index, node_to_index_map) where indices are:
/// - atoms: 0, 1, 2, ... (non-negative)
/// - pairs: -1, -2, -3, ... (negative)
fn collect_interned_nodes(
    allocator: &Allocator,
    root: NodePtr,
) -> (InternedNodes, i32, HashMap<NodePtr, i32>) {
    let mut nodes = InternedNodes {
        atoms: Vec::new(),
        pairs: Vec::new(),
    };
    let mut node_to_index: HashMap<NodePtr, i32> = HashMap::new();
    let mut stack: Vec<NodePtr> = vec![root];

    while let Some(&current) = stack.last() {
        if node_to_index.contains_key(&current) {
            stack.pop();
            continue;
        }

        match allocator.sexp(current) {
            SExp::Atom => {
                stack.pop();
                let idx = nodes.atoms.len() as i32;
                nodes.atoms.push(current);
                node_to_index.insert(current, idx);
            }
            SExp::Pair(left, right) => {
                if node_to_index.contains_key(&left) && node_to_index.contains_key(&right) {
                    stack.pop();
                    nodes.pairs.push(current);
                    let idx = -(nodes.pairs.len() as i32);
                    node_to_index.insert(current, idx);
                } else {
                    if !node_to_index.contains_key(&right) {
                        stack.push(right);
                    }
                    if !node_to_index.contains_key(&left) {
                        stack.push(left);
                    }
                }
            }
        }
    }

    let root_index = node_to_index[&root];
    (nodes, root_index, node_to_index)
}

/// Serialize a node using the 2026 serialization format.
///
/// This function:
/// 1. Interns the node to deduplicate atoms and pairs
/// 2. Renumbers atoms and pairs for optimal compression
/// 3. Serializes using the 2026 format with varints
pub fn serialize_2026(allocator: &Allocator, node: NodePtr) -> Result<Vec<u8>> {
    // Step 1: Intern the node (O(n) where n = unique nodes)
    let (interned_allocator, interned_root) = intern_node(allocator, node)?;

    // Step 2: Collect unique atoms and pairs from the interned allocator
    let (nodes, root_index, node_to_index) =
        collect_interned_nodes(&interned_allocator, interned_root);

    let atom_count = nodes.atoms.len();
    let pair_count = nodes.pairs.len();

    // Step 3: Sort atoms by length (shorter atoms get lower indices)
    let mut sorted_atom_indices: Vec<usize> = (0..atom_count).collect();
    sorted_atom_indices.sort_by_key(|&i| interned_allocator.atom_len(nodes.atoms[i]));

    // Create remap for atoms (maps old index -> new index)
    let mut atom_remap: HashMap<i32, i32> = HashMap::new();
    for (new_idx, &old_idx) in sorted_atom_indices.iter().enumerate() {
        atom_remap.insert(old_idx as i32, new_idx as i32);
    }

    // Step 4: Build remapped pair children (atom indices remapped, pair indices unchanged)
    let remapped_pairs: Vec<(i32, i32)> = nodes
        .pairs
        .iter()
        .map(|&pair_node| {
            let (left, right) = match interned_allocator.sexp(pair_node) {
                SExp::Pair(l, r) => (l, r),
                _ => unreachable!(),
            };
            let left_idx = node_to_index[&left];
            let right_idx = node_to_index[&right];
            let new_left = if left_idx >= 0 {
                atom_remap[&left_idx]
            } else {
                left_idx
            };
            let new_right = if right_idx >= 0 {
                atom_remap[&right_idx]
            } else {
                right_idx
            };
            (new_left, new_right)
        })
        .collect();

    // Step 5: Group atoms by length
    let mut atoms_by_length: HashMap<usize, Vec<NodePtr>> = HashMap::new();
    for &old_idx in &sorted_atom_indices {
        let atom_node = nodes.atoms[old_idx];
        let len = interned_allocator.atom_len(atom_node);
        atoms_by_length
            .entry(len)
            .or_default()
            .push(atom_node);
    }

    // Step 6: Serialize
    let mut output = Vec::new();

    // Write number of unique lengths
    output.write_all(&encode_varint(atoms_by_length.len() as i64))?;

    // Write each length group
    let mut sorted_lengths: Vec<usize> = atoms_by_length.keys().copied().collect();
    sorted_lengths.sort();

    for length in sorted_lengths {
        let atoms_of_length = &atoms_by_length[&length];
        let count = atoms_of_length.len();

        if count == 1 {
            // Single atom: write positive length, then bytes
            output.write_all(&encode_varint(length as i64))?;
            output.write_all(interned_allocator.atom(atoms_of_length[0]).as_ref())?;
        } else {
            // Multiple atoms: write negative length, then count, then all bytes
            output.write_all(&encode_varint(-(length as i64)))?;
            output.write_all(&encode_varint(count as i64))?;
            for &atom_node in atoms_of_length {
                output.write_all(interned_allocator.atom(atom_node).as_ref())?;
            }
        }
    }

    // Step 7: Generate instruction stream
    if pair_count == 0 {
        // No pairs, root is an atom - just push it
        let remapped_root_idx = atom_remap[&root_index];
        output.write_all(&encode_varint(1))?; // One instruction
        output.write_all(&encode_varint(remapped_root_idx as i64 + 1))?; // Push the atom
    } else {
        // Generate instruction stream using stack-based traversal
        let mut construction_order: HashMap<i32, i32> = HashMap::new();
        let mut instructions: Vec<i64> = Vec::new();

        #[derive(Debug)]
        enum Op {
            Build(i32),
            Cons(i32),
        }

        // Start with the root (root_index is already a pair index like -1, -2, etc.)
        let mut work_stack: Vec<Op> = vec![Op::Build(root_index)];

        while let Some(op) = work_stack.pop() {
            match op {
                Op::Cons(node_index) => {
                    // We've finished processing the children of this pair, record it
                    instructions.push(0); // cons
                    construction_order.insert(node_index, construction_order.len() as i32);
                }
                Op::Build(node_index) => {
                    if node_index >= 0 {
                        // It's an atom, push it (use 1-based indexing)
                        instructions.push(node_index as i64 + 1);
                    } else {
                        // It's a pair
                        // Check if we've already constructed this pair
                        if let Some(&constructed_idx) = construction_order.get(&node_index) {
                            // Reference the already-constructed pair
                            instructions.push(-(constructed_idx as i64 + 1));
                        } else {
                            // Build this pair: process left, process right, then cons
                            let pair_idx = (-node_index - 1) as usize;
                            let (left, right) = remapped_pairs[pair_idx];

                            // Push operations in reverse order
                            work_stack.push(Op::Cons(node_index));
                            work_stack.push(Op::Build(right));
                            work_stack.push(Op::Build(left));
                        }
                    }
                }
            }
        }

        // Write instruction count and instructions
        output.write_all(&encode_varint(instructions.len() as i64))?;
        for instruction in instructions {
            output.write_all(&encode_varint(instruction))?;
        }
    }

    Ok(output)
}

/// Deserialize a node from bytes using the 2026 serialization format.
pub fn deserialize_2026(allocator: &mut Allocator, data: &[u8]) -> Result<NodePtr> {
    let mut cursor = Cursor::new(data);

    // Read atoms - reuse a single buffer for reading
    let mut atoms: Vec<NodePtr> = Vec::new();
    let atom_lengths_count = decode_varint(&mut cursor)? as usize;
    let mut atom_buffer: Vec<u8> = Vec::new();

    for _ in 0..atom_lengths_count {
        let atom_length = decode_varint(&mut cursor)?;
        let (actual_length, atom_count) = if atom_length < 0 {
            let len = (-atom_length) as usize;
            let count = decode_varint(&mut cursor)? as usize;
            (len, count)
        } else {
            (atom_length as usize, 1)
        };

        // Resize buffer once per length group
        atom_buffer.resize(actual_length, 0);

        for _ in 0..atom_count {
            cursor
                .read_exact(&mut atom_buffer)
                .map_err(|_| EvalErr::SerializationError)?;
            let atom_node = allocator.new_atom(&atom_buffer)?;
            atoms.push(atom_node);
        }
    }

    let instruction_count = decode_varint(&mut cursor)? as usize;
    if instruction_count == 0 {
        // No pairs, just return the single atom
        return if atoms.is_empty() {
            Err(EvalErr::SerializationError)
        } else {
            Ok(atoms[0])
        };
    }

    // Pre-allocate vectors - pairs will have at most instruction_count entries
    // (one per cons instruction), stack depth is typically much smaller
    let mut pairs: Vec<NodePtr> = Vec::with_capacity(instruction_count / 2);
    let mut stack: Vec<NodePtr> = Vec::with_capacity(64);

    for _ in 0..instruction_count {
        let instruction = decode_varint(&mut cursor)?;
        if instruction == 0 {
            // Cons: pop two items, create pair, push it
            if stack.len() < 2 {
                return Err(EvalErr::SerializationError);
            }
            let right = stack.pop().unwrap();
            let left = stack.pop().unwrap();
            let pair = allocator.new_pair(left, right)?;
            pairs.push(pair);
            stack.push(pair);
        } else if instruction > 0 {
            // Push atom (1-based indexing)
            let atom_idx = (instruction - 1) as usize;
            let atom = *atoms.get(atom_idx).ok_or(EvalErr::SerializationError)?;
            stack.push(atom);
        } else {
            // Push already-constructed pair (negative index)
            let pair_idx = (-instruction - 1) as usize;
            let pair = *pairs.get(pair_idx).ok_or(EvalErr::SerializationError)?;
            stack.push(pair);
        }
    }

    // The final item on the stack is the root
    if stack.len() != 1 {
        return Err(EvalErr::SerializationError);
    }

    Ok(stack[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_simple_atom() {
        let mut allocator = Allocator::new();
        let node = allocator.new_atom(b"hello").unwrap();

        let serialized = serialize_2026(&allocator, node).unwrap();
        let mut new_allocator = Allocator::new();
        let deserialized = deserialize_2026(&mut new_allocator, &serialized).unwrap();

        let original_atom = allocator.atom(node);
        let deserialized_atom = new_allocator.atom(deserialized);
        assert_eq!(original_atom.as_ref(), deserialized_atom.as_ref());
    }

    #[test]
    fn test_roundtrip_simple_pair() {
        let mut allocator = Allocator::new();
        let left = allocator.new_atom(b"left").unwrap();
        let right = allocator.new_atom(b"right").unwrap();
        let pair = allocator.new_pair(left, right).unwrap();

        let serialized = serialize_2026(&allocator, pair).unwrap();
        let mut new_allocator = Allocator::new();
        let deserialized = deserialize_2026(&mut new_allocator, &serialized).unwrap();

        // Check structure
        match new_allocator.sexp(deserialized) {
            SExp::Pair(l, r) => {
                let left_atom = new_allocator.atom(l);
                let right_atom = new_allocator.atom(r);
                assert_eq!(left_atom.as_ref(), b"left");
                assert_eq!(right_atom.as_ref(), b"right");
            }
            _ => panic!("Expected pair"),
        }
    }
}
