use std::collections::HashMap;

use crate::allocator::{Allocator, Atom, NodePtr, SExp};
use crate::error::Result;

/// this function takes a node and returns a new allocator and node
/// that has the same value, but all nodes are interned
/// The new allocator is guaranteed to have no duplicate atoms or pairs

pub fn create_interned_node(
    allocator: &Allocator,
    node: NodePtr,
) -> Result<(Allocator, NodePtr, usize, usize)> {
    let mut new_allocator = Allocator::new();
    let mut node_stack = vec![node];
    let mut atom_to_interned_node: HashMap<Atom, NodePtr> = HashMap::new();
    let mut pair_to_interned_node: HashMap<(NodePtr, NodePtr), NodePtr> = HashMap::new();
    let mut node_to_interned_node: HashMap<NodePtr, NodePtr> = HashMap::new();
    let mut result_node: NodePtr = new_allocator.nil();

    while let Some(current_node) = node_stack.pop() {
        match allocator.sexp(current_node) {
            SExp::Atom => {
                let atom = allocator.atom(current_node);
                let atom_bytes = atom.as_ref();
                let existing_atom: Option<&NodePtr> = atom_to_interned_node.get(atom_bytes);
                if let Some(&interned_node) = existing_atom {
                    result_node = interned_node;
                } else {
                    result_node = new_allocator.new_atom(atom.as_ref())?;
                    node_to_interned_node.insert(current_node, result_node);
                    atom_to_interned_node.insert(atom, result_node);
                }
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
                        // Right not processed yet, push node back to process children first
                        node_stack.push(current_node);
                        node_stack.push(right);
                    }
                } else {
                    // Left not processed yet, push node back to process children first
                    node_stack.push(current_node);
                    node_stack.push(right);
                    node_stack.push(left);
                }
            }
        }
    }
    let atom_count = atom_to_interned_node.len();
    let pair_count = pair_to_interned_node.len();
    Ok((new_allocator, result_node, atom_count, pair_count))
}
