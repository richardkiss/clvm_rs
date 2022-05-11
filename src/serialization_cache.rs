use crate::allocator::{Allocator, NodePtr, SExp};
use crate::sha2::Sha256;
use std::collections::HashMap;

pub struct ObjectCache<T> {
    hash: HashMap<NodePtr, T>,
}

impl<T> ObjectCache<T> {
    pub fn get(&self, key: &NodePtr) -> Option<&T> {
        self.hash.get(key)
    }
    pub fn default() -> Self {
        let hash = HashMap::new();
        Self { hash }
    }
}

pub fn generate_cache<T>(
    allocator: &mut Allocator,
    root_node: NodePtr,
    f: fn(&mut ObjectCache<T>, &mut Allocator, NodePtr) -> Option<T>,
) -> ObjectCache<T> {
    let mut cache: ObjectCache<T> = ObjectCache::default();
    cache.update(allocator, root_node, f);
    cache
}

impl<T> ObjectCache<T> {
    pub fn update(
        &mut self,
        allocator: &mut Allocator,
        root_node: NodePtr,
        f: fn(&mut ObjectCache<T>, &mut Allocator, NodePtr) -> Option<T>,
    ) -> () {
        let mut obj_list = vec![root_node];
        loop {
            match obj_list.pop() {
                None => {
                    return;
                }
                Some(node) => match f(self, allocator, node) {
                    None => match allocator.sexp(node) {
                        SExp::Pair(left, right) => {
                            obj_list.push(node);
                            obj_list.push(left);
                            obj_list.push(right);
                        }
                        _ => panic!("f returned `None` for atom"),
                    },
                    Some(v) => {
                        self.hash.insert(node, v);
                    }
                },
            }
        }
    }
}

pub fn treehash(
    cache: &mut ObjectCache<[u8; 32]>,
    allocator: &mut Allocator,
    node: NodePtr,
) -> Option<[u8; 32]> {
    match allocator.sexp(node) {
        SExp::Pair(left, right) => match cache.hash.get(&left) {
            None => None,
            Some(left_value) => match cache.hash.get(&right) {
                None => None,
                Some(right_value) => {
                    let mut sha256 = Sha256::new();
                    sha256.update(&[2]);
                    sha256.update(left_value);
                    sha256.update(right_value);
                    Some(sha256.finish())
                }
            },
        },
        SExp::Atom(atom_buf) => {
            let mut sha256 = Sha256::new();
            sha256.update(&[1]);
            sha256.update(allocator.buf(&atom_buf));
            Some(sha256.finish())
        }
    }
}

pub fn serialized_length(
    cache: &mut ObjectCache<usize>,
    allocator: &mut Allocator,
    node: NodePtr,
) -> Option<usize> {
    match allocator.sexp(node) {
        SExp::Pair(left, right) => match cache.hash.get(&left) {
            None => None,
            Some(left_value) => match cache.hash.get(&right) {
                None => None,
                Some(right_value) => Some(1 + left_value + right_value),
            },
        },
        SExp::Atom(atom_buf) => {
            let buf = allocator.buf(&atom_buf);
            let lb = buf.len();
            Some(if lb == 0 {
                1
            } else if lb == 1 && buf[0] < 128 {
                1
            } else if lb < 0x40 {
                1 + lb
            } else if lb < 0x2000 {
                2 + lb
            } else if lb < 0x100000 {
                3 + lb
            } else if lb < 0x8000000 {
                4 + lb
            } else {
                5 + lb
            })
        }
    }
}
