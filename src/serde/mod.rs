mod bitset;
pub(crate) mod bytes32;
mod de;
mod de_br;
mod de_tree;
mod identity_hash;
mod incremental;
pub mod intern;
pub(crate) mod object_cache;
mod parse_atom;
mod path_builder;
mod read_cache_lookup;
mod ser;
#[cfg(feature = "ser-2026")]
mod ser_2026;
mod ser_br;
mod serialized_length;
mod tools;
mod tree_cache;
mod utils;
#[cfg(feature = "ser-2026")]
mod varint;
pub mod write_atom;

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_intern;
#[cfg(all(test, feature = "ser-2026"))]
mod test_ser_2026;

pub use bitset::BitSet;
pub use bytes32::Bytes32;
pub use de::node_from_bytes;
pub use de_br::{node_from_bytes_backrefs, node_from_bytes_backrefs_old};
pub use de_tree::{parse_triples, ParsedTriple};
pub use identity_hash::RandomState;
pub use incremental::{Serializer, UndoState};
// New API
pub use intern::{intern, InternedStats, InternedTree};
// Deprecated - kept for backward compatibility
#[allow(deprecated)]
pub use intern::{create_interned_node, intern_node, stats_for_interned_nodes};
pub use object_cache::{serialized_length, treehash, ObjectCache};
pub use path_builder::{ChildPos, PathBuilder};
pub use read_cache_lookup::ReadCacheLookup;
pub use ser::{node_to_bytes, node_to_bytes_limit};
#[cfg(feature = "ser-2026")]
pub use ser_2026::{deserialize_2026, serialize_2026};
pub use ser_br::{node_to_bytes_backrefs, node_to_bytes_backrefs_limit};
pub use serialized_length::{serialized_length_atom, serialized_length_small_number};
pub use tools::{
    is_canonical_serialization, serialized_length_from_bytes, serialized_length_from_bytes_trusted,
    tree_hash_from_stream,
};
pub use tree_cache::{TreeCache, TreeCacheCheckpoint};

// Re-export EvalErr for use by chia module
pub use crate::error::EvalErr;
