pub mod allocator;
pub mod bls_ops;
pub mod chia;
pub mod chia_dialect;
pub mod core_ops;
pub mod cost;
pub mod dialect;
pub mod error;
pub mod f_table;
pub mod keccak256_ops;
pub mod more_ops;
pub mod number;
pub mod op_utils;
pub mod reduction;
pub mod run_program;
pub mod runtime_dialect;
pub mod secp_ops;
pub mod serde;
pub mod traverse_path;

pub use allocator::{Allocator, Atom, NodePtr, ObjectType, SExp};
pub use chia_dialect::ChiaDialect;
pub use run_program::run_program;

// Chia-specific exports (will migrate to chia_rs)
pub use chia::{
    cost_and_tree_hash_for_bytes, cost_components, generator_cost_and_hash, process_generator,
    CostComponents, GeneratorInfo, COEF_A, COEF_B, COEF_I, COEF_P, COEF_S, SHA_COST_PER_UNIT,
    SIZE_COST_PER_BYTE,
};

pub use chia_dialect::{ENABLE_KECCAK_OPS_OUTSIDE_GUARD, LIMIT_HEAP, MEMPOOL_MODE, NO_UNKNOWN_OPS};

#[cfg(feature = "counters")]
pub use run_program::run_program_with_counters;

#[cfg(feature = "pre-eval")]
pub use run_program::run_program_with_pre_eval;

#[cfg(feature = "counters")]
pub use run_program::Counters;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_ops;
