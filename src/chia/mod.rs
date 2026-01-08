//! Chia-specific functionality.
//!
//! This module contains Chia blockchain-specific code that will eventually
//! migrate to `chia_rs`. It is kept separate from the core CLVM functionality
//! in `serde/` to make the migration path clear.
//!
//! ## Contents
//!
//! - `generator`: Process CLVM generators for consensus validation
//!   - `GeneratorInfo`: Bundle of interned tree, hash, and stats
//!   - `process_generator`: Main entry point for generator validation
//!   - `generator_cost_and_hash`: Simplest API - returns (cost, hash)
//!   - Cost functions: `size_cost`, `sha_cost`, `total_cost`
//!
//! ## Cost Formula
//!
//! The blended formula protects against both memory and CPU DoS:
//! ```text
//! size_component = B×atom_bytes + A×atom_count + P×pair_count
//! sha_component  = S×sha_blocks + I×sha_invocations
//! total_cost = size_component × SIZE_COST_PER_BYTE + sha_component × SHA_COST_PER_UNIT
//! ```
//!
//! ## Migration Plan
//!
//! When migrating to `chia_rs`:
//! 1. Copy this module to `chia_rs/crates/chia-consensus/src/`
//! 2. Update imports to use `clvmr::` instead of `crate::`
//! 3. The cost constants can be adjusted via consensus constants if needed
//! 4. Remove this module from `clvm_rs`

mod generator;

pub use generator::{
    cost_and_tree_hash_for_bytes, generator_cost_and_hash, intern_stats, process_generator,
    sha_cost, size_cost, total_cost, GeneratorInfo, COEF_A, COEF_B, COEF_I, COEF_P, COEF_S,
    SHA_COST_PER_UNIT, SIZE_COST_PER_BYTE,
};
