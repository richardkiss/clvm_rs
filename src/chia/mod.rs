//! Chia-specific functionality.
//!
//! This module contains Chia blockchain-specific code that will eventually
//! migrate to `chia_rs`. It is kept separate from the core CLVM functionality
//! in `serde/` to make the migration path clear.
//!
//! ## Contents
//!
//! - `generator`: Process CLVM generators for consensus validation
//!   - `CostComponents`: Raw metrics for cost formula calculation
//!   - `GeneratorInfo`: Bundle of interned tree, hash, and cost data
//!   - `process_generator`: Main entry point for generator validation
//!
//! ## Migration Plan
//!
//! When migrating to `chia_rs`:
//! 1. Copy this module to `chia_rs/crates/chia-consensus/src/`
//! 2. Update imports to use `clvmr::` instead of `crate::`
//! 3. Add consensus constants and the actual cost formula
//! 4. Remove this module from `clvm_rs`

mod generator;

pub use generator::{cost_components, process_generator, CostComponents, GeneratorInfo};
