//! DoS test harness for cost formula validation
//!
//! Generates adversarial CLVM structures and evaluates various cost formulas
//! to identify potential exploitation vectors.
//!
//! Usage:
//!   cargo run --release -p clvm-rs-test-tools --bin dos-test
//!   cargo run --release -p clvm-rs-test-tools --bin dos-test -- --help

use clap::Parser;
use clvmr::serde::{node_to_bytes_backrefs, InternedStats};
use clvmr::{intern_stats, Allocator, NodePtr};
use std::time::Instant;

// Cost formula constants (matching generator.rs)
const COEF_B: u64 = 1;
const COEF_A: u64 = 2;
const COEF_P: u64 = 2;
const COEF_S: u64 = 1;
const COEF_I: u64 = 8;
const SIZE_COST_PER_BYTE: u64 = 6000;
const SHA_COST_PER_UNIT: u64 = 4500;
const OLD_COST_PER_BYTE: u64 = 12000;

#[derive(Parser)]
#[command(name = "dos-test")]
#[command(about = "Test cost formulas against adversarial CLVM structures")]
struct Args {
    /// Scale factor for test sizes (default generates moderate-sized structures)
    #[arg(short, long, default_value = "1000")]
    scale: usize,

    /// Show detailed per-test output
    #[arg(short, long)]
    verbose: bool,

    /// Only run specific test (by name substring)
    #[arg(short, long)]
    filter: Option<String>,
}

/// Result of running a single adversarial test
struct TestResult {
    name: String,
    stats: InternedStats,
    backref_size: u64,
    build_time_us: u64,
    intern_time_us: u64,
}

impl TestResult {
    /// Size component: B×atom_bytes + A×atom_count + P×pair_count
    fn size_component(&self) -> u64 {
        let s = &self.stats;
        COEF_B * s.atom_bytes + COEF_A * s.atom_count + COEF_P * s.pair_count
    }

    /// SHA component: S×sha_blocks + I×sha_invocations
    fn sha_component(&self) -> u64 {
        let s = &self.stats;
        COEF_S * s.sha_blocks() + COEF_I * s.sha_invocations()
    }

    /// New blended cost formula (50% size + 50% SHA)
    fn cost_blended(&self) -> u64 {
        self.size_component() * SIZE_COST_PER_BYTE + self.sha_component() * SHA_COST_PER_UNIT
    }

    /// Old cost formula (backref_size × 12000)
    fn cost_old(&self) -> u64 {
        self.backref_size * OLD_COST_PER_BYTE
    }

    /// Ratio of actual work (intern time) to cost charged
    fn work_per_cost(&self, cost: u64) -> f64 {
        if cost == 0 {
            return f64::INFINITY;
        }
        self.intern_time_us as f64 / cost as f64
    }

    /// Ratio of new cost to old cost
    fn cost_ratio(&self) -> f64 {
        let old = self.cost_old();
        if old == 0 {
            return f64::INFINITY;
        }
        self.cost_blended() as f64 / old as f64
    }
}

fn main() {
    let args = Args::parse();

    println!("=== DoS Test Harness for Cost Formulas ===\n");
    println!("Scale factor: {}", args.scale);
    println!();

    #[allow(clippy::type_complexity)]
    let tests: Vec<(&str, fn(&mut Allocator, usize) -> NodePtr)> = vec![
        ("million_nil_atoms", build_many_nil_atoms),
        ("million_tiny_atoms", build_many_tiny_atoms),
        ("deep_nesting", build_deep_nesting),
        ("maximally_shared_tree", build_maximally_shared),
        ("single_huge_atom", build_single_huge_atom),
        ("wide_shallow_tree", build_wide_shallow),
        ("many_small_pairs", build_many_small_pairs),
        ("balanced_tree", build_balanced_tree),
        ("long_list", build_long_list),
        ("hash_sized_atoms", build_hash_sized_atoms),
        ("worst_sha_ratio", build_worst_sha_ratio),
        ("best_sha_ratio", build_best_sha_ratio),
    ];

    let mut results = Vec::new();

    for (name, builder) in &tests {
        if let Some(ref filter) = args.filter {
            if !name.contains(filter.as_str()) {
                continue;
            }
        }

        // Build the structure
        let mut allocator = Allocator::new();
        let start = Instant::now();
        let node = builder(&mut allocator, args.scale);
        let build_time_us = start.elapsed().as_micros() as u64;

        // Compute stats (this does interning internally)
        let start = Instant::now();
        let stats = match intern_stats(&allocator, node) {
            Ok(s) => s,
            Err(e) => {
                println!("{}: ERROR - {:?}", name, e);
                continue;
            }
        };
        let intern_time_us = start.elapsed().as_micros() as u64;

        // Compute actual backref-serialized size
        let backref_size = match node_to_bytes_backrefs(&allocator, node) {
            Ok(bytes) => bytes.len() as u64,
            Err(e) => {
                println!("{}: ERROR serializing - {:?}", name, e);
                continue;
            }
        };

        results.push(TestResult {
            name: name.to_string(),
            stats,
            backref_size,
            build_time_us,
            intern_time_us,
        });
    }

    // Print component summary
    println!(
        "{:<25} {:>10} {:>10} {:>12} {:>12} {:>10} {:>10}",
        "Test", "Atoms", "Pairs", "AtomBytes", "BackrefSize", "SHA Inv", "SHA Blk"
    );
    println!("{}", "-".repeat(97));

    for r in &results {
        let s = &r.stats;
        println!(
            "{:<25} {:>10} {:>10} {:>12} {:>12} {:>10} {:>10}",
            r.name,
            s.atom_count,
            s.pair_count,
            s.atom_bytes,
            r.backref_size,
            s.sha_invocations(),
            s.sha_blocks()
        );
    }

    // Print cost comparison
    println!();
    println!(
        "{:<25} {:>12} {:>12} {:>14} {:>14} {:>8}",
        "Test", "Size Comp", "SHA Comp", "Blended Cost", "Old Cost", "Ratio"
    );
    println!("{}", "-".repeat(95));

    for r in &results {
        println!(
            "{:<25} {:>12} {:>12} {:>14} {:>14} {:>8.2}",
            r.name,
            r.size_component(),
            r.sha_component(),
            r.cost_blended(),
            r.cost_old(),
            r.cost_ratio()
        );
    }

    // Print timing analysis
    println!();
    println!(
        "{:<25} {:>10} {:>10} {:>16} {:>14}",
        "Test", "Build μs", "Intern μs", "μs/Blended Cost", "ns/cost unit"
    );
    println!("{}", "-".repeat(85));

    for r in &results {
        let ns_per_cost = if r.cost_blended() > 0 {
            (r.intern_time_us as f64 * 1000.0) / r.cost_blended() as f64
        } else {
            f64::INFINITY
        };
        println!(
            "{:<25} {:>10} {:>10} {:>16.9} {:>14.6}",
            r.name,
            r.build_time_us,
            r.intern_time_us,
            r.work_per_cost(r.cost_blended()),
            ns_per_cost
        );
    }

    // Identify potential issues
    println!();
    println!("=== DoS Analysis (Blended Formula) ===");
    println!();
    println!(
        "Formula: cost = size_comp × {} + sha_comp × {}",
        SIZE_COST_PER_BYTE, SHA_COST_PER_UNIT
    );
    println!(
        "Where:   size_comp = {}×bytes + {}×atoms + {}×pairs",
        COEF_B, COEF_A, COEF_P
    );
    println!(
        "         sha_comp  = {}×sha_blocks + {}×sha_invocations",
        COEF_S, COEF_I
    );
    println!();

    // Find tests with highest work-per-cost ratio (potential DoS vectors)
    let mut by_work_ratio: Vec<_> = results.iter().collect();
    by_work_ratio.sort_by(|a, b| {
        b.work_per_cost(b.cost_blended())
            .partial_cmp(&a.work_per_cost(a.cost_blended()))
            .unwrap()
    });

    println!("Highest work/cost ratio (potential DoS vectors):");
    for r in by_work_ratio.iter().take(5) {
        let ns_per_cost = (r.intern_time_us as f64 * 1000.0) / r.cost_blended() as f64;
        println!(
            "  {}: {:.6} μs/cost ({} μs intern, {} cost, {:.3} ns/cost)",
            r.name,
            r.work_per_cost(r.cost_blended()),
            r.intern_time_us,
            r.cost_blended(),
            ns_per_cost
        );
    }

    // Show cost ratio analysis (new vs old)
    println!();
    println!("=== New vs Old Cost Comparison ===");
    println!();
    println!("Ratio > 1.0 means new formula charges MORE (safer against DoS)");
    println!("Ratio < 1.0 means new formula charges LESS (potential concern)");
    println!();

    let mut by_ratio: Vec<_> = results.iter().collect();
    by_ratio.sort_by(|a, b| a.cost_ratio().partial_cmp(&b.cost_ratio()).unwrap());

    for r in &by_ratio {
        let indicator = if r.cost_ratio() >= 1.0 { "✓" } else { "⚠" };
        println!(
            "  {} {}: new/old = {:.2}x (blended={}, old={})",
            indicator,
            r.name,
            r.cost_ratio(),
            r.cost_blended(),
            r.cost_old()
        );
    }

    // Check for concerning patterns
    println!();
    println!("=== Safety Assessment ===");
    println!();

    let min_ratio = by_ratio.first().map(|r| r.cost_ratio()).unwrap_or(1.0);
    let max_work_per_cost = by_work_ratio
        .first()
        .map(|r| r.work_per_cost(r.cost_blended()))
        .unwrap_or(0.0);

    if min_ratio < 0.5 {
        println!("⚠ WARNING: Some structures cost <50% of old formula - review needed!");
    } else if min_ratio < 1.0 {
        println!(
            "⚠ CAUTION: Some structures cost less than old formula (min ratio: {:.2}x)",
            min_ratio
        );
    } else {
        println!(
            "✓ All adversarial structures cost >= old formula (min ratio: {:.2}x)",
            min_ratio
        );
    }

    println!(
        "  Max work/cost ratio: {:.6} μs/cost unit",
        max_work_per_cost
    );
    println!(
        "  This means ~{:.0} cost units per microsecond of work",
        1.0 / max_work_per_cost
    );

    if args.verbose {
        println!();
        println!("=== Detailed Results ===");
        for r in &results {
            println!();
            println!("{}:", r.name);
            println!("  Stats:");
            println!("    atom_count: {}", r.stats.atom_count);
            println!("    pair_count: {}", r.stats.pair_count);
            println!("    atom_bytes: {}", r.stats.atom_bytes);
            println!("    backref_size: {}", r.backref_size);
            println!("    sha_atom_blocks: {}", r.stats.sha_atom_blocks);
            println!("    sha_pair_blocks: {}", r.stats.sha_pair_blocks());
            println!("  Timing:");
            println!("    build: {} μs", r.build_time_us);
            println!("    intern: {} μs", r.intern_time_us);
            println!("  Costs:");
            println!("    size_component: {}", r.size_component());
            println!("    sha_component: {}", r.sha_component());
            println!("    blended_cost: {}", r.cost_blended());
            println!("    old_cost: {}", r.cost_old());
            println!("    new/old ratio: {:.2}x", r.cost_ratio());
        }
    }
}

// ============ Adversarial Structure Builders ============

/// Many zero-byte atoms (nil)
fn build_many_nil_atoms(allocator: &mut Allocator, scale: usize) -> NodePtr {
    // Create a list of nils: (nil nil nil ... nil)
    let nil = allocator.nil();
    let mut node = nil;
    for _ in 0..scale {
        node = allocator.new_pair(nil, node).unwrap();
    }
    node
}

/// Many 1-byte atoms
fn build_many_tiny_atoms(allocator: &mut Allocator, scale: usize) -> NodePtr {
    let mut node = allocator.nil();
    for i in 0..scale {
        let atom = allocator.new_atom(&[(i & 0xff) as u8]).unwrap();
        node = allocator.new_pair(atom, node).unwrap();
    }
    node
}

/// Deeply nested pairs: (((((...nil)))))
fn build_deep_nesting(allocator: &mut Allocator, scale: usize) -> NodePtr {
    let nil = allocator.nil();
    let mut node = nil;
    for _ in 0..scale {
        node = allocator.new_pair(node, nil).unwrap();
    }
    node
}

/// Maximally shared binary tree (exponential logical size, linear unique nodes)
fn build_maximally_shared(allocator: &mut Allocator, scale: usize) -> NodePtr {
    // Depth is log2(scale) to keep it reasonable
    let depth = (scale as f64).log2() as usize;
    let leaf = allocator.new_atom(&[42]).unwrap();
    let mut node = leaf;
    for _ in 0..depth {
        node = allocator.new_pair(node, node).unwrap();
    }
    node
}

/// Single huge atom
fn build_single_huge_atom(allocator: &mut Allocator, scale: usize) -> NodePtr {
    let data: Vec<u8> = (0..scale * 100).map(|i| (i & 0xff) as u8).collect();
    allocator.new_atom(&data).unwrap()
}

/// Wide, shallow tree (many siblings at depth 1)
fn build_wide_shallow(allocator: &mut Allocator, scale: usize) -> NodePtr {
    let atom = allocator.new_atom(&[1, 2, 3]).unwrap();
    let mut node = allocator.nil();
    for _ in 0..scale {
        node = allocator.new_pair(atom, node).unwrap();
    }
    node
}

/// Many small independent pairs
fn build_many_small_pairs(allocator: &mut Allocator, scale: usize) -> NodePtr {
    let mut pairs = Vec::with_capacity(scale);
    for i in 0..scale {
        let left = allocator.new_atom(&[(i & 0xff) as u8]).unwrap();
        let right = allocator.new_atom(&[((i >> 8) & 0xff) as u8]).unwrap();
        pairs.push(allocator.new_pair(left, right).unwrap());
    }
    // Combine into a list
    let mut node = allocator.nil();
    for p in pairs {
        node = allocator.new_pair(p, node).unwrap();
    }
    node
}

/// Balanced binary tree
fn build_balanced_tree(allocator: &mut Allocator, scale: usize) -> NodePtr {
    fn build_tree(allocator: &mut Allocator, depth: usize, counter: &mut usize) -> NodePtr {
        if depth == 0 {
            *counter += 1;
            allocator.new_atom(&[(*counter & 0xff) as u8]).unwrap()
        } else {
            let left = build_tree(allocator, depth - 1, counter);
            let right = build_tree(allocator, depth - 1, counter);
            allocator.new_pair(left, right).unwrap()
        }
    }

    let depth = (scale as f64).log2() as usize;
    let mut counter = 0;
    build_tree(allocator, depth, &mut counter)
}

/// Long linked list
fn build_long_list(allocator: &mut Allocator, scale: usize) -> NodePtr {
    let mut node = allocator.nil();
    for i in 0..scale {
        let atom = allocator.new_atom(&[(i & 0xff) as u8]).unwrap();
        node = allocator.new_pair(atom, node).unwrap();
    }
    node
}

/// Many 32-byte atoms (hash-sized, typical for Chia)
fn build_hash_sized_atoms(allocator: &mut Allocator, scale: usize) -> NodePtr {
    let mut node = allocator.nil();
    for i in 0..scale {
        // 32-byte atom (like a hash)
        let mut data = [0u8; 32];
        data[0] = (i & 0xff) as u8;
        data[1] = ((i >> 8) & 0xff) as u8;
        let atom = allocator.new_atom(&data).unwrap();
        node = allocator.new_pair(atom, node).unwrap();
    }
    node
}

/// Worst case for SHA ratio: many atoms that barely fit in 1 block
/// Atoms of 54 bytes: 54 + 1 (prefix) + 9 (padding) = 64 = 1 block
fn build_worst_sha_ratio(allocator: &mut Allocator, scale: usize) -> NodePtr {
    let mut node = allocator.nil();
    for i in 0..scale {
        // 54-byte atom (maximizes bytes per SHA block)
        let mut data = [0u8; 54];
        data[0] = (i & 0xff) as u8;
        let atom = allocator.new_atom(&data).unwrap();
        node = allocator.new_pair(atom, node).unwrap();
    }
    node
}

/// Best case for SHA ratio: atoms that just spill to 2 blocks
/// Atoms of 55 bytes: 55 + 1 + 9 = 65 = 2 blocks (but 55 bytes of data)
fn build_best_sha_ratio(allocator: &mut Allocator, scale: usize) -> NodePtr {
    let mut node = allocator.nil();
    for i in 0..scale {
        // 55-byte atom (just over threshold, gets 2 blocks for ~55 bytes)
        let mut data = [0u8; 55];
        data[0] = (i & 0xff) as u8;
        let atom = allocator.new_atom(&data).unwrap();
        node = allocator.new_pair(atom, node).unwrap();
    }
    node
}
