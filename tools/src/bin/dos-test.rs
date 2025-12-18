//! DoS test harness for cost formula validation
//!
//! Generates adversarial CLVM structures and evaluates various cost formulas
//! to identify potential exploitation vectors.
//!
//! Usage:
//!   cargo run --release -p clvm_tools --bin dos-test
//!   cargo run --release -p clvm_tools --bin dos-test -- --help

use clap::Parser;
use clvmr::{cost_components, Allocator, CostComponents, NodePtr};
use std::time::Instant;

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
    components: CostComponents,
    build_time_us: u64,
    intern_time_us: u64,
}

impl TestResult {
    /// Simplified 3-term formula: atom_bytes + A×atom_count + P×pair_count
    /// This is the proposed hard fork formula (no SHA terms needed due to caching)
    fn cost_3term(&self, a: u64, p: u64) -> u64 {
        let c = &self.components;
        c.atom_bytes + a * c.atom_count + p * c.pair_count
    }

    /// Balanced formula with moderate constants
    fn cost_balanced(&self) -> u64 {
        // A=300, P=500
        self.cost_3term(300, 500)
    }

    /// Scaled formula to match old COST_PER_BYTE=12000 magnitude
    fn cost_scaled(&self) -> u64 {
        // A=3000, P=5000
        self.cost_3term(3000, 5000)
    }

    /// SHA256-only cost (for comparison/analysis)
    fn cost_sha_only(&self) -> u64 {
        let c = &self.components;
        10 * c.sha_invocations() + 3 * c.sha_blocks()
    }

    /// Storage-only cost (for comparison/analysis)
    fn cost_storage_only(&self) -> u64 {
        let c = &self.components;
        c.atom_bytes + 2 * c.atom_count + 6 * c.pair_count
    }

    /// Ratio of actual work (intern time) to cost charged
    fn work_per_cost(&self, cost: u64) -> f64 {
        if cost == 0 {
            return f64::INFINITY;
        }
        self.intern_time_us as f64 / cost as f64
    }
}

fn main() {
    let args = Args::parse();

    println!("=== DoS Test Harness for Cost Formulas ===\n");
    println!("Scale factor: {}", args.scale);
    println!();

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

        // Compute cost components (this does interning internally)
        let start = Instant::now();
        let components = match cost_components(&allocator, node) {
            Ok(c) => c,
            Err(e) => {
                println!("{}: ERROR - {:?}", name, e);
                continue;
            }
        };
        let intern_time_us = start.elapsed().as_micros() as u64;

        results.push(TestResult {
            name: name.to_string(),
            components,
            build_time_us,
            intern_time_us,
        });
    }

    // Print results
    println!(
        "{:<25} {:>10} {:>10} {:>12} {:>10} {:>10}",
        "Test", "Atoms", "Pairs", "Bytes", "SHA Inv", "SHA Blk"
    );
    println!("{}", "-".repeat(85));

    for r in &results {
        let c = &r.components;
        println!(
            "{:<25} {:>10} {:>10} {:>12} {:>10} {:>10}",
            r.name,
            c.atom_count,
            c.pair_count,
            c.atom_bytes,
            c.sha_invocations(),
            c.sha_blocks()
        );
    }

    println!();
    println!(
        "{:<25} {:>12} {:>12} {:>14} {:>14}",
        "Test", "Balanced", "Scaled", "SHA-only", "Store-only"
    );
    println!("{}", "-".repeat(75));

    for r in &results {
        println!(
            "{:<25} {:>12} {:>12} {:>14} {:>14}",
            r.name,
            r.cost_balanced(),
            r.cost_scaled(),
            r.cost_sha_only(),
            r.cost_storage_only()
        );
    }

    // Print timing analysis
    println!();
    println!(
        "{:<25} {:>10} {:>10} {:>14} {:>14}",
        "Test", "Build μs", "Intern μs", "μs/Balanced", "μs/Scaled"
    );
    println!("{}", "-".repeat(75));

    for r in &results {
        println!(
            "{:<25} {:>10} {:>10} {:>14.6} {:>14.6}",
            r.name,
            r.build_time_us,
            r.intern_time_us,
            r.work_per_cost(r.cost_balanced()),
            r.work_per_cost(r.cost_scaled())
        );
    }

    // Identify potential issues
    println!();
    println!("=== Potential Issues ===");
    println!();

    // Find tests with highest work-per-cost ratio
    let mut by_balanced: Vec<_> = results.iter().collect();
    by_balanced.sort_by(|a, b| {
        b.work_per_cost(b.cost_balanced())
            .partial_cmp(&a.work_per_cost(a.cost_balanced()))
            .unwrap()
    });

    println!("Highest work/cost (balanced formula: bytes + 300×atoms + 500×pairs):");
    for r in by_balanced.iter().take(3) {
        println!(
            "  {}: {:.6} μs/cost (intern={}μs, cost={})",
            r.name,
            r.work_per_cost(r.cost_balanced()),
            r.intern_time_us,
            r.cost_balanced()
        );
    }

    let mut by_scaled: Vec<_> = results.iter().collect();
    by_scaled.sort_by(|a, b| {
        b.work_per_cost(b.cost_scaled())
            .partial_cmp(&a.work_per_cost(a.cost_scaled()))
            .unwrap()
    });

    println!();
    println!("Highest work/cost (scaled formula: bytes + 3000×atoms + 5000×pairs):");
    for r in by_scaled.iter().take(3) {
        println!(
            "  {}: {:.8} μs/cost (intern={}μs, cost={})",
            r.name,
            r.work_per_cost(r.cost_scaled()),
            r.intern_time_us,
            r.cost_scaled()
        );
    }

    // Compare balanced vs scaled
    println!();
    println!("=== Balanced vs Scaled Ratio ===");
    println!();

    for r in &results {
        let ratio = r.cost_scaled() as f64 / r.cost_balanced() as f64;
        println!("{}: scaled/balanced = {:.2}x", r.name, ratio);
    }

    if args.verbose {
        println!();
        println!("=== Detailed Results ===");
        for r in &results {
            println!();
            println!("{}:", r.name);
            println!("  Components:");
            println!("    atom_count: {}", r.components.atom_count);
            println!("    pair_count: {}", r.components.pair_count);
            println!("    atom_bytes: {}", r.components.atom_bytes);
            println!("    sha_atom_blocks: {}", r.components.sha_atom_blocks);
            println!("    sha_pair_blocks: {}", r.components.sha_pair_blocks);
            println!("  Timing:");
            println!("    build: {} μs", r.build_time_us);
            println!("    intern: {} μs", r.intern_time_us);
            println!("  Costs:");
            println!("    balanced (300/500): {}", r.cost_balanced());
            println!("    scaled (3000/5000): {}", r.cost_scaled());
            println!("    sha_only: {}", r.cost_sha_only());
            println!("    storage_only: {}", r.cost_storage_only());
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
