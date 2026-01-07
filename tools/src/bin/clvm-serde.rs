use clap::{Parser, ValueEnum};
use clvmr::allocator::Allocator;
use clvmr::serde::{
    deserialize_2026, intern, node_from_bytes, node_from_bytes_backrefs, node_to_bytes,
    node_to_bytes_backrefs, serialize_2026, treehash, InternedStats, ObjectCache,
};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
enum Format {
    /// Classic CLVM serialization (no compression)
    Classic,
    /// CLVM with back-references (0xfe compression)
    Backref,
    /// 2026 serialization format (intern-based)
    Ser2026,
}

/// A tool for converting between CLVM serialization formats and computing tree hashes
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input file or directory path (directory requires --batch)
    input: String,

    /// Input format (if not specified, will try backref then classic)
    #[arg(short = 'f', long)]
    input_format: Option<Format>,

    /// Output file path (if not specified, only prints hash)
    #[arg(short, long)]
    output: Option<String>,

    /// Output format (required if output is specified)
    #[arg(short = 't', long, requires = "output")]
    output_format: Option<Format>,

    /// Run benchmarks for deserialization and serialization
    #[arg(short, long, default_value_t = false)]
    benchmark: bool,

    /// Number of iterations for benchmarking
    #[arg(short = 'n', long, default_value_t = 100)]
    iterations: u32,

    /// Print sizes of each format
    #[arg(short, long, default_value_t = false)]
    sizes: bool,

    /// Print interned statistics (for cost formula tuning)
    #[arg(long, default_value_t = false)]
    stats: bool,

    /// Batch mode: process all .bin files in directory (recursive)
    #[arg(long, default_value_t = false)]
    batch: bool,

    /// Output CSV file for batch analysis
    #[arg(long)]
    csv: Option<String>,

    /// B coefficient for size component (per atom byte)
    #[arg(long, default_value_t = 1)]
    coef_b: u64,

    /// A coefficient for size component (per atom)
    #[arg(long, default_value_t = 2)]
    coef_a: u64,

    /// P coefficient for size component (per pair)
    #[arg(long, default_value_t = 2)]
    coef_p: u64,

    /// S coefficient for SHA component (per sha_block)
    #[arg(long, default_value_t = 1)]
    coef_s: u64,

    /// I coefficient for SHA component (per sha_invocation)
    #[arg(long, default_value_t = 8)]
    coef_i: u64,

    /// SIZE_COST_PER_BYTE multiplier for size component
    #[arg(long, default_value_t = 6000)]
    size_cost_per_byte: u64,

    /// SHA_COST_PER_UNIT multiplier for SHA component
    #[arg(long, default_value_t = 4500)]
    sha_cost_per_unit: u64,

    /// Old COST_PER_BYTE for comparison
    #[arg(long, default_value_t = 12000)]
    old_cost_per_byte: u64,
}

fn deserialize(
    allocator: &mut Allocator,
    data: &[u8],
    format: Option<Format>,
) -> Result<clvmr::allocator::NodePtr, String> {
    match format {
        Some(Format::Classic) => node_from_bytes(allocator, data)
            .map_err(|e| format!("Failed to parse as classic: {:?}", e)),
        Some(Format::Backref) => node_from_bytes_backrefs(allocator, data)
            .map_err(|e| format!("Failed to parse as backref: {:?}", e)),
        Some(Format::Ser2026) => deserialize_2026(allocator, data)
            .map_err(|e| format!("Failed to parse as 2026: {:?}", e)),
        None => {
            // Try backref first (backward compatible with classic), then 2026
            if let Ok(node) = node_from_bytes_backrefs(allocator, data) {
                return Ok(node);
            }
            // Try 2026 format
            deserialize_2026(allocator, data)
                .map_err(|e| format!("Failed to parse (tried backref/classic and 2026): {:?}", e))
        }
    }
}

fn serialize(
    allocator: &Allocator,
    node: clvmr::allocator::NodePtr,
    format: Format,
) -> Result<Vec<u8>, String> {
    match format {
        Format::Classic => {
            node_to_bytes(allocator, node).map_err(|e| format!("Failed to serialize: {:?}", e))
        }
        Format::Backref => node_to_bytes_backrefs(allocator, node)
            .map_err(|e| format!("Failed to serialize: {:?}", e)),
        Format::Ser2026 => {
            serialize_2026(allocator, node).map_err(|e| format!("Failed to serialize: {:?}", e))
        }
    }
}

fn compute_tree_hash(allocator: &Allocator, node: clvmr::allocator::NodePtr) -> [u8; 32] {
    let mut cache = ObjectCache::new(treehash);
    *cache.get_or_calculate(allocator, &node, None).unwrap()
}

fn compute_stats(
    allocator: &Allocator,
    node: clvmr::allocator::NodePtr,
) -> Result<InternedStats, String> {
    let tree = intern(allocator, node).map_err(|e| format!("Failed to intern: {:?}", e))?;
    Ok(tree.stats())
}

fn format_name(format: Format) -> &'static str {
    match format {
        Format::Classic => "classic",
        Format::Backref => "backref",
        Format::Ser2026 => "2026",
    }
}

/// Record for CSV output
#[derive(Debug)]
struct AnalysisRecord {
    filename: String,
    input_size: usize,
    classic_size: usize,
    backref_size: usize,
    ser2026_size: usize,
    atom_count: u64,
    pair_count: u64,
    atom_bytes: u64,
    sha_blocks: u64,
    sha_invocations: u64,
    size_component: u64,
    sha_component: u64,
    blended_cost: u64,
    old_cost: u64,
    cost_ratio: f64,
    size_pct: f64,
    tree_hash: String,
}

#[derive(Clone, Copy)]
struct CostParams {
    coef_b: u64,
    coef_a: u64,
    coef_p: u64,
    coef_s: u64,
    coef_i: u64,
    size_cost_per_byte: u64,
    sha_cost_per_unit: u64,
    old_cost_per_byte: u64,
}

fn analyze_file(
    path: &Path,
    input_format: Option<Format>,
    params: CostParams,
) -> Result<AnalysisRecord, String> {
    let data = fs::read(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let input_size = data.len();

    let mut allocator = Allocator::new();
    let node = deserialize(&mut allocator, &data, input_format)?;

    // Compute tree hash
    let hash = compute_tree_hash(&allocator, node);
    let tree_hash = hex::encode(hash);

    // Compute sizes
    let classic_size = serialize(&allocator, node, Format::Classic)
        .map(|b| b.len())
        .unwrap_or(0);
    let backref_size = serialize(&allocator, node, Format::Backref)
        .map(|b| b.len())
        .unwrap_or(0);
    let ser2026_size = serialize(&allocator, node, Format::Ser2026)
        .map(|b| b.len())
        .unwrap_or(0);

    // Compute interned stats
    let stats = compute_stats(&allocator, node)?;

    // Calculate blended cost
    let size_component = params.coef_b * stats.atom_bytes
        + params.coef_a * stats.atom_count
        + params.coef_p * stats.pair_count;
    let sha_component =
        params.coef_s * stats.sha_blocks() + params.coef_i * stats.sha_invocations();
    let blended_cost =
        size_component * params.size_cost_per_byte + sha_component * params.sha_cost_per_unit;
    let old_cost = backref_size as u64 * params.old_cost_per_byte;
    let cost_ratio = if old_cost > 0 {
        blended_cost as f64 / old_cost as f64
    } else {
        0.0
    };
    let size_pct = if blended_cost > 0 {
        (size_component * params.size_cost_per_byte) as f64 / blended_cost as f64 * 100.0
    } else {
        0.0
    };

    Ok(AnalysisRecord {
        filename: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        input_size,
        classic_size,
        backref_size,
        ser2026_size,
        atom_count: stats.atom_count,
        pair_count: stats.pair_count,
        atom_bytes: stats.atom_bytes,
        sha_blocks: stats.sha_blocks(),
        sha_invocations: stats.sha_invocations(),
        size_component,
        sha_component,
        blended_cost,
        old_cost,
        cost_ratio,
        size_pct,
        tree_hash,
    })
}

fn collect_bin_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut files = Vec::new();

    fn visit_dir(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
        let entries = fs::read_dir(dir).map_err(|e| format!("Failed to read dir: {}", e))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let path = entry.path();
            if path.is_dir() {
                visit_dir(&path, files)?;
            } else if path.extension().map(|e| e == "bin").unwrap_or(false) {
                files.push(path);
            }
        }
        Ok(())
    }

    visit_dir(dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn write_csv(records: &[AnalysisRecord], path: &str) -> Result<(), String> {
    let file = fs::File::create(path).map_err(|e| format!("Failed to create CSV: {}", e))?;
    let mut writer = BufWriter::new(file);

    // Header
    writeln!(
        writer,
        "filename,input_size,classic_size,backref_size,ser2026_size,atom_count,pair_count,atom_bytes,sha_blocks,sha_invocations,size_component,sha_component,blended_cost,old_cost,cost_ratio,size_pct,tree_hash"
    )
    .map_err(|e| format!("Failed to write CSV header: {}", e))?;

    // Data rows
    for r in records {
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.4},{:.1},{}",
            r.filename,
            r.input_size,
            r.classic_size,
            r.backref_size,
            r.ser2026_size,
            r.atom_count,
            r.pair_count,
            r.atom_bytes,
            r.sha_blocks,
            r.sha_invocations,
            r.size_component,
            r.sha_component,
            r.blended_cost,
            r.old_cost,
            r.cost_ratio,
            r.size_pct,
            r.tree_hash
        )
        .map_err(|e| format!("Failed to write CSV row: {}", e))?;
    }

    writer
        .flush()
        .map_err(|e| format!("Failed to flush CSV: {}", e))?;
    Ok(())
}

fn benchmark_deserialize(
    data: &[u8],
    format: Option<Format>,
    iterations: u32,
) -> Result<std::time::Duration, String> {
    let mut total = std::time::Duration::ZERO;

    for _ in 0..iterations {
        let mut allocator = Allocator::new();
        let start = Instant::now();
        let _ = deserialize(&mut allocator, data, format)?;
        total += start.elapsed();
    }

    Ok(total / iterations)
}

fn benchmark_serialize(
    allocator: &Allocator,
    node: clvmr::allocator::NodePtr,
    format: Format,
    iterations: u32,
) -> Result<std::time::Duration, String> {
    let mut total = std::time::Duration::ZERO;

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = serialize(allocator, node, format)?;
        total += start.elapsed();
    }

    Ok(total / iterations)
}

fn run_batch(args: &Args) -> Result<(), String> {
    let dir = Path::new(&args.input);
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", args.input));
    }

    let files = collect_bin_files(dir)?;
    println!("Found {} .bin files", files.len());

    let mut records = Vec::new();
    let mut errors = Vec::new();

    let params = CostParams {
        coef_b: args.coef_b,
        coef_a: args.coef_a,
        coef_p: args.coef_p,
        coef_s: args.coef_s,
        coef_i: args.coef_i,
        size_cost_per_byte: args.size_cost_per_byte,
        sha_cost_per_unit: args.sha_cost_per_unit,
        old_cost_per_byte: args.old_cost_per_byte,
    };

    for (i, path) in files.iter().enumerate() {
        eprint!(
            "\rProcessing {}/{}: {}",
            i + 1,
            files.len(),
            path.file_name().unwrap_or_default().to_string_lossy()
        );

        match analyze_file(path, args.input_format, params) {
            Ok(record) => records.push(record),
            Err(e) => errors.push((path.clone(), e)),
        }
    }
    eprintln!(); // newline after progress

    println!("\nProcessed {} files successfully", records.len());
    if !errors.is_empty() {
        println!("{} files failed:", errors.len());
        for (path, err) in &errors {
            println!("  {}: {}", path.display(), err);
        }
    }

    // Summary statistics
    if !records.is_empty() {
        let total_input: usize = records.iter().map(|r| r.input_size).sum();
        let total_backref: usize = records.iter().map(|r| r.backref_size).sum();
        let total_blended: u64 = records.iter().map(|r| r.blended_cost).sum();
        let total_old: u64 = records.iter().map(|r| r.old_cost).sum();
        let avg_ratio: f64 =
            records.iter().map(|r| r.cost_ratio).sum::<f64>() / records.len() as f64;
        let avg_size_pct: f64 =
            records.iter().map(|r| r.size_pct).sum::<f64>() / records.len() as f64;
        let min_ratio = records
            .iter()
            .map(|r| r.cost_ratio)
            .min_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);
        let max_ratio = records
            .iter()
            .map(|r| r.cost_ratio)
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);

        println!(
            "\nBlended Cost Summary (B={}, A={}, P={}, S={}, I={}):",
            args.coef_b, args.coef_a, args.coef_p, args.coef_s, args.coef_i
        );
        println!(
            "  SIZE_COST_PER_BYTE={}, SHA_COST_PER_UNIT={}",
            args.size_cost_per_byte, args.sha_cost_per_unit
        );
        println!("  Total input size:   {} bytes", total_input);
        println!("  Total backref size: {} bytes", total_backref);
        println!("  Total blended cost: {}", total_blended);
        println!("  Total old cost:     {}", total_old);
        println!(
            "  Cost ratio (new/old): min={:.4}, avg={:.4}, max={:.4}",
            min_ratio, avg_ratio, max_ratio
        );
        println!(
            "  Avg size/sha split: {:.1}% / {:.1}%",
            avg_size_pct,
            100.0 - avg_size_pct
        );

        // Find outliers
        let outliers: Vec<_> = records
            .iter()
            .filter(|r| r.cost_ratio < 0.5 || r.cost_ratio > 2.0)
            .collect();
        if !outliers.is_empty() {
            println!("\nOutliers (ratio < 0.5 or > 2.0):");
            for r in outliers.iter().take(10) {
                println!(
                    "  {} ratio={:.4} (blended={}, old={})",
                    r.filename, r.cost_ratio, r.blended_cost, r.old_cost
                );
            }
            if outliers.len() > 10 {
                println!("  ... and {} more", outliers.len() - 10);
            }
        }
    }

    // Write CSV if requested
    if let Some(csv_path) = &args.csv {
        write_csv(&records, csv_path)?;
        println!("\nCSV written to: {}", csv_path);
    }

    Ok(())
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    // Batch mode
    if args.batch {
        return run_batch(&args);
    }

    // Single file mode
    let input_path = Path::new(&args.input);
    if input_path.is_dir() {
        return Err("Input is a directory. Use --batch for batch processing.".to_string());
    }

    // Read input file
    let data = fs::read(&args.input).map_err(|e| format!("Failed to read input file: {}", e))?;

    println!("Input: {} ({} bytes)", args.input, data.len());

    // Deserialize
    let mut allocator = Allocator::new();
    let node = deserialize(&mut allocator, &data, args.input_format)?;

    if let Some(fmt) = args.input_format {
        println!("Input format: {}", format_name(fmt));
    } else {
        println!("Input format: auto-detected (backref/classic)");
    }

    // Compute and print tree hash
    let hash = compute_tree_hash(&allocator, node);
    println!("Tree hash: {}", hex::encode(hash));

    // Print sizes if requested
    if args.sizes {
        println!("\nSizes:");
        for fmt in [Format::Classic, Format::Backref, Format::Ser2026] {
            match serialize(&allocator, node, fmt) {
                Ok(bytes) => println!("  {}: {} bytes", format_name(fmt), bytes.len()),
                Err(e) => println!("  {}: error - {}", format_name(fmt), e),
            }
        }
    }

    // Print interned stats if requested
    if args.stats {
        let stats = compute_stats(&allocator, node)?;
        println!("\nInterned Statistics:");
        println!("  atom_count:      {}", stats.atom_count);
        println!("  pair_count:      {}", stats.pair_count);
        println!(
            "  atom_bytes:      {} (sum of all atom lengths)",
            stats.atom_bytes
        );
        println!(
            "  sha_atom_blocks: {} (for atom hashing)",
            stats.sha_atom_blocks
        );
        println!(
            "  sha_pair_blocks: {} (for pair hashing)",
            stats.sha_pair_blocks()
        );
        println!("  ---");
        println!("  sha_blocks:      {} (total)", stats.sha_blocks());
        println!(
            "  sha_invocations: {} (atom_count + pair_count)",
            stats.sha_invocations()
        );

        // Blended cost calculation (50% size + 50% SHA)
        let size_component = args.coef_b * stats.atom_bytes
            + args.coef_a * stats.atom_count
            + args.coef_p * stats.pair_count;
        let sha_component =
            args.coef_s * stats.sha_blocks() + args.coef_i * stats.sha_invocations();
        let blended_cost =
            size_component * args.size_cost_per_byte + sha_component * args.sha_cost_per_unit;

        let backref_size = serialize(&allocator, node, Format::Backref)
            .map(|b| b.len())
            .unwrap_or(0) as u64;
        let old_cost = backref_size * args.old_cost_per_byte;

        let ratio = if old_cost > 0 {
            blended_cost as f64 / old_cost as f64
        } else {
            0.0
        };

        let size_pct = if blended_cost > 0 {
            (size_component * args.size_cost_per_byte) as f64 / blended_cost as f64 * 100.0
        } else {
            0.0
        };

        println!(
            "\nBlended Cost Formula (B={}, A={}, P={}, S={}, I={}):",
            args.coef_b, args.coef_a, args.coef_p, args.coef_s, args.coef_i
        );
        println!(
            "  size_component = {}×{} + {}×{} + {}×{} = {}",
            args.coef_b,
            stats.atom_bytes,
            args.coef_a,
            stats.atom_count,
            args.coef_p,
            stats.pair_count,
            size_component
        );
        println!(
            "  sha_component  = {}×{} + {}×{} = {}",
            args.coef_s,
            stats.sha_blocks(),
            args.coef_i,
            stats.sha_invocations(),
            sha_component
        );
        println!("  ---");
        println!(
            "  size_cost  = {} × {} = {}",
            size_component,
            args.size_cost_per_byte,
            size_component * args.size_cost_per_byte
        );
        println!(
            "  sha_cost   = {} × {} = {}",
            sha_component,
            args.sha_cost_per_unit,
            sha_component * args.sha_cost_per_unit
        );
        println!(
            "  blended    = {} ({:.1}% size, {:.1}% sha)",
            blended_cost,
            size_pct,
            100.0 - size_pct
        );
        println!("  ---");
        println!("  backref_size = {}", backref_size);
        println!(
            "  old_cost     = {} × {} = {}",
            backref_size, args.old_cost_per_byte, old_cost
        );
        println!("  ratio (new/old) = {:.4}", ratio);
    }

    // Benchmark if requested
    if args.benchmark {
        println!("\nBenchmarks ({} iterations):", args.iterations);

        // Benchmark deserialization of input
        println!("  Deserialization:");
        let deser_time = benchmark_deserialize(&data, args.input_format, args.iterations)?;
        println!(
            "    input ({}): {:?}",
            args.input_format.map(format_name).unwrap_or("auto"),
            deser_time
        );

        // Benchmark deserialization of each format
        for fmt in [Format::Classic, Format::Backref, Format::Ser2026] {
            if let Ok(serialized) = serialize(&allocator, node, fmt) {
                if let Ok(time) = benchmark_deserialize(&serialized, Some(fmt), args.iterations) {
                    println!("    {}: {:?}", format_name(fmt), time);
                }
            }
        }

        // Benchmark serialization
        println!("  Serialization:");
        for fmt in [Format::Classic, Format::Backref, Format::Ser2026] {
            match benchmark_serialize(&allocator, node, fmt, args.iterations) {
                Ok(time) => println!("    {}: {:?}", format_name(fmt), time),
                Err(e) => println!("    {}: error - {}", format_name(fmt), e),
            }
        }
    }

    // Write output if specified
    if let Some(output_path) = args.output {
        let output_format = args
            .output_format
            .ok_or("Output format is required when output path is specified")?;

        let output_data = serialize(&allocator, node, output_format)?;

        let mut file = fs::File::create(&output_path)
            .map_err(|e| format!("Failed to create output file: {}", e))?;
        file.write_all(&output_data)
            .map_err(|e| format!("Failed to write output file: {}", e))?;

        println!(
            "\nOutput: {} ({} bytes, {} format)",
            output_path,
            output_data.len(),
            format_name(output_format)
        );
    }

    Ok(())
}
