#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "numpy",
# ]
# ///
"""
Benchmark script to determine optimal ratio between COST_PER_SHA_BLOCK and
COST_PER_SHA_INVOCATION by measuring actual wall-clock time for SHA256 operations.

This script:
1. Generates test blobs of various sizes
2. Measures actual SHA256 timing using Python's hashlib
3. Tests around the 55/56 byte boundary to validate SHA padding logic
4. Fits a linear model to find the optimal cost ratio

Usage: uv run benchmark_sha_cost.py
"""

import hashlib
import time
from typing import Tuple, List
import numpy as np
from dataclasses import dataclass


@dataclass
class BenchmarkResult:
    blob_size: int
    wall_time_ns: float

    @property
    def wall_time_us(self) -> float:
        return self.wall_time_ns / 1000

    @property
    def wall_time_ms(self) -> float:
        return self.wall_time_ns / 1_000_000


def sha_block_for_size(blob_size: int) -> int:
    """
    Estimate SHA blocks for a blob of given size.
    Based on cost.rs logic:
    - Atoms have (size + 9) / 64 blocks (9 bytes for SHA256 padding)
    """
    # For a single atom blob - ceiling division: (a + b - 1) // b
    sha_blocks = (blob_size + 9 + 63) // 64
    return sha_blocks


def benchmark_function(func, blob_pool: List[bytes], iterations: int) -> list[float]:
    """
    Generic benchmark function that measures the time to call a function in a loop.
    Takes multiple trials and returns the median to avoid outliers.
    Cycles through a pool of blobs to avoid cache effects.

    Args:
        func: Callable that takes bytes and returns something (can be no-op)
        blob_pool: List of pre-generated blobs to cycle through
        iterations: Number of iterations per trial (required)

    Returns:
        Median time in nanoseconds per function call
    """

    pool_size = len(blob_pool)
    trials = []

    # Measure - cycle through blob pool
    blobs = []
    for i in range(iterations):
        blobs.append(blob_pool[i % pool_size])
    start = time.perf_counter_ns()
    for blob in blobs:
        func(blob)
    end = time.perf_counter_ns()

    total_ns = end - start
    avg_ns_per_iter = total_ns / iterations
    trials.append(avg_ns_per_iter)

    # Return median to avoid outliers
    return trials


def benchmark_overhead(
    blob_pool: List[bytes], iterations: int, num_trials: int
) -> list[float]:
    """
    Measure Python loop overhead with blob indexing and parameter passing.
    Used to subtract driver overhead from SHA benchmark results.
    Calls benchmark_function with a no-op to measure exact same overhead.
    """

    # Define a no-op function that takes a blob but does nothing
    def noop(data: bytes) -> None:
        pass

    return benchmark_function(noop, blob_pool, iterations)


def benchmark_sha256(blob_pool: List[bytes], iterations: int) -> list[float]:
    """
    Benchmark SHA256 hashing for a blob and return average time in nanoseconds.
    Takes multiple trials and returns the median for statistical robustness.
    """

    def sha256_digest(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    return benchmark_function(
        sha256_digest,
        blob_pool,
        iterations,
    )


def generate_test_cases():
    """
    Generate test cases as (blob_size, iterations, num_trials) tuples.
    Yields blob sizes with appropriate iteration counts and trial counts.
    - Small blobs: more iterations, more trials
    - Large blobs: fewer iterations, fewer trials
    """

    for _ in range(10):
        iterations = 1000

        # Small blobs - more iterations and trials
        for size in [1, 2, 5, 10, 20, 32]:
            yield size, iterations

        # Around 55-56 boundary (55+9=64, 56+9=65) - detailed testing
        for size in range(50, 70):
            yield size, iterations

        # Other block boundaries: 64-9=55, 128-9=119, 192-9=183, etc.
        for blocks in range(2, 10):
            boundary = blocks * 64 - 9
            for size in [
                boundary - 2,
                boundary - 1,
                boundary,
                boundary + 1,
                boundary + 2,
            ]:
                yield size, iterations

        # Medium to large - fewer iterations and trials
        for size in [256, 512, 1024, 2048, 4096, 8192, 16384]:
            iterations = 10000 * 256 // size
            yield size, iterations

        # Even larger blobs (100s of blocks) - minimal iterations and trials
        for blocks in [50, 75, 100, 150, 200, 256, 512, 1024]:
            size = blocks * 64 - 9
            iterations = 10000 * 256 // size
            yield size - 1, iterations
            yield size, iterations
            yield size + 1, iterations


def run_benchmark() -> dict[int, List[float]]:
    """
    Run benchmark across all test sizes and collect results.
    Returns a dictionary with size as key and list of measurements as value.
    """
    test_cases = list(generate_test_cases())

    print(f"Running benchmark with {len(test_cases)} different blob sizes...")
    # Collect all measurements in a dictionary with size as key
    results_by_size = {}

    for size, iterations in test_cases:
        # Generate blob pool once for this size
        blob_pool = [
            bytes([(i * 7 + j) & 0xFF for j in range(size)]) for i in range(10)
        ]

        # Take multiple independent measurements
        times = benchmark_sha256(blob_pool, iterations)

        # Store all measurements for this size
        results_by_size.setdefault(size, []).extend(times)

    return results_by_size


def analyze_results(results_by_size: dict[int, List[float]]) -> None:
    """
    Analyze results and fit linear model to find optimal cost ratio.
    """
    print("\n" + "=" * 80)
    print("ANALYSIS: Fitting linear model to wall-clock time")
    print("=" * 80)

    # Extract data
    medians = {size: np.median(times) for size, times in results_by_size.items()}
    sizes = sorted(medians.keys())
    sha_blocks = np.array([sha_block_for_size(size) for size in sizes])
    sha_invocations = np.array([1] * len(sizes))
    # Use median of measurements for each size
    wall_times_ns = np.array([np.median(results_by_size[size]) for size in sizes])

    # Model: time = a * blocks + b * invocations
    X = np.column_stack([sha_blocks, sha_invocations])
    coeffs = np.linalg.lstsq(X, wall_times_ns, rcond=None)[0]

    ns_per_block, ns_per_invocation = coeffs

    print(
        f"\nLinear fit: wall_time_ns = {ns_per_block:.2f} * sha_blocks + {ns_per_invocation:.2f}"
    )
    print("\nTime costs:")
    print(f"  Per SHA block:      {ns_per_block:.2f} ns")
    print(f"  Per invocation:     {ns_per_invocation:.2f} ns")
    print(f"  Ratio (invoc/block): {ns_per_invocation / ns_per_block:.2f}x")

    # Calculate R² to see how well linear model fits
    predicted = X @ coeffs
    ss_res = np.sum((wall_times_ns - predicted) ** 2)
    ss_tot = np.sum((wall_times_ns - np.mean(wall_times_ns)) ** 2)
    r_squared = 1 - (ss_res / ss_tot)

    print(f"\nModel fit quality (R²): {r_squared:.6f}")

    # Show residuals for outliers
    residuals = wall_times_ns - predicted
    std_residual = np.std(residuals)

    print("Residual statistics:")
    print(f"  Mean: {np.mean(residuals):.2f} ns")
    print(f"  Std Dev: {std_residual:.2f} ns")

    outlier_threshold = 3 * std_residual
    outliers = np.abs(residuals) > outlier_threshold
    if np.any(outliers):
        print("\n  Outliers (>3σ):")
        for i in np.where(outliers)[0]:
            print(
                f"    Size {sizes[i]}: predicted {predicted[i]:.0f} ns, actual {wall_times_ns[i]:.0f} ns, residual {residuals[i]:+.0f} ns"
            )

    # Recommendations
    print(f"\n{'=' * 80}")
    print("RECOMMENDATIONS for cost constants:")
    print(f"{'=' * 80}")

    # Normalize to blocks per nanosecond
    invocation_to_block_ratio = ns_per_invocation / ns_per_block
    print(
        f"\nEmpirical ratio of invocation time to block time: {invocation_to_block_ratio:.3f}x"
    )

    # Suggested values based on empirical ratio
    print(f"\nEmpirical ratio: {invocation_to_block_ratio:.3f}x")
    print("\nSuggested cost constant options:")
    print(
        f"  Option 1: COST_PER_SHA_BLOCK=1, COST_PER_SHA_INVOCATION={int(invocation_to_block_ratio + 0.5)}"
    )
    print(
        f"  Option 2: COST_PER_SHA_BLOCK=2, COST_PER_SHA_INVOCATION={int(2 * invocation_to_block_ratio + 0.5)}"
    )
    print(
        f"  Option 3: COST_PER_SHA_BLOCK=3, COST_PER_SHA_INVOCATION={int(3 * invocation_to_block_ratio + 0.5)}"
    )

    # Show accuracy by grouping by block count
    print(f"\n{'=' * 80}")
    print("Accuracy check by SHA block count:")
    print(f"{'=' * 80}")

    block_groups = {}
    for size in sizes:
        blocks = sha_block_for_size(size)
        if blocks not in block_groups:
            block_groups[blocks] = []
        block_groups[blocks].extend(results_by_size[size])

    for blocks in sorted(block_groups.keys())[:10]:  # Show first 10 groups
        group_results = block_groups[blocks]
        times = group_results
        print(
            f"  {blocks:2d} blocks: {len(group_results):2d} samples, avg={np.mean(times):.1f}±{np.std(times):.1f} ns (min={np.min(times):.1f}, max={np.max(times):.1f})"
        )


def validate_sha_boundaries(results_by_size: dict[int, List[float]]) -> None:
    """
    Validate SHA block boundaries using existing benchmark results.
    Checks: 55/56 (1→2), 119/120 (2→3), 183/184 (3→4) block transitions.
    Formulas: size+9 must be multiple of 64.
    - 55+9=64 → 1 block, 56+9=65 → 2 blocks
    - 119+9=128 → 2 blocks, 120+9=129 → 3 blocks
    - 183+9=192 → 3 blocks, 184+9=193 → 4 blocks
    """
    print("\n" + "=" * 80)
    print("SHA BLOCK BOUNDARY VALIDATION")
    print("=" * 80)

    # results_by_size is already in the correct format

    boundaries = [
        (list(range(50, 71)), "55/56 (1→2 blocks)"),
        (list(range(115, 126)), "119/120 (2→3 blocks)"),
        (list(range(179, 190)), "183/184 (3→4 blocks)"),
    ]

    for test_sizes, label in boundaries:
        print(f"\n{'=' * 80}")
        print(f"Boundary: {label}")
        print(f"{'=' * 80}")

        # Filter to only sizes we have data for
        available_sizes = [s for s in test_sizes if s in results_by_size]

        if not available_sizes:
            print("  No data available for this boundary range")
            continue

        print(
            f"{'Size':>6} | {'Expected Blocks':>17} | {'Measured Time (ns)':>19} | {'Time/Block (ns)':>16}"
        )
        print("-" * 80)

        measurements = {}
        for size in available_sizes:
            sha_blocks = sha_block_for_size(size)[0]
            avg_time_ns = np.median(results_by_size[size])
            measurements[size] = (sha_blocks, avg_time_ns)

            time_per_block = avg_time_ns / sha_blocks if sha_blocks > 0 else 0
            print(
                f"{size:6} | {sha_blocks:17} | {avg_time_ns:19.1f} | {time_per_block:16.2f}"
            )

        # Analyze consistency
        block_groups = {}
        for size, (blocks, interval) in measurements.items():
            if blocks not in block_groups:
                block_groups[blocks] = []
            block_groups[blocks].append(interval)

        print("\nConsistency by block count:")
        block_keys = sorted(block_groups.keys())
        for blocks in block_keys:
            times = block_groups[blocks]
            mean_time = sum(times) / len(times)
            std_time = (sum((t - mean_time) ** 2 for t in times) / len(times)) ** 0.5
            print(
                f"  {blocks}-block sizes: mean={mean_time:.1f} ns, std={std_time:.1f} ns, n={len(times)}"
            )

        # Check transition
        if len(block_keys) >= 2:
            expected_diff = 27.90  # From fitted model
            actual_diff = sum(block_groups[block_keys[1]]) / len(
                block_groups[block_keys[1]]
            ) - sum(block_groups[block_keys[0]]) / len(block_groups[block_keys[0]])
            print(
                f"\n  Expected time increase ({block_keys[0]}→{block_keys[1]} blocks): {expected_diff:.1f} ns"
            )
            print(f"  Observed time increase: {actual_diff:.1f} ns")
            match = abs(actual_diff - expected_diff) < 10
            print(f"  Match: {'✓ YES' if match else '✗ NO'} (within 10 ns)")


def measure_overhead() -> Tuple[float, float, float]:
    """
    Measure Python driver overhead before and after benchmark.
    Returns (median_overhead_before, median_overhead_after, median_overhead_average).
    """
    # First, measure Python driver overhead (before main benchmark)
    print("=" * 80)
    print(
        "MEASURING PYTHON DRIVER OVERHEAD - BEFORE (20 trials per size, using median)"
    )
    print("=" * 80)

    overhead_samples_before = []
    for size in [1, 100, 1000, 10000, 65536]:
        blob_pool = [
            bytes([(i * 7 + j) & 0xFF for j in range(size)]) for i in range(10)
        ]
        overhead_ns = benchmark_overhead(blob_pool, iterations=1000, num_trials=20)
        overhead_samples_before.extend(overhead_ns)
        median = overhead_ns[len(overhead_ns) // 2]
        print(f"  Size {size:6}: {median:8.2f} ns overhead per iteration")

    # Use median of all samples to avoid outliers
    print(
        f"\nAll overhead samples (before): {[f'{x:.2f}' for x in overhead_samples_before]}"
    )
    overhead_samples_before.sort()
    median_overhead_before = overhead_samples_before[len(overhead_samples_before) // 2]
    print(
        f"Median Python overhead (before): {median_overhead_before:.2f} ns per iteration\n"
    )

    # Measure overhead again after benchmark (system is now warmed up)
    print("\n" + "=" * 80)
    print("MEASURING PYTHON DRIVER OVERHEAD - AFTER (20 trials per size, using median)")
    print("=" * 80)

    overhead_samples_after = []
    for size in [1, 100, 1000, 10000, 65536]:
        blob_pool = [
            bytes([(i * 7 + j) & 0xFF for j in range(size)]) for i in range(10)
        ]
        overhead_ns = benchmark_overhead(blob_pool, iterations=1000, num_trials=20)
        overhead_samples_after.extend(overhead_ns)

    overhead_samples_after.sort()
    median_overhead_after = overhead_samples_after[len(overhead_samples_after) // 2]
    print(
        f"\nAll overhead samples (after): {[f'{x:.2f}' for x in overhead_samples_after]}"
    )
    print(
        f"Median Python overhead (after): {median_overhead_after:.2f} ns per iteration"
    )

    # Use the average of before and after medians
    median_overhead = (median_overhead_before + median_overhead_after) / 2
    print(f"\nUsing average of before/after: {median_overhead:.2f} ns per iteration")
    print("This will be subtracted from SHA measurements to get true SHA cost.\n")

    return median_overhead_before, median_overhead_after, median_overhead


def print_results_table(results_by_size: dict[int, List[float]]) -> None:
    """
    Print the results table showing average time and efficiency for each size.
    """
    print("-" * 80)
    print(
        f"{'Size':>6} | {'Blocks':>7} | {'Invocs':>7} | {'Avg Time (μs)':>15} | {'Efficiency (ns/block)':>20}"
    )
    print("-" * 80)

    sizes = sorted(results_by_size.keys())
    for size in sizes:
        sha_blocks = sha_block_for_size(size)
        times = results_by_size[size]
        avg_time_ns = sum(times) / len(times)
        ns_per_block = avg_time_ns / sha_blocks if sha_blocks > 0 else 0
        print(
            f"{size:6} | {sha_blocks:7} | {1:7} | {avg_time_ns / 1000:15.2f} | {ns_per_block:20.2f}"
        )


def report_results(
    results_by_size: dict[int, List[float]], median_overhead: float
) -> None:
    """
    Print analysis and final report of benchmark results.
    """
    analyze_results(results_by_size)
    # validate_sha_boundaries(results_by_size)

    # Print final linear function summary
    print("\n" + "=" * 80)
    print("FINAL LINEAR MODEL")
    print("=" * 80)

    # Re-extract data and compute final coefficients for clean output
    sizes = sorted(results_by_size.keys())
    sha_blocks = np.array([sha_block_for_size(size) for size in sizes])
    sha_invocations = np.array([1 for size in sizes])
    # Use median of measurements for each size
    wall_times_ns = np.array([np.median(results_by_size[size]) for size in sizes])

    X = np.column_stack([sha_blocks, sha_invocations])
    coeffs = np.linalg.lstsq(X, wall_times_ns, rcond=None)[0]
    ns_per_block, ns_per_invocation = coeffs

    # Recalculate with Python overhead removed
    # We measured median overhead, subtract it from invocation cost
    ns_per_invocation_adjusted = ns_per_invocation - median_overhead

    ratio = ns_per_invocation / ns_per_block

    # Check for invalid adjusted values
    if ns_per_invocation_adjusted <= 0:
        print(
            f"\n⚠️  WARNING: Adjusted per-block cost is {ns_per_invocation_adjusted:.2f} ns (non-positive!)"
        )
        print(
            f"   Raw per-block: {ns_per_block:.2f} ns, Overhead: {median_overhead:.2f} ns"
        )
        print("   This suggests overhead measurement is too high or noisy.")
        print("   Using raw measurements instead.\n")
        ns_per_invocation_adjusted = ns_per_invocation
        median_overhead = 0.0
        ratio_adjusted = ratio
    else:
        ratio_adjusted = ns_per_invocation_adjusted / ns_per_block

    print("\nRaw measurements (including Python overhead):")
    print(f"  wall_time_ns = {ns_per_block:.2f} * sha_blocks + {ns_per_invocation:.2f}")

    print(
        f"\nAdjusted measurements (Python overhead removed: {median_overhead:.2f} ns):"
    )
    print(
        f"  wall_time_ns = {ns_per_block:.2f} * sha_blocks + {ns_per_invocation_adjusted:.2f}"
    )

    print(f"\nRaw ratio (invocation / block): {ratio:.2f}x")
    print(f"Adjusted ratio (invocation / block): {ratio_adjusted:.2f}x")

    print(f"\n{'=' * 80}")
    print("FINAL LINEAR MODEL (Python overhead removed)")
    print(f"{'=' * 80}")
    print(
        f"\nwall_time_ns = {ns_per_block:.2f} * sha_blocks + {ns_per_invocation_adjusted:.2f}"
    )
    print("\nOr equivalently:")
    print(
        f"cost = {ns_per_block:.2f} ns/block * block_count + {ns_per_invocation_adjusted:.2f} ns/invocation * invocation_count"
    )
    print("\nRelative costs:")
    print(f"  Invocation overhead is {ratio_adjusted:.2f}x the per-block cost")


if __name__ == "__main__":
    median_overhead_before, median_overhead_after, median_overhead = measure_overhead()

    # Run benchmark multiple times and collect all results
    all_results = run_benchmark()

    # Print the results table
    print_results_table(all_results)

    # Report the final analysis
    report_results(all_results, median_overhead)
