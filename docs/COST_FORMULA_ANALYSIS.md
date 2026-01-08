# Generator Identity and Cost: A Content-Addressable Approach

This document explains the hard fork changes to generator identity and cost calculation, the reasoning behind the new formulas, and the DoS analysis that validates their safety.

## Executive Summary

This hard fork makes two fundamental changes to how generators are identified and charged:

1. **Identity**: Generator identity changes from `SHA256(serialized_bytes)` to `SHA256_tree_hash(generator)`
2. **Cost**: Generator cost changes from `len(serialized_bytes) × 12000` to a blended formula based on tree structure

Both changes serve the same goal: **make consensus depend on the logical content of the generator, not its serialization format**.

This decouples consensus from serialization, enabling future compression improvements without hard forks.

---

## The Problem: Serialization-Coupled Consensus

### Current State

Today, generator identity and cost are both tied to serialization:

```
identity = SHA256(serialized_bytes)
cost = len(serialized_bytes) × COST_PER_BYTE
```

This creates several problems:

1. **Format lock-in**: Any change to serialization format changes the generator's identity, breaking consensus compatibility.

2. **Compression penalties**: Better compression → smaller bytes → different hash. A more efficient representation of the _same logical tree_ would have a different identity.

3. **Cost inconsistency**: The same logical tree serialized differently would have different costs, even though the actual work to process it is identical.

### The Solution: Content-Addressable Identity

After the hard fork:

```
identity = SHA256_tree_hash(generator)  // Content-addressable
cost = f(interned_tree_structure)       // Structure-based
```

**Key insight**: Two generators with the same tree hash contain the same logical content. They should have the same identity and cost, regardless of how they were serialized.

This means:

- Classic serialization (no compression)
- Backref serialization (some sharing)
- 2026 serialization (full interning)
- Future formats we haven't invented yet

...can all represent the same generator with the **same identity and same cost**.

---

## Why This Matters: Future-Proofing Consensus

### Enabling Better Compression

With serialization-coupled consensus, any compression improvement requires a hard fork because it changes generator hashes.

With content-addressable identity, we can:

- Improve compression algorithms without consensus changes
- Add new serialization formats transparently
- Optimize wire protocol independently of validation

The generator's identity is its _content_, not its _encoding_.

### The Interning Requirement

To ensure `same content = same cost`, we must **intern** the generator before computing cost:

```
Any serialization → deserialize → intern → canonical tree → deterministic cost
```

Interning deduplicates the tree, producing a canonical representation where:

- Identical atoms share the same node
- Identical subtrees share the same node

After interning, cost becomes a pure function of tree structure, independent of how the tree arrived.

---

## The New Cost Formula

### Why Not Just Use Serialized Size?

With content-addressable identity, we can't use serialized size for cost because:

1. Different serializations of the same tree would have different costs
2. We want `same tree hash = same cost`

We need a cost formula based on the **interned tree structure**.

### The Blended Formula

```
size_component = B×atom_bytes + A×atom_count + P×pair_count
sha_component  = S×sha_blocks + I×sha_invocations

total_cost = size_component × SIZE_COST_PER_BYTE
           + sha_component × SHA_COST_PER_UNIT
```

**Constants:**
| Constant | Value | Purpose |
|----------|-------|---------|
| B | 1 | Per byte of atom data |
| A | 2 | Per-atom overhead |
| P | 2 | Per-pair overhead |
| S | 1 | Per SHA256 block (64 bytes) |
| I | 8 | Per SHA256 invocation |
| SIZE_COST_PER_BYTE | 6000 | Size component multiplier |
| SHA_COST_PER_UNIT | 4500 | SHA component multiplier |

### Why Two Components?

The formula protects against **two distinct DoS vectors**:

**1. Memory/Storage DoS**

- Attack: Create structures expensive to store but cheap to hash
- Protection: Size component charges for structural overhead

**2. CPU/Hashing DoS**

- Attack: Create structures with many small nodes (cheap in bytes, expensive to hash)
- Protection: SHA component charges for hashing work

By splitting ~50/50, neither attack vector can exploit the other's blind spot.

### Why SHA Invocation Cost Matters

SHA256 has significant per-invocation overhead beyond the per-block mixing cost:

| Hardware   | Per Block | Per Invocation | Ratio |
| ---------- | --------- | -------------- | ----- |
| Apple M4   | 19 ns     | 151 ns         | 7.9×  |
| Intel 2012 | 520 ns    | 3,465 ns       | 6.7×  |

A tree with 1000 tiny atoms incurs 1000 invocations regardless of total bytes. Without the `I=8` coefficient, such structures would be severely undercharged.

---

## DoS Analysis and Validation

### Adversarial Structures Tested

| Structure           | Description            | DoS Vector            |
| ------------------- | ---------------------- | --------------------- |
| `million_nil_atoms` | Many zero-byte atoms   | High invocation count |
| `deep_nesting`      | Deeply nested pairs    | High pair count       |
| `single_huge_atom`  | One ~100KB atom        | Large data payload    |
| `many_small_pairs`  | Many independent pairs | High pair count       |
| `hash_sized_atoms`  | Many 32-byte atoms     | Typical puzzle data   |

### Results: New vs Old Cost

```
Ratio > 1.0 means new formula charges MORE (safer)
Ratio < 1.0 means new formula charges LESS

  ⚠ single_huge_atom: 0.51x  (large data - NOT a DoS vector)
  ⚠ hash_sized_atoms: 0.70x  (typical data - NOT a DoS vector)
  ✓ balanced_tree:    1.93x
  ✓ million_tiny_atoms: 2.17x
  ✓ many_small_pairs: 2.25x
  ✓ deep_nesting:     2.37x
  ✓ million_nil_atoms: 2.37x
```

**Key finding**: All adversarial structures (many small nodes, deep nesting) cost **2x+ more** than before. The structures that cost less are large-data payloads, which have the _lowest_ work-per-cost ratio and are not DoS vectors.

### Cross-Hardware Validation

| Hardware                   | Per Block | Per Invocation | I/S Ratio |
| -------------------------- | --------- | -------------- | --------- |
| **Apple M4** (2024)        | 19 ns     | 151 ns         | 7.9×      |
| **Intel 2012** (no SHA-NI) | 520 ns    | 3,465 ns       | 6.7×      |

The I/S ratio is consistent (6.7-7.9×) across hardware. Using `I=8` is conservative on all tested platforms.

### Worst-Case Validation Times

For maximum-cost adversarial generators:

| Hardware                     | Size-Only Formula | Blended Formula | Protection |
| ---------------------------- | ----------------- | --------------- | ---------- |
| **Apple M4**                 | 174 ms            | 37 ms           | 4.7×       |
| **Raspberry Pi 5** (est.)    | ~700 ms           | ~150 ms         | 4.7×       |
| **Intel 2012** (unsupported) | 4.1 sec           | 870 ms          | 4.7×       |

**Conclusion**:

- Supported hardware: <200 ms worst case ✅
- Unsupported legacy: <1 sec best-effort ✅
- Consistent 4.7× protection improvement ✅

---

## Fitting Methodology

### SHA256 Timing Benchmark

**Tool**: `tools/benchmark_sha_cost.py`

1. Hash blobs of varying sizes (1 byte to 64KB)
2. Test around SHA256 block boundaries (55/56, 119/120 bytes)
3. Fit linear model: `time = ns_per_block × blocks + ns_per_invocation`
4. Extract I/S ratio

**Result**: I/S ≈ 8 (invocation overhead is 8× block cost)

### Cost Coefficient Fitting

**Data**: Synthetic generators built from real mainnet spends (excluding NFT JPEGs)

**Goal**: Find multipliers such that:

- Total cost ≈ old cost for typical generators (backward compatible)
- ~50% from size component, ~50% from SHA component

**Results**:

| Generator      | Blended Cost | Old Cost | Ratio | Split |
| -------------- | ------------ | -------- | ----- | ----- |
| synthetic_1M   | 2,821M       | 2,936M   | 96%   | 45/55 |
| synthetic_500K | 1,592M       | 1,503M   | 106%  | 44/56 |

---

## Implications: Maximum Block Size Increase

### Large Atoms Cost Less Than Before

A consequence of the blended formula is that **large single atoms cost less** than under the old formula:

| Formula | Cost for N-byte atom                       | Max atom at 11B limit |
| ------- | ------------------------------------------ | --------------------- |
| **Old** | `N × 12000`                                | ~895 KB               |
| **New** | `(N+2) × 6000 + (N/64+9) × 4500` ≈ `6070N` | **~1.81 MB**          |

The new formula allows single atoms **~2× larger** for the same cost because:

1. `SIZE_COST_PER_BYTE = 6000` (half of old 12000)
2. SHA overhead for large atoms is minimal (one invocation, blocks proportional to size)

### Why This Happens

Large atoms are the _safest_ structure from a DoS perspective - they have the lowest work-per-cost ratio. The old formula was effectively _overcharging_ for large data payloads.

The blended formula shifts cost toward structures with high node counts (where SHA invocation overhead matters), not raw byte volume.

### Potential Concern: Blockchain Storage Abuse

⚠️ **This could enable cheaper on-chain storage.**

A farmer could create a spend with a large atom in a "garbage" solution containing incompressible data:

- Old formula: ~895 KB max per block at cost limit
- New formula: ~1.81 MB max per block at cost limit

This roughly **doubles the potential storage per block** for someone willing to burn the cost.

### Assessment

This is a **known trade-off**, not an oversight:

1. **DoS protection was the priority**: The old formula left CPU-bound attacks undercharged by 4.7×. Fixing that was more important than preventing storage abuse.

2. **Storage abuse is self-limiting**: Attackers must pay full cost (in fees) for the space. Unlike DoS attacks, storage abuse doesn't let you do more work than you pay for.

3. **Compression still helps**: Real generators with structure (not random data) still benefit from sharing. Only incompressible garbage blobs get "cheaper."

4. **Future mitigation possible**: If storage abuse becomes a problem, the `SIZE_COST_PER_BYTE` multiplier could be increased in a future fork without changing the formula structure.

**Bottom line**: We traded slightly cheaper storage for 4.7× better DoS protection. This seems like the right trade-off since DoS attacks are a consensus/security issue, while storage abuse is an economics issue.

---

## Summary

### What's Changing

| Aspect                 | Before                     | After                        |
| ---------------------- | -------------------------- | ---------------------------- |
| **Identity**           | `SHA256(serialized_bytes)` | `SHA256_tree_hash(tree)`     |
| **Cost basis**         | Serialized length          | Interned tree structure      |
| **Consensus coupling** | Tied to serialization      | Independent of serialization |

### Why It's Safe

1. ✅ All adversarial structures cost 2x+ more than before
2. ✅ Typical generators cost 96-106% of old (backward compatible)
3. ✅ Maximum work/cost ratio is bounded across hardware
4. ✅ SHA invocation overhead properly captured (I=8)
5. ✅ Formula validated on both fast (M4) and slow (2012 Intel) hardware

### Why It's Better

1. **Content-addressable identity**: Same logical tree = same identity
2. **Serialization independence**: Future compression doesn't break consensus
3. **DoS protection**: 4.7× better protection against CPU-bound attacks
4. **Cleaner semantics**: Cost reflects actual work, not encoding artifact

---

## Appendix: Benchmark Commands

```bash
# SHA256 timing benchmark
uv run tools/benchmark_sha_cost.py

# DoS test with adversarial structures
cargo run --release -p clvm-rs-test-tools --bin dos-test

# Analyze synthetic generators
cargo run --release -p clvm-rs-test-tools --bin clvm-serde -- synthetic_1M.bin --stats --sizes

# Batch analysis of generator directory
cargo run --release -p clvm-rs-test-tools --bin clvm-serde -- ./GENERATORS --batch --csv results.csv
```
