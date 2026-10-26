use clvmr::allocator::Allocator;
use clvmr::serde::{ObjectCache, node_from_bytes_backrefs, treehash};
use clvmr::serde_2026::{deserialize_2026, normalize_varints, serialize_2026};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::include_bytes;

const BENCH_MAX_ATOM_LEN: usize = 1 << 20;

/// A list of `n` distinct 4-byte atoms, serialized. This is dense in
/// varints: one atom-ref instruction per 4 payload bytes.
fn synthetic_list(n: u32) -> Vec<u8> {
    let mut a = Allocator::new();
    let mut list = a.nil();
    for i in 0..n {
        let atom = a.new_atom(&(i | 0x0100_0000).to_be_bytes()).unwrap();
        list = a.new_pair(atom, list).unwrap();
    }
    serialize_2026(&a, list, 0).unwrap()
}

fn normalize_2026_benchmark(c: &mut Criterion) {
    let blocks = [
        ("0", include_bytes!("0.generator") as &[u8]),
        ("1", include_bytes!("1.generator") as &[u8]),
        ("3", include_bytes!("3.generator") as &[u8]),
        ("5", include_bytes!("5.generator") as &[u8]),
        (
            "block_af9c3d98",
            include_bytes!("block_af9c3d98.bin") as &[u8],
        ),
    ];

    let mut group = c.benchmark_group("normalize_2026");

    let mut blobs: Vec<(&str, Vec<u8>)> = blocks
        .into_iter()
        .map(|(name, block)| {
            let mut a = Allocator::new();
            let node = node_from_bytes_backrefs(&mut a, block).expect("node_from_bytes_backrefs");
            (name, serialize_2026(&a, node, 0).expect("serialize_2026"))
        })
        .collect();
    // 116_000 atoms gives a ~920 KB blob, near the 916 KB generator limit.
    blobs.push(("synthetic_920k", synthetic_list(116_000)));

    for (name, blob) in blobs {
        group.throughput(Throughput::Bytes(blob.len() as u64));

        group.bench_with_input(BenchmarkId::new("normalize", name), &blob, |b, blob| {
            b.iter(|| black_box(normalize_varints(blob).expect("normalize")))
        });

        group.bench_with_input(BenchmarkId::new("deserialize", name), &blob, |b, blob| {
            b.iter(|| {
                let mut a = Allocator::new();
                black_box(deserialize_2026(&mut a, blob, BENCH_MAX_ATOM_LEN, false).unwrap())
            })
        });

        let mut a = Allocator::new();
        let node = deserialize_2026(&mut a, &blob, BENCH_MAX_ATOM_LEN, false).unwrap();
        group.bench_with_input(BenchmarkId::new("tree_hash", name), &node, |b, node| {
            b.iter(|| {
                let mut cache = ObjectCache::new(treehash);
                black_box(*cache.get_or_calculate(&a, node, None).unwrap())
            })
        });
    }

    group.finish();
}

criterion_group!(benches, normalize_2026_benchmark);
criterion_main!(benches);
