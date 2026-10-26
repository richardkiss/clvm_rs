//! Tests for `normalize_varints`.

use super::{SERDE_2026_MAGIC_PREFIX, deserialize_2026, normalize_varints, serialize_2026};
use crate::allocator::Allocator;
use crate::serde::{ObjectCache, node_from_bytes_backrefs, node_to_bytes, treehash};
use hex::FromHex;
use rstest::rstest;

const TEST_MAX_ATOM_LEN: usize = 1 << 20;

/// Encode `value` as a varint occupying exactly `width` bytes.
fn padded_varint(value: i64, width: usize) -> Vec<u8> {
    assert!((1..=8).contains(&width));
    let leading_ones = width - 1;
    let total_bits = 7 * width as u32;
    let unsigned = (value as u64) & ((1u64 << total_bits) - 1);
    let prefix = if leading_ones > 0 {
        ((1u16 << leading_ones) - 1) << (8 - leading_ones)
    } else {
        0
    } as u8;
    let mut out = vec![prefix | (unsigned >> (8 * leading_ones)) as u8];
    for i in (0..leading_ones).rev() {
        out.push((unsigned >> (8 * i)) as u8);
    }
    // The padded encoding decodes back to `value`.
    let decoded = super::read_varint(&mut &out[..], false).unwrap();
    assert_eq!(
        decoded, value,
        "value {value} does not fit in {width} bytes"
    );
    out
}

fn hash_blob(blob: &[u8]) -> [u8; 32] {
    let mut a = Allocator::new();
    let node = deserialize_2026(&mut a, blob, TEST_MAX_ATOM_LEN, false).unwrap();
    let mut cache = ObjectCache::new(treehash);
    *cache.get_or_calculate(&a, &node, None).unwrap()
}

fn canonical_bytes(blob: &[u8]) -> Vec<u8> {
    let mut a = Allocator::new();
    let node = deserialize_2026(&mut a, blob, TEST_MAX_ATOM_LEN, false).unwrap();
    node_to_bytes(&a, node).unwrap()
}

/// A blob token: a varint with an encoding width, or raw atom payload bytes.
enum Tok<'a> {
    V(i64, usize),
    Raw(&'a [u8]),
}
use Tok::{Raw, V};

fn build(tokens: &[Tok]) -> Vec<u8> {
    let mut out = SERDE_2026_MAGIC_PREFIX.to_vec();
    for t in tokens {
        match t {
            V(v, w) => out.extend(padded_varint(*v, *w)),
            Raw(b) => out.extend_from_slice(b),
        }
    }
    out
}

/// A blob with structure the serializer would never emit: a size-1 group in
/// the `-len, count` form, an unsorted atom table, right-first conses (`-1`)
/// and a pair back-reference.
///
/// Decodes to `((bar . foo) . ((bar . foo) . A))` with `A` = 100 bytes of
/// 0x41. `w` gives the width of each varint, in order.
fn hand_built(w: &[usize; 13]) -> Vec<u8> {
    let big = [0x41u8; 100];
    build(&[
        V(2, w[0]), // two groups
        V(-3, w[1]),
        V(2, w[2]), // two 3-byte atoms
        Raw(b"foo"),
        Raw(b"bar"),
        V(-100, w[3]),
        V(1, w[4]), // one 100-byte atom in the -len,count form
        Raw(&big),
        V(7, w[5]),   // seven instructions
        V(2, w[6]),   // push foo (atom 0)
        V(3, w[7]),   // push bar (atom 1)
        V(-1, w[8]),  // right-first cons -> (bar . foo), pair 0
        V(4, w[9]),   // push A (atom 2)
        V(-2, w[10]), // push pair 0
        V(-1, w[11]), // right-first cons -> ((bar . foo) . A), pair 1
        V(1, w[12]),  // left-first cons -> (pair 0 . pair 1)
    ])
}

const MINIMAL_WIDTHS: [usize; 13] = [1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1];

fn corpus() -> Vec<Vec<u8>> {
    let mut blobs = Vec::new();
    for hex in [
        "80",
        "01",
        "ff83666f6fff8362617280",
        "ffff0102ffff0102ffff010200",
        "ff846c6f6e67ff86737472696e67ff826f66fffe0bff8474657874fffe1780",
        "ff83666f6ffffe01fffe01fffe01fffe01fffe01fffe0180",
    ] {
        let bytes = Vec::from_hex(hex).unwrap();
        let mut a = Allocator::new();
        let node = node_from_bytes_backrefs(&mut a, &bytes).unwrap();
        blobs.push(serialize_2026(&a, node, 0).unwrap());
    }
    for generator in [
        &include_bytes!("../../benches/2.generator")[..],
        &include_bytes!("../../benches/3.generator")[..],
        &include_bytes!("../../benches/4.generator")[..],
    ] {
        let mut a = Allocator::new();
        let node = node_from_bytes_backrefs(&mut a, generator).unwrap();
        blobs.push(serialize_2026(&a, node, 0).unwrap());
    }
    blobs.push(hand_built(&MINIMAL_WIDTHS));
    blobs.push(hand_built(&[8; 13]));
    blobs
}

#[test]
fn test_normalize_preserves_tree_hash() {
    for blob in corpus() {
        let normalized = normalize_varints(&blob).unwrap();
        assert_eq!(hash_blob(&normalized), hash_blob(&blob));
    }
}

#[test]
fn test_normalize_is_idempotent() {
    for blob in corpus() {
        let once = normalize_varints(&blob).unwrap();
        assert_eq!(normalize_varints(&once).unwrap(), once);
    }
}

#[test]
fn test_normalize_leaves_serializer_output_unchanged() {
    for blob in corpus().into_iter().take(9) {
        assert_eq!(normalize_varints(&blob).unwrap(), blob);
    }
    let minimal = hand_built(&MINIMAL_WIDTHS);
    assert_eq!(normalize_varints(&minimal).unwrap(), minimal);
}

#[test]
fn test_normalize_keeps_non_default_structure() {
    let minimal = hand_built(&MINIMAL_WIDTHS);
    let padded = hand_built(&[3, 4, 5, 6, 7, 8, 2, 3, 4, 5, 6, 7, 8]);
    assert!(padded.len() > minimal.len());
    assert_eq!(normalize_varints(&padded).unwrap(), minimal);
    assert_eq!(
        canonical_bytes(&minimal),
        Vec::from_hex(format!(
            "ffff8362617283666f6fffff8362617283666f6fc064{}",
            "41".repeat(100)
        ))
        .unwrap()
    );
}

/// Pad each varint of `hand_built` on its own, at every width, and check
/// that normalization shrinks it back to the minimal blob. The positions
/// cover group count, positive and negative atom lengths, group size,
/// instruction count, atom refs, pair refs and both cons opcodes.
#[test]
fn test_normalize_shrinks_each_overlong_varint() {
    let minimal = hand_built(&MINIMAL_WIDTHS);
    for pos in 0..13 {
        for width in MINIMAL_WIDTHS[pos] + 1..=8 {
            let mut widths = MINIMAL_WIDTHS;
            widths[pos] = width;
            let padded = hand_built(&widths);
            assert_eq!(padded.len(), minimal.len() + width - MINIMAL_WIDTHS[pos]);
            assert_eq!(
                normalize_varints(&padded).unwrap(),
                minimal,
                "position {pos} width {width}"
            );
        }
    }
}

#[test]
fn test_normalize_shrinks_padded_generator() {
    // Pad the group count of a real generator blob to 8 bytes.
    let blob = &corpus()[7];
    let mut body = &blob[SERDE_2026_MAGIC_PREFIX.len()..];
    let mut padded = SERDE_2026_MAGIC_PREFIX.to_vec();
    let groups = super::read_varint(&mut body, false).unwrap();
    padded.extend(padded_varint(groups, 8));
    padded.extend_from_slice(body);
    assert_eq!(normalize_varints(&padded).unwrap(), *blob);
}

#[test]
fn test_normalize_drops_trailing_bytes() {
    let minimal = hand_built(&MINIMAL_WIDTHS);
    let mut trailing = minimal.clone();
    trailing.extend_from_slice(b"junk");
    assert_eq!(normalize_varints(&trailing).unwrap(), minimal);
}

#[rstest]
#[case(&[], "empty input")]
#[case(&[0xfd, 0xff, b'2', b'0', b'2', b'7', 0x00, 0x01, 0x00], "wrong magic")]
#[case(&[0x7f], "negative group count")]
#[case(&[0xff], "0xFF invalid varint prefix")]
#[case(&[0x80], "truncated multibyte varint")]
#[case(&[0x01, 0x00, 0x01, 0x00], "zero-length atom")]
#[case(&[0x01, 0x7d, 0x00, 0x01, 0x00], "empty group")]
#[case(&[0x01, 0x7d, 0x80, 0x00, 0x01, 0x00], "empty group, overlong count")]
#[case(&[0x01, 0x7d, 0x02, 0x41, 0x41, 0x41, 0x01, 0x02], "group shorter than declared")]
#[case(&[0x01, 0x01, 0x41], "truncated before instruction count")]
#[case(&[0x01, 0x01, 0x41, 0x00], "zero instructions")]
#[case(&[0x01, 0x01, 0x41, 0x02, 0x02], "missing instruction")]
#[case(&[0x01, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01], "huge atom length")]
#[case(&[0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], "length * count overflow")]
fn test_normalize_rejects_malformed(#[case] body: &[u8], #[case] desc: &str) {
    let blob = if desc == "empty input" || desc == "wrong magic" {
        body.to_vec()
    } else {
        [&SERDE_2026_MAGIC_PREFIX[..], body].concat()
    };
    assert!(normalize_varints(&blob).is_err(), "should reject: {desc}");
}

#[test]
fn test_normalize_rejects_every_truncation() {
    for blob in corpus() {
        for len in 0..blob.len() {
            assert!(normalize_varints(&blob[..len]).is_err(), "len {len}");
        }
    }
}

#[test]
fn test_normalize_random_bytes_never_panic() {
    // xorshift; deterministic
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let seed = hand_built(&[2; 13]);
    for _ in 0..20_000 {
        let mut blob = seed.clone();
        for _ in 0..(next() % 4 + 1) {
            let i = SERDE_2026_MAGIC_PREFIX.len()
                + (next() as usize % (blob.len() - SERDE_2026_MAGIC_PREFIX.len()));
            blob[i] = next() as u8;
        }
        if let Ok(normalized) = normalize_varints(&blob) {
            assert_eq!(normalize_varints(&normalized).unwrap(), normalized);
            let mut a = Allocator::new();
            if deserialize_2026(&mut a, &blob, TEST_MAX_ATOM_LEN, false).is_ok() {
                assert_eq!(hash_blob(&normalized), hash_blob(&blob));
            }
        }
    }
}
