//! Rewrite every varint in a serde_2026 blob in minimal form.
//!
//! Back-references in serde_2026 are atom-table and pair-construction
//! indices, not byte offsets, so shrinking a varint never moves a reference
//! target. The pass therefore works purely at the token level: it walks the
//! header and instruction stream, re-encodes each varint minimally, and
//! copies atom payloads verbatim. It does not build a tree.

use crate::error::{EvalErr, Result};

use super::SERDE_2026_MAGIC_PREFIX;
use super::varint::{read_varint, write_varint};

fn copy_varint(input: &mut &[u8], out: &mut Vec<u8>) -> Result<i64> {
    let value = read_varint(input, false)?;
    write_varint(out, value)?;
    Ok(value)
}

fn copy_count(input: &mut &[u8], out: &mut Vec<u8>) -> Result<u64> {
    u64::try_from(copy_varint(input, out)?).map_err(|_| EvalErr::SerializationError)
}

/// Return a copy of the magic-prefixed serde_2026 `blob` with every varint
/// (group count, atom lengths, group sizes, instruction count, instructions)
/// in minimal encoding.
///
/// Atom payloads, atom grouping, atom order and the instruction sequence are
/// kept as-is, so the decoded tree and its back-reference structure are
/// unchanged. Bytes after the end of the blob are dropped.
///
/// Header checks match [`super::deserialize_2026`]: zero-length atoms, empty
/// groups and an empty instruction stream are errors. Instruction semantics
/// (stack depth, index validity) are left to the deserializer.
pub fn normalize_varints(blob: &[u8]) -> Result<Vec<u8>> {
    let mut input = blob
        .strip_prefix(&SERDE_2026_MAGIC_PREFIX)
        .ok_or(EvalErr::SerializationError)?;
    let mut out = Vec::with_capacity(blob.len());
    out.extend_from_slice(&SERDE_2026_MAGIC_PREFIX);

    let group_count = copy_count(&mut input, &mut out)?;
    for _ in 0..group_count {
        let length_val = copy_varint(&mut input, &mut out)?;
        let (length, count) = if length_val < 0 {
            (length_val.unsigned_abs(), copy_count(&mut input, &mut out)?)
        } else {
            (length_val as u64, 1)
        };
        if length == 0 || count == 0 {
            return Err(EvalErr::SerializationError);
        }
        let payload_len = length
            .checked_mul(count)
            .filter(|&n| n <= input.len() as u64)
            .ok_or(EvalErr::SerializationError)? as usize;
        let (payload, rest) = input.split_at(payload_len);
        out.extend_from_slice(payload);
        input = rest;
    }

    let instruction_count = copy_count(&mut input, &mut out)?;
    if instruction_count == 0 {
        return Err(EvalErr::SerializationError);
    }
    for _ in 0..instruction_count {
        copy_varint(&mut input, &mut out)?;
    }

    Ok(out)
}
