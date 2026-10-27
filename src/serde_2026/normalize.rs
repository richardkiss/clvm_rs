//! Rewrite every varint in a serde_2026 blob in minimal form.
//!
//! Back-references in serde_2026 are atom-table and pair-construction
//! indices, not byte offsets, so shrinking a varint never moves a reference
//! target. The pass therefore works purely at the token level: it walks the
//! header and instruction stream, re-encodes each varint minimally, and
//! keeps atom payloads verbatim. It does not build a tree.
//!
//! A minimal encoding is never longer than the one it replaces, so the write
//! position never passes the read position and the rewrite happens in place.
//! When every varint is already minimal, nothing is written.

use crate::error::{EvalErr, Result};

use super::SERDE_2026_MAGIC_PREFIX;
use super::varint::write_varint;

/// Read and write positions into the buffer being normalized.
struct Cursor {
    read: usize,
    write: usize,
}

impl Cursor {
    fn varint(&mut self, buf: &mut [u8]) -> Result<i64> {
        let start = self.read;
        let first = *buf.get(start).ok_or(EvalErr::SerializationError)?;
        let extra = first.leading_ones() as usize;
        if extra >= 8 {
            return Err(EvalErr::SerializationError);
        }
        let consumed = extra + 1;
        let rest = buf
            .get(start + 1..start + consumed)
            .ok_or(EvalErr::SerializationError)?;
        let mut raw = (first & (0x7f >> extra)) as u64;
        for &b in rest {
            raw = (raw << 8) | b as u64;
        }
        // Sign-extend the 7 * consumed bit two's complement value.
        let unused = 64 - 7 * consumed as u32;
        let value = ((raw << unused) as i64) >> unused;
        self.read += consumed;

        // An n-byte varint is overlong when its value fits in n - 1 bytes.
        let overlong = consumed > 1 && {
            let high = value >> (7 * consumed as u32 - 8);
            high == 0 || high == -1
        };
        if overlong {
            let mut minimal = Vec::with_capacity(8);
            write_varint(&mut minimal, value)?;
            buf[self.write..self.write + minimal.len()].copy_from_slice(&minimal);
            self.write += minimal.len();
        } else {
            if self.write != start {
                for i in 0..consumed {
                    buf[self.write + i] = buf[start + i];
                }
            }
            self.write += consumed;
        }
        Ok(value)
    }

    fn count(&mut self, buf: &mut [u8]) -> Result<u64> {
        u64::try_from(self.varint(buf)?).map_err(|_| EvalErr::SerializationError)
    }

    fn payload(&mut self, buf: &mut [u8], len: u64) -> Result<()> {
        let len = usize::try_from(len)
            .ok()
            .filter(|&n| n <= buf.len() - self.read)
            .ok_or(EvalErr::SerializationError)?;
        if self.write != self.read {
            buf.copy_within(self.read..self.read + len, self.write);
        }
        self.read += len;
        self.write += len;
        Ok(())
    }
}

/// Rewrite the magic-prefixed serde_2026 `blob` in place so every varint
/// (group count, atom lengths, group sizes, instruction count, instructions)
/// uses its minimal encoding, then truncate it to the new length.
///
/// Atom payloads, atom grouping, atom order and the instruction sequence are
/// kept as-is, so the decoded tree and its back-reference structure are
/// unchanged. Bytes after the end of the blob are dropped.
///
/// Header checks match [`super::deserialize_2026`]: zero-length atoms, empty
/// groups and an empty instruction stream are errors. Instruction semantics
/// (stack depth, index validity) are left to the deserializer. On error the
/// contents of `blob` are unspecified.
pub fn normalize_varints_in_place(blob: &mut Vec<u8>) -> Result<()> {
    if !blob.starts_with(&SERDE_2026_MAGIC_PREFIX) {
        return Err(EvalErr::SerializationError);
    }
    let buf = blob.as_mut_slice();
    let start = SERDE_2026_MAGIC_PREFIX.len();
    let mut c = Cursor {
        read: start,
        write: start,
    };

    let group_count = c.count(buf)?;
    for _ in 0..group_count {
        let length_val = c.varint(buf)?;
        let (length, count) = if length_val < 0 {
            (length_val.unsigned_abs(), c.count(buf)?)
        } else {
            (length_val as u64, 1)
        };
        if length == 0 || count == 0 {
            return Err(EvalErr::SerializationError);
        }
        c.payload(
            buf,
            length
                .checked_mul(count)
                .ok_or(EvalErr::SerializationError)?,
        )?;
    }

    let instruction_count = c.count(buf)?;
    if instruction_count == 0 {
        return Err(EvalErr::SerializationError);
    }
    for _ in 0..instruction_count {
        c.varint(buf)?;
    }

    blob.truncate(c.write);
    Ok(())
}

/// Return a normalized copy of `blob`. See [`normalize_varints_in_place`].
pub fn normalize_varints(blob: &[u8]) -> Result<Vec<u8>> {
    let mut out = blob.to_vec();
    normalize_varints_in_place(&mut out)?;
    Ok(out)
}
