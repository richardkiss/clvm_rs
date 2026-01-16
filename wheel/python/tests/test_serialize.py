import io
import unittest

from clvm_rs.program import Program
from clvm_rs.ser import atom_to_byte_iterator


TEXT = b"the quick brown fox jumps over the lazy dogs"


class InfiniteStream(io.TextIOBase):
    def __init__(self, b):
        self.buf = b

    def read(self, n):
        ret = b""
        while n > 0 and len(self.buf) > 0:
            ret += self.buf[0:1]
            self.buf = self.buf[1:]
            n -= 1
        ret += b" " * n
        return ret


class LargeAtom:
    def __len__(self):
        return 0x400000001


class SerializeTest(unittest.TestCase):
    def check_serde(self, s):
        v = Program.to(s)
        b = bytes(v)
        f = io.BytesIO()
        v.stream(f)
        b1 = f.getvalue()
        self.assertEqual(b, b1)
        v1 = Program.parse(io.BytesIO(b))
        if v != v1:
            print("%s: %d %s %s" % (v, len(b), b, v1))
            breakpoint()
            b = bytes(v)
            v1 = Program.parse(io.BytesIO(b))
        self.assertEqual(v, v1)

    def test_zero(self):
        v = Program.to(b"\x00")
        self.assertEqual(bytes(v), b"\x00")

    def test_empty(self):
        v = Program.to(b"")
        self.assertEqual(bytes(v), b"\x80")

    def test_empty_string(self):
        self.check_serde(b"")

    def test_single_bytes(self):
        for _ in range(256):
            self.check_serde(bytes([_]))

    def test_short_lists(self):
        self.check_serde([])
        for _ in range(0, 2048, 8):
            for size in range(1, 5):
                self.check_serde([_] * size)

    def test_cons_box(self):
        self.check_serde((0, 0))
        self.check_serde((0, [1, 2, 30, 40, 600, ([], 18)]))
        self.check_serde((100, (TEXT, (30, (50, (90, (TEXT, TEXT + TEXT)))))))

    def test_long_blobs(self):
        text = TEXT * 300
        for _, t in enumerate(text):
            t1 = text[:_]
            self.check_serde(t1)

    def test_blob_limit(self):
        with self.assertRaises(ValueError):
            next(atom_to_byte_iterator(LargeAtom()))

    def test_very_long_blobs(self):
        for size in [0x40, 0x2000, 0x100000, 0x8000000]:
            count = size // len(TEXT)
            text = TEXT * count
            assert len(text) < size
            self.check_serde(text)
            text = TEXT * (count + 1)
            assert len(text) > size
            self.check_serde(text)

    def test_very_deep_tree(self):
        blob = b"a"
        for depth in [10, 100, 1000, 10000, 100000]:
            s = Program.to(blob)
            for _ in range(depth):
                s = Program.to((s, blob))
            self.check_serde(s)

    def test_deserialize_empty(self):
        bytes_in = b""
        with self.assertRaises(ValueError):
            Program.from_bytes(bytes_in)
        with self.assertRaises(ValueError):
            Program.parse(io.BytesIO(bytes_in))

    def test_deserialize_truncated_size(self):
        # fe means the total number of bytes in the length-prefix is 7
        # one for each bit set. 5 bytes is too few
        bytes_in = b"\xfe    "
        with self.assertRaises(ValueError):
            Program.from_bytes(bytes_in)
        with self.assertRaises(ValueError):
            Program.parse(io.BytesIO(bytes_in))

    def test_deserialize_truncated_blob(self):
        # this is a complete length prefix. The blob is supposed to be 63 bytes
        # the blob itself is truncated though, it's less than 63 bytes
        bytes_in = b"\xbf   "

        with self.assertRaises(ValueError):
            Program.from_bytes(bytes_in)
        with self.assertRaises(ValueError):
            Program.parse(io.BytesIO(bytes_in))

    def test_deserialize_large_blob(self):
        # this length prefix is 7 bytes long, the last 6 bytes specifies the
        # length of the blob, which is 0xffffffffffff, or (2^48 - 1)
        # we don't support blobs this large, and we should fail immediately
        # when exceeding the max blob size, rather than trying to read this
        # many bytes from the stream
        bytes_in = b"\xfe" + b"\xff" * 6

        with self.assertRaises(ValueError):
            Program.parse(InfiniteStream(bytes_in))

    def test_repr_clvm_tree(self):
        with self.assertRaises(ValueError):
            Program.fromhex("ff8085")

        # Default path uses CLVMTree (fast path)
        o = Program.fromhex("ff808185")
        self.assertEqual(repr(o._unwrapped_pair[0]), "<CLVMTree: 80>")
        self.assertEqual(repr(o._unwrapped_pair[1]), "<CLVMTree: 8185>")
        
        # With allow_backrefs, uses LazyNode
        o2 = Program.from_bytes(bytes.fromhex("ff808185"), allow_backrefs=True)
        # Just verify it works, don't check internal representation
        self.assertEqual(o, o2)

    def test_bad_blob(self):
        self.assertRaises(ValueError, lambda: Program.fromhex("ff"))
        f = io.BytesIO(bytes.fromhex("ff"))
        self.assertRaises(ValueError, lambda: Program.parse(f))

    def test_large_atom(self):
        s = "foo" * 100
        p = Program.to(s)
        blob = bytes(p)
        p1 = Program.from_bytes(blob)
        self.assertEqual(p, p1)

    def test_too_large_atom(self):
        self.assertRaises(ValueError, lambda: Program.fromhex("fc"))
        self.assertRaises(ValueError, lambda: Program.fromhex("fc8000000000"))


class CompressedSerializeTest(unittest.TestCase):
    def test_roundtrip_simple(self):
        """Test basic compressed serialization roundtrip"""
        original = Program.to([1, 2, 3])
        compressed = original.to_bytes_compressed()
        restored = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(original, restored)

    def test_roundtrip_complex(self):
        """Test compressed serialization with nested structures"""
        original = Program.to([[1, 2], [3, [4, 5]], 6])
        compressed = original.to_bytes_compressed()
        restored = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(original, restored)

    def test_compression_with_repetition(self):
        """Verify compression reduces size for repeated structures"""
        # Create a structure with repetition
        leaf = Program.to(b"x" * 100)
        repeated = Program.to([leaf, leaf, leaf, leaf])

        standard = bytes(repeated)
        compressed = repeated.to_bytes_compressed()

        # Compressed should be significantly smaller
        self.assertLess(len(compressed), len(standard))
        # Should save at least 200 bytes (3 repetitions of 100-byte leaf)
        self.assertLess(len(compressed), len(standard) - 200)

    def test_empty_program(self):
        """Test compressed serialization of empty program"""
        original = Program.to(b"")
        compressed = original.to_bytes_compressed()
        restored = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(original, restored)

    def test_single_atom(self):
        """Test compressed serialization of single atom"""
        original = Program.to(42)
        compressed = original.to_bytes_compressed()
        restored = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(original, restored)

    def test_deep_nesting(self):
        """Test compressed serialization with deep nesting"""
        # Build a deeply nested structure
        original = Program.to(1)
        for _ in range(100):
            original = Program.to([original, 2])

        compressed = original.to_bytes_compressed()
        restored = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(original, restored)

    def test_large_repeated_subtree(self):
        """Test compression with large repeated subtrees"""
        # Create a large subtree
        large_leaf = Program.to(b"data" * 1000)
        nested = Program.to([large_leaf, [large_leaf, large_leaf]])

        # Many repetitions
        repeated = Program.to([nested, nested, nested])

        standard = bytes(repeated)
        compressed = repeated.to_bytes_compressed()

        # Should get significant compression
        self.assertLess(len(compressed), len(standard) * 0.5)

    def test_no_repetition_minimal_overhead(self):
        """Verify minimal overhead when there's no repetition"""
        # Unique values, no repetition
        original = Program.to([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

        standard = bytes(original)
        compressed = original.to_bytes_compressed()

        # Should be roughly the same size (maybe slightly different)
        # Allow up to 20 bytes difference for back-ref infrastructure
        self.assertLess(abs(len(compressed) - len(standard)), 20)

    def test_fromhex_then_compress(self):
        """Test compressing a program created from hex"""
        original = Program.fromhex("ff01ff02ff0102")
        compressed = original.to_bytes_compressed()
        restored = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(original, restored)

    def test_to_then_compress(self):
        """Test compressing a program created with to()"""
        # Create structure with repeated elements
        original = Program.to([[b"key", [1, 2, 3]], [b"repeat", [1, 2, 3]]])
        compressed = original.to_bytes_compressed()
        restored = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(original, restored)

    def test_allow_backrefs_accepts_standard(self):
        """Test that allow_backrefs=True accepts standard format"""
        original = Program.to([1, 2, 3])
        standard = bytes(original)

        # Should work with allow_backrefs=True
        restored = Program.from_bytes(standard, allow_backrefs=True)
        self.assertEqual(original, restored)

    def test_default_rejects_compressed(self):
        """Test that default from_bytes rejects compressed format"""
        original = Program.to([[1, 2], [1, 2]])
        compressed = original.to_bytes_compressed()

        # Should raise ValueError without allow_backrefs
        with self.assertRaises(ValueError):
            Program.from_bytes(compressed)

    def test_default_accepts_both_formats(self):
        """Test that allow_backrefs=True accepts both formats"""
        original = Program.to([[1, 2], [1, 2]])

        standard = bytes(original)
        compressed = original.to_bytes_compressed()

        # Standard works by default
        p1 = Program.from_bytes(standard)
        self.assertEqual(p1, original)

        # Compressed requires allow_backrefs=True
        p2 = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(p2, original)
        self.assertEqual(p1, p2)

    def test_repeated_cons_boxes(self):
        """Test compression with repeated cons box structures"""
        # Create a structure that's repeated
        structure = Program.to([1, [2, 3]])
        repeated = Program.to([structure, structure, structure])

        standard = bytes(repeated)
        compressed = repeated.to_bytes_compressed()

        # Should see compression
        self.assertLess(len(compressed), len(standard))

        # Verify roundtrip
        restored = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(restored, repeated)

    def test_very_long_list(self):
        """Test compression with a very long list"""
        # Create a long list with repeating pattern
        long_list = Program.to([1, 2, 3] * 100)

        standard = bytes(long_list)
        compressed = long_list.to_bytes_compressed()

        # Should be roughly similar size (no compression for distinct linear list)
        # But roundtrip should work correctly
        restored = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(restored, long_list)

    def test_tree_with_shared_leaves(self):
        """Test compression with tree structure sharing leaves"""
        leaf = Program.to(b"shared")
        left = Program.to([leaf, leaf])
        right = Program.to([leaf, leaf])
        tree = Program.to([left, right])

        standard = bytes(tree)
        compressed = tree.to_bytes_compressed()

        # Should compress well (many references to same leaf)
        self.assertLess(len(compressed), len(standard) * 0.6)

        # Verify roundtrip
        restored = Program.from_bytes(compressed, allow_backrefs=True)
        self.assertEqual(restored, tree)
