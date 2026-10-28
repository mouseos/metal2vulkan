#!/usr/bin/env python3
import hashlib
import struct
import unittest
from decode import decode

class DecodeTest(unittest.TestCase):
    def setUp(self):
        data = struct.pack('<6I', 0x07230203, 0x10500, 0, 8, 0, 0x01020304)
        sha = hashlib.sha256(data).hexdigest()
        self.begin = f'm2vspv1 begin pid=56 id=0 words=6 sha256={sha} stage=Vertex entryhex=6d61696e pipeline=missing'
        self.data = f'm2vspv1 data pid=56 id=0 offset=0 hex={data.hex()}'
        self.end = f'm2vspv1 end pid=56 id=0 words=6 sha256={sha}'
        self.expected = data
    def test_roundtrip(self):
        self.assertEqual(decode([self.begin, self.data, self.end])[0][3], self.expected)
    def test_rejects_incomplete_or_mixed(self):
        for lines in ([self.begin, self.data], [self.begin, self.data, self.data, self.end], [self.begin, self.data, self.end, self.begin], [self.data, self.end]):
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                decode(lines)
    def test_rejects_changed_payload(self):
        with self.assertRaises(ValueError):
            decode([self.begin, self.data[:-2] + 'ff', self.end])

if __name__ == '__main__':
    unittest.main()
