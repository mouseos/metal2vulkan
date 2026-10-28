#!/usr/bin/env python3
import struct
import unittest
from decode import checksum, decode

class DecodeTest(unittest.TestCase):
    def setUp(self):
        data = struct.pack('<6I', 0x07230203, 0x10500, 0, 8, 0, 0x01020304)
        sha = checksum(56, 0, 6, 'Vertex', 'main', data)
        self.begin = f'm2vspv1 begin pid=56 id=0 words=6 sha256={sha} stage=Vertex entryhex=6d61696e pipeline=missing'
        self.data = f'm2vspv1 data pid=56 id=0 offset=0 hex={data.hex()}'
        self.end = f'm2vspv1 end pid=56 id=0 words=6 sha256={sha}'
        self.expected = data
    def test_roundtrip(self):
        self.assertEqual(decode([self.begin, self.data, self.end], allow_unframed=True)[0][3], self.expected)
    def test_unframed_requires_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            decode([self.begin, self.data, self.end])
    def test_rejects_incomplete_or_mixed(self):
        for lines in ([self.begin, self.data], [self.begin, self.data, self.data, self.end], [self.begin, self.data, self.end, self.begin], [self.data, self.end]):
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                decode(lines, allow_unframed=True)
    def uart(self, records, outer_pid=56):
        lines = []
        for seq, record in enumerate(records):
            parts = [record[i:i + 27] for i in range(0, len(record), 27)]
            for i, part in enumerate(parts):
                prefix = f"sc{outer_pid:08x}{seq:08x}{i:04x}{len(parts):04x}"
                fnv = 2166136261
                for byte in f"{prefix}:{part}".encode('ascii'):
                    fnv = ((fnv ^ byte) * 16777619) & 0xffffffff
                lines.append(f"powervr-metal[backboardd]: {prefix}{fnv:08x}:{part}")
        return lines
    def test_uart_fragments(self):
        lines = self.uart((self.begin, self.data, self.end))
        self.assertEqual(decode(lines)[0][3], self.expected)
        with self.assertRaises(ValueError):
            decode(lines[:-1])
        with self.assertRaises(ValueError):
            decode(lines + lines[:1])
        corrupt = lines.copy()
        corrupt[0] = corrupt[0][:-1] + ('0' if corrupt[0][-1] != '0' else '1')
        with self.assertRaises(ValueError):
            decode(corrupt)
    def test_rejects_malformed_header_after_complete_capture(self):
        lines = self.uart((self.begin, self.data, self.end))
        malformed = lines[0].replace('sc00000038', 'scz0000038', 1)
        with self.assertRaises(ValueError):
            decode(lines + [malformed])
    def test_rejects_short_truncated_header_after_complete_capture(self):
        lines = self.uart((self.begin, self.data, self.end))
        with self.assertRaises(ValueError):
            decode(lines + ['powervr-metal[backboardd]: sc00000038'])
    def test_rejects_changed_metadata(self):
        for begin in (self.begin.replace('stage=Vertex', 'stage=Fragment'),
                      self.begin.replace('entryhex=6d61696e', 'entryhex=666f6f'),
                      self.begin.replace('pipeline=missing', 'pipeline=present')):
            with self.subTest(begin=begin), self.assertRaises(ValueError):
                decode([begin, self.data, self.end], allow_unframed=True)
    def test_rejects_outer_pid_mismatch(self):
        with self.assertRaises(ValueError):
            decode(self.uart((self.begin, self.data, self.end), outer_pid=57))
    def test_rejects_changed_payload(self):
        with self.assertRaises(ValueError):
            decode([self.begin, self.data[:-2] + 'ff', self.end], allow_unframed=True)

if __name__ == '__main__':
    unittest.main()
