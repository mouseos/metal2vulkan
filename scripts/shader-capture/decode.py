#!/usr/bin/env python3
"""Recover bounded diagnostic frames from one boot's log into a new host directory."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

MAX_WORDS = 8192
LINE = re.compile(r'm2vspv1 (begin|data|end) pid=(\d+) id=(\d+) (.*)')
FRAGMENT = re.compile(r'sc([0-9a-f]{8})([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4}):([^\r\n]*)')

def reassemble(lines):
    groups = {}
    for line in lines:
        match = FRAGMENT.search(line)
        if not match:
            yield line
            continue
        pid, sequence, index, count, data = match.groups()
        key = (pid, sequence)
        index, count = int(index, 16), int(count, 16)
        if not 0 < count <= 64 or index >= count or len(data) > 35:
            raise ValueError('invalid UART fragment')
        group = groups.setdefault(key, {'count': count, 'parts': {}, 'done': False})
        if group['count'] != count or group['done'] or index in group['parts']:
            raise ValueError('duplicate or inconsistent UART fragment')
        group['parts'][index] = data
        if len(group['parts']) == count:
            group['done'] = True
            yield ''.join(group['parts'][part] for part in range(count))
    if any(not group['done'] for group in groups.values()):
        raise ValueError('incomplete UART fragment group')


def decode(lines):
    frames = {}
    for line in reassemble(lines):
        match = LINE.search(line)
        if not match:
            continue
        kind, pid, ident, fields = match.groups()
        key = (int(pid), int(ident))
        parts = fields.split()
        if any('=' not in part for part in parts):
            raise ValueError('malformed fields')
        attrs = dict(part.split('=', 1) for part in parts)
        if len(attrs) != len(parts):
            raise ValueError('duplicate field')
        if kind == 'begin':
            if key in frames:
                raise ValueError('duplicate identity; separate boot logs')
            count = int(attrs['words'])
            if not 5 <= count <= MAX_WORDS or not re.fullmatch('[0-9a-f]{64}', attrs['sha256']):
                raise ValueError('invalid size or digest')
            entry = bytes.fromhex(attrs['entryhex']).decode('utf-8')
            if len(entry.encode()) > 256:
                raise ValueError('entry too long')
            frames[key] = {'meta': attrs, 'entry': entry, 'count': count, 'chunks': {}, 'end': False}
        elif key not in frames:
            raise ValueError('data without begin')
        else:
            f = frames[key]
            if f['end']:
                raise ValueError('data after end')
            if kind == 'data':
                offset = int(attrs['offset'])
                data = bytes.fromhex(attrs['hex'])
                if offset < 0 or offset % 32 or not data or len(data) % 4 or len(data) > 128 or offset + len(data) // 4 > f['count'] or offset in f['chunks']:
                    raise ValueError('invalid or duplicate chunk')
                f['chunks'][offset] = data
            else:
                if int(attrs['words']) != f['count'] or attrs['sha256'] != f['meta']['sha256']:
                    raise ValueError('end does not match begin')
                f['end'] = True
    if not frames:
        raise ValueError('no frames')
    result = []
    for (pid, ident), f in frames.items():
        if not f['end']:
            raise ValueError('incomplete frame')
        offsets = sorted(f['chunks'])
        data = bytearray()
        for offset in offsets:
            if offset != len(data) // 4:
                raise ValueError('missing or overlapping chunk')
            data.extend(f['chunks'][offset])
        if len(data) != 4 * f['count'] or hashlib.sha256(data).hexdigest() != f['meta']['sha256']:
            raise ValueError('length or digest mismatch')
        if struct.unpack_from('<I', data)[0] != 0x07230203:
            raise ValueError('bad SPIR-V magic')
        result.append((pid, ident, f, bytes(data)))
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('output', type=Path, help='new output directory on the host')
    args = parser.parse_args()
    with args.log.open(encoding='utf-8', errors='replace') as stream:
        frames = decode(stream)
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = []
    for pid, ident, f, data in frames:
        name = f'pid-{pid}-id-{ident}.spv'
        (args.output / name).write_bytes(data)
        manifest.append({'file': name, 'pid': pid, 'id': ident, 'entry': f['entry'], 'stage': f['meta']['stage'], 'sha256': f['meta']['sha256'], 'pipeline': 'missing'})
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'PASS: {len(frames)} complete captures')

if __name__ == '__main__':
    main()
