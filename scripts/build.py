#!/usr/bin/env python3
"""Build a reproducible portable source payload, NOT an SDK/ipk certification."""
import gzip
import hashlib
import io
from pathlib import Path
import tarfile

root = Path(__file__).resolve().parents[1]
dest = root / 'dist'
dest.mkdir(exist_ok=True)
files = []
for directory in ('rahawrt', 'web', 'openwrt', 'scripts', 'docs', 'tests', '.github'):
    files += [p for p in (root/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
files += [root/p for p in ('README.md', 'LICENSE', 'THIRD_PARTY.md', 'Makefile', '.gitignore')]
archive = dest / 'rahawrt-0.1.0.tar.gz'
with archive.open('wb') as target, gzip.GzipFile(filename='', fileobj=target, mode='wb', mtime=0) as gz, tarfile.open(fileobj=gz, mode='w|') as tar:
    for path in sorted(files):
        info = tar.gettarinfo(str(path), arcname=str(path.relative_to(root)))
        info.uid = info.gid = 0
        info.uname = info.gname = ''
        info.mtime = 0
        info.mode = 0o755 if path.suffix == '.sh' else 0o644
        with path.open('rb') as source:
            tar.addfile(info, source)
manifest = hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n'
(dest/'SHA256SUMS').write_text(manifest)
print(manifest, end='')
