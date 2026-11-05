import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ArtifactTests(unittest.TestCase):
    def test_reproducible_source_payload(self):
        subprocess.run([sys.executable, 'scripts/build.py'], cwd=ROOT, stdout=subprocess.PIPE, check=True)
        archive = ROOT/'dist/rahawrt-0.1.0.tar.gz'
        first = hashlib.sha256(archive.read_bytes()).hexdigest()
        subprocess.run([sys.executable, 'scripts/build.py'], cwd=ROOT, stdout=subprocess.PIPE, check=True)
        self.assertEqual(first, hashlib.sha256(archive.read_bytes()).hexdigest())
        with tarfile.open(archive) as tar:
            names = tar.getnames()
            for name in ('LICENSE','THIRD_PARTY.md','tests/test_http.py','rahawrt/server.py','openwrt/Makefile','web/app.js'):
                self.assertIn(name,names)
            self.assertFalse(any(name.startswith('/') or '..' in Path(name).parts or '__pycache__' in name for name in names))

    def test_architecture_index_parser(self):
        spec = importlib.util.spec_from_file_location('discover', ROOT/'scripts/discover-architectures.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        html = '<a href="../">up</a><a href="x86_64/">x86</a><a href="aarch64_generic/">arm</a><a href="https://untrusted/">x</a><a href="sha256sums">sums</a>'
        self.assertEqual(module.extract(html), ['aarch64_generic','x86_64'])
        with self.assertRaises(ValueError): module.extract('<html>denied</html>')
