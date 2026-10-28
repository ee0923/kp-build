"""Exercise the publication boundary offline with a fake GitHub CLI."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class ReleaseTests(unittest.TestCase):
    def run_publish(self, tamper=False, extra=False, existing=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / 'dist'
            dist.mkdir()
            data = b'verified package'
            (dist / 'app.apk').write_bytes(data)
            (dist / 'SHA256SUMS').write_text(hashlib.sha256(data).hexdigest() + '  app.apk\n')
            if tamper:
                (dist / 'app.apk').write_bytes(b'changed')
            if extra:
                (dist / 'private.key').write_text('must not upload')
            cli = root / 'gh'
            cli.write_text('''#!/usr/bin/env python3
import json, os, sys
with open('calls.jsonl', 'a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\\n')
sys.exit(0 if sys.argv[2] != 'view' or os.environ['EXISTING'] == '1' else 1)
''')
            cli.chmod(0o755)
            result = subprocess.run(['bash', str(Path(__file__).with_name('publish-release.sh'))],
                                    cwd=root, capture_output=True, text=True,
                                    env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                                         'GH_TOKEN': 'fixture', 'GH_REPO': 'fixture/repo',
                                         'RELEASE_TAG': 'build-1', 'RELEASE_TARGET': 'a' * 40,
                                         'PACKAGE_ID': 'android', 'EXISTING': str(int(existing))})
            calls = root / 'calls.jsonl'
            return result, [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []

    def test_create_and_upload_only_verified_files(self):
        result, calls = self.run_publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[1] for call in calls], ['view', 'create', 'upload'])
        self.assertIn('--target', calls[1])
        self.assertIn('a' * 40, calls[1])
        self.assertEqual(calls[2], ['release', 'upload', 'build-1',
                                    'dist/SHA256SUMS-android', 'dist/app.apk', '--clobber'])

    def test_existing_release_is_reused(self):
        result, calls = self.run_publish(existing=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[1] for call in calls], ['view', 'upload'])

    def test_tampering_and_extra_files_block_all_network_calls(self):
        for options in ({'tamper': True}, {'extra': True}):
            result, calls = self.run_publish(**options)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
