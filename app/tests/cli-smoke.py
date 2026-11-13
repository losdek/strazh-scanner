"""End-to-end checks against the compiled, standalone Rust scanner."""
import hashlib
import json
import pathlib
import subprocess
import tempfile

binary = pathlib.Path(__file__).resolve().parents[1] / 'target/release/vt-scan'

def scan(*args):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=15)
    reports = [json.loads(line) for line in result.stdout.splitlines()]
    return result, reports

with tempfile.TemporaryDirectory(prefix='vt-cli-') as directory:
    root = pathlib.Path(directory)
    data = root / 'nested'; data.mkdir()
    ordinary = data / 'quoted " unicode é.txt'; ordinary.write_bytes(b'hello')
    (data / 'empty').touch()
    (data / 'loop').symlink_to(data, target_is_directory=True)
    eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    (data / 'test.txt').write_bytes(eicar + b'\r\n')
    (data / 'disguised.pdf').write_bytes(b'\x7fELF\x02\0')
    large = b'a' * (2 * 1024 * 1024 + 7)
    (data / 'large.txt').write_bytes(large)
    result, reports = scan('--scan', '--workers', 4, data)
    assert result.returncode == 1, result.stderr
    summary = reports[-1]
    assert summary['files'] == 5 and summary['matches'] == 1 and summary['reviews'] == 1 and summary['skipped'] == 1 and summary['errors'] == 0, summary
    assert any(r.get('hash') == hashlib.sha256(large).hexdigest() for r in reports)
    assert any(r.get('path') == str(ordinary) for r in reports)
    blocklist = root / 'hashes.txt'
    blocklist.write_text(hashlib.sha256(b'hello').hexdigest() + ' Custom test signature\n')
    result, reports = scan('--mode', 'hashes', '--signatures', blocklist, ordinary)
    assert result.returncode == 1 and reports[0]['status'] == 'match'
    assert 'Custom test signature' in reports[0]['details'][0]
    result, reports = scan(root / 'missing')
    assert result.returncode == 2 and reports[0]['status'] == 'error'
    result, _ = scan('--workers', 20, ordinary)
    assert result.returncode == 2 and 'Workers' in result.stderr
print('CLI passed: recursion, Unicode/quoted names, streaming hashes, EICAR with newline, disguised executable, imported blocklist, symlink loop, missing path, resource validation.')
