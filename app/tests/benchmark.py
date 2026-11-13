"""Scanner-only benchmark; generated binary files, warm filesystem cache."""
import json
import os
import pathlib
import tempfile
import time

project = pathlib.Path(__file__).resolve().parents[2]
binary = str(project / 'app/target/release/vt-scan')
results = []
with tempfile.TemporaryDirectory(prefix='vt-benchmark-') as directory:
    folder = pathlib.Path(directory) / 'files'
    folder.mkdir()
    chunk = bytes(range(256)) * 4096
    for number in range(8):
        with (folder / f'input-{number}.bin').open('wb') as output:
            for _ in range(32):
                output.write(chunk)
    for mode in ['hashes', 'static']:
        for workers in [1, 2, 4]:
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
                args = [binary, '--quiet', '--mode', mode, '--workers', str(workers), str(folder)]
                pid = os.posix_spawn(binary, args, os.environ, file_actions=[(os.POSIX_SPAWN_DUP2, output.fileno(), 1), (os.POSIX_SPAWN_DUP2, error.fileno(), 2)])
                peak = 0
                while True:
                    try:
                        for line in pathlib.Path(f'/proc/{pid}/status').read_text().splitlines():
                            if line.startswith('VmHWM:'):
                                peak = max(peak, int(line.split()[1]))
                    except FileNotFoundError:
                        pass
                    waited, status, _ = os.wait4(pid, os.WNOHANG)
                    if waited:
                        break
                    time.sleep(.002)
                output.seek(0)
                error.seek(0)
                assert os.waitstatus_to_exitcode(status) == 0, error.read()
                summary = json.loads(output.read())
                assert summary['files'] == 8 and summary['bytes'] == 256 * 1024 * 1024 and summary['errors'] == 0, summary
                result = {'mode': mode, 'workers': workers, 'files': 8, 'MiB': 256, 'seconds': summary['seconds'], 'MiB_per_second': round(256 / summary['seconds'], 1), 'peak_RSS_MiB': round(peak / 1024, 2)}
                results.append(result)
                print(json.dumps(result), flush=True)
(project / 'checks/native-scan-benchmark.json').write_text(json.dumps({'scope': 'Native vt-scan process only; excludes WebKit GUI and optional ClamAV daemon. Eight 32 MiB generated binary files, warm filesystem cache, single run per setting. RSS sampled via /proc/PID/status VmHWM.', 'results': results}, indent=2) + '\n')
