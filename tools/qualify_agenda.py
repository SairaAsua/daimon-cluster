"""Run bounded agenda qualification against a disposable upstream engine.

No installed service, real home state, bot or Matrix runtime is selected.
"""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    binary = args.binary.resolve()
    version = subprocess.check_output([str(binary), 'version'], text=True)
    if not version.startswith('Vikunja api version v2.7.0\n'):
        raise ValueError('Pinned Vikunja 2.7.0 required')
    work = root / '.work'
    work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work, prefix='agenda-qualification-') as directory:
        directory = Path(directory)
        with closing(socket.socket()) as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        config = directory / 'config.yml'
        config.write_text(f'''service:
  interface: 127.0.0.1:{port}
  publicurl: http://127.0.0.1:{port}/
  rootpath: {directory}
  enableregistration: true
  enableemailreminders: false
database:
  type: sqlite
  path: {directory}/engine.sqlite
mailer:
  enabled: false
cors:
  enable: false
log:
  level: WARNING
''')
        config.chmod(0o600)
        with (directory/'engine.log').open('wb') as logs:
            engine = subprocess.Popen([str(binary), '--config', str(config)], stdout=logs,
                                      stderr=logs, env={**os.environ, 'GOMAXPROCS': '1'})
            try:
                origin = f'http://127.0.0.1:{port}'
                for _ in range(100):
                    if engine.poll() is not None:
                        raise RuntimeError('Disposable engine exited before readiness')
                    try:
                        with urllib.request.urlopen(origin+'/api/v1/info', timeout=1) as r:
                            if json.load(r)['version']=='v2.7.0':
                                break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise RuntimeError('Disposable engine readiness deadline')
                from tools.ci_scope import HOME_TESTS
                command = [sys.executable, '-m', 'pytest', '-q', *HOME_TESTS,
                           '--junitxml='+str(work/'agenda-tests.xml')]
                code = subprocess.call(command, cwd=root,
                    env={**os.environ, 'DAIMON_AGENDA_VIKUNJA': origin})
                if code:
                    return code
                return code
            finally:
                engine.terminate()
                try:
                    engine.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    engine.kill(); engine.wait(timeout=5)


if __name__ == '__main__':
    raise SystemExit(main())
