"""Run the guest-owner contracts with real kernel UID1000 on a disposable CI host.

Keep host root mapped to root so protected-path validation retains its real
meaning. No account, source ownership, interpreter or SDK file is changed.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import sys


def run(command: list[str], uid: int, gid: int) -> int:
    if os.geteuid() != 0 or uid <= 0 or gid <= 0 or uid == 65534 or gid == 65534:
        raise ValueError('root and an actual non-root runner owner are required')
    ready_read, ready_write = os.pipe()
    mapped_read, mapped_write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(ready_read)
        os.close(mapped_write)
        try:
            os.setgroups([])
            os.unshare(os.CLONE_NEWUSER)
            os.write(ready_write, b'1')
            os.close(ready_write)
            if os.read(mapped_read, 1) != b'1':
                raise RuntimeError('owner mapping was not installed')
            os.close(mapped_read)
            os.setresgid(1000, 1000, 1000)
            os.setresuid(1000, 1000, 1000)
            os.execv(command[0], command)
        except BaseException as error:
            print(f'guest-owner namespace child failed: {error}', file=sys.stderr, flush=True)
            os._exit(1)
    os.close(ready_write)
    os.close(mapped_read)
    try:
        if os.read(ready_read, 1) != b'1':
            raise RuntimeError('guest-owner user namespace unavailable')
        process = Path('/proc') / str(child)
        # The parent retains real host-root map authority. newuidmap's separate
        # subordinate-ID allocation is not needed for this disposable mapping.
        (process / 'setgroups').write_text('deny')
        (process / 'uid_map').write_text(f'0 0 1\n1000 {uid} 1\n')
        (process / 'gid_map').write_text(f'0 0 1\n1000 {gid} 1\n')
        os.write(mapped_write, b'1')
    except BaseException:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        raise
    finally:
        os.close(ready_read)
        os.close(mapped_write)
    return os.waitstatus_to_exitcode(os.waitpid(child, 0)[1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', required=True, type=int)
    parser.add_argument('--gid', required=True, type=int)
    args = parser.parse_args()
    return run([sys.executable, '-B', '-m', 'pytest', '-q',
        'tests/test_guest_owner_bootstrap.py', '-W', 'error::ResourceWarning',
        '-W', 'error::pytest.PytestUnraisableExceptionWarning', '--durations=5'], args.uid, args.gid)


if __name__ == '__main__':
    raise SystemExit(main())
