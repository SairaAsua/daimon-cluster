"""Use the existing canonical registry through its actual owner process.

The root worker does not change registry ownership or make a second registry.
The short-lived child clears supplementary groups and drops privilege before
calling the same maintained, serialized Registry implementation.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

from . import being_seed
from .embodiments import Registry
from .onboarding import OnboardingError


class OwnerRegistry:
    def __init__(self, root: Path):
        self.root = being_seed._path(root)
        info = root.stat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077
                or info.st_uid != os.geteuid() and os.geteuid() != 0):
            raise OnboardingError('canonical_onboarding_registry_required')
        self.owner = (info.st_uid, info.st_gid, info.st_dev, info.st_ino)
        self.path = root / 'embodiments.json'

    def _call(self, action: str, origin: dict, *, deadline_ns: int | None = None) -> dict:
        def remaining() -> float:
            if deadline_ns is None:
                return 15
            value = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
            if value <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            return min(15, value)
        remaining()
        being_seed._path(self.root)
        info = self.root.stat()
        if (info.st_uid, info.st_gid, info.st_dev, info.st_ino) != self.owner or info.st_mode & 0o077:
            raise OnboardingError('canonical_onboarding_registry_changed')
        if self.owner[0] == os.geteuid():
            registry = Registry(self.root)
            value = registry.load() if action == 'load' else registry.adopt_running(**origin)
            remaining()
            return value
        launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                    'from clusterctl.onboarding_registry import child;raise SystemExit(child())')
        try:
            result = subprocess.run([sys.executable, '-B', '-I', '-c', launcher,
                str(Path(__file__).resolve().parents[1]), str(self.root), json.dumps(self.owner), action],
                input=json.dumps(origin).encode(), capture_output=True, timeout=remaining(), check=False,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8',
                     'LD_LIBRARY_PATH': str(Path(sys.base_prefix) / 'lib')})
            if result.returncode or len(result.stdout) > 4 * 1024**2:
                raise OnboardingError('canonical_onboarding_registry_unavailable')
            value = json.loads(result.stdout)
            if not isinstance(value, dict):
                raise OnboardingError('canonical_onboarding_registry_unavailable')
            remaining()
            return value
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            raise OnboardingError('canonical_onboarding_registry_unavailable') from None

    def load(self, *, deadline_ns: int | None = None) -> dict:
        return self._call('load', {}, deadline_ns=deadline_ns)

    def adopt_running(self, **origin) -> dict:
        if set(origin) != {'body_ref', 'embodiment_id', 'incarnation_id'}:
            raise OnboardingError('canonical_onboarding_registry_required')
        return self._call('adopt', origin)


def child() -> int:
    """Only two typed registry operations; no command, key or capability input."""
    try:
        root = being_seed._path(Path(sys.argv[1]))
        uid, gid, device, inode = json.loads(sys.argv[2])
        action = sys.argv[3]
        if os.geteuid() != 0 or action not in {'load', 'adopt'}:
            return 1
        info = root.stat()
        if ((info.st_uid, info.st_gid, info.st_dev, info.st_ino) != (uid, gid, device, inode)
                or info.st_mode & 0o077):
            return 1
        request = sys.stdin.buffer.read(4097)
        if len(request) > 4096:
            return 1
        origin = json.loads(request)
        if (not isinstance(origin, dict) or set(origin) != (
                set() if action == 'load' else {'body_ref', 'embodiment_id', 'incarnation_id'})):
            return 1
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        if os.geteuid() != uid or os.getegid() != gid:
            return 1
        registry = Registry(root)
        value = registry.load() if action == 'load' else registry.adopt_running(**origin)
        print(json.dumps(value))
        return 0
    except Exception:
        return 1
