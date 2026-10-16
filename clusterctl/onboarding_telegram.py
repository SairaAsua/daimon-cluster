"""Dedicated native Telegram configuration and receiving token preparation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, digest, validate_plan
from .onboarding_guest import mkdir_chain, new_bytes
from .onboarding_service import publish

PREVIOUS_COMMIT = '5af79bdf0716dadf92ae982bfbeafdf2eb21f6a9'
PREVIOUS_ARCHIVE = '6ab8a38ec08274eeb036c40632ffbeb6dc8b5d14d385d7d5de4a8428a3fcd9b5'
PREVIOUS_BINARY = 'e29bff3da0682e4c8f37ae75c9a724f5c0f3be6238063f14d86eb1123fd2e620'
RETAINED_COMMIT = 'ee5f8837ab51da99034fcd4285b0c7916c96651f'
RETAINED_ARCHIVE = 'f586c9ace3fd91aaded87859e1d37c5a8dd71749777c8264a2cdcf0f76ece06b'
RETAINED_BINARY = 'deb7aa777e75f7b8865f8a2060f7cd0d138aa5ce1fe1da0feee470530bbdafcc'
RETAINED_CURRENT_COMMIT = 'abd85a90eaf204e45bf479daae24d645cdf18762'
RETAINED_CURRENT_ARCHIVE = '27450b3c7256d203287d6918d3822f85b9844a0d9a0659be7cb03318253e5296'
RETAINED_CURRENT_BINARY = '1330014e7b34806b400d1046ef24c26ea5a588970f47142e58a39bb0c06127b5'
CONVERSATION_COMMIT = '762e582e077bb406d289b4685918a568b9d53feb'
CONVERSATION_ARCHIVE = '87bc7c0a4f9b6ba87c2c14a235ae6e8383ada9803010dd1a35571ac075151a8e'
CONVERSATION_BINARY = 'ace52375e49c09360a39a62c427bf4567f38b33d6d1713f8aa910b016dafa4cd'
RETAINED_GOAL_COMMIT = 'e54b5393c24923c3eef93f8ebc82e2f01dedac05'
RETAINED_GOAL_ARCHIVE = 'df5eb49cb5e8036473cc2c2363ea869b1b3acdf0305a91a5d9faab018eaff787'
RETAINED_GOAL_BINARY = 'a3bac1546cd69219bb6be1176541ca879f7864df108b6ec047d6de13f5cfe589'
COMMIT = '1983a929632cb62ea260c96079989152553a45e3'
ARCHIVE = '4f5f06f423d2d71356ef128582621bfd6330c4fd55b8e3374e8c8bca2c222cb8'
BINARY = 'f0e7fa2f03b651489c41f3cf25507715dadcff102e09d4280988fd2a53006250'
SCHEMA = 'cluster-onboarding-telegram/v1'
UNIT = 'daimon-onboarding-telegram.service'
NATIVE_UNIT = 'daimon-onboarding-codex.service'


def artifact(code: Path, *, uid: int) -> dict:
    return artifact_directory(code / 'telegram', uid=uid)


def artifact_directory(directory: Path, *, uid: int) -> dict:
    """Only explicitly qualified text binaries; labels never select software."""
    value = json.loads(onboarding_release.regular(directory / 'artifact.json', uid=uid, limit=65536))
    if not isinstance(value, dict):
        raise OnboardingError('qualified_telegram_binary_required')
    value = dict(value)
    if 'rust' in value and 'rust_toolchain' not in value:
        value['rust_toolchain'] = value.pop('rust')
    common = dict(rust_toolchain='1.95.0', features='--no-default-features')
    qualified = [dict(commit=c, archive_sha256=a, binary_sha256=b, **common) for c, a, b in (
        (PREVIOUS_COMMIT, PREVIOUS_ARCHIVE, PREVIOUS_BINARY),
        (RETAINED_COMMIT, RETAINED_ARCHIVE, RETAINED_BINARY),
        (RETAINED_CURRENT_COMMIT, RETAINED_CURRENT_ARCHIVE, RETAINED_CURRENT_BINARY),
        (CONVERSATION_COMMIT, CONVERSATION_ARCHIVE, CONVERSATION_BINARY),
        (RETAINED_GOAL_COMMIT, RETAINED_GOAL_ARCHIVE, RETAINED_GOAL_BINARY),
        (COMMIT, ARCHIVE, BINARY))]
    binary = directory / 'telecodex'
    if (value not in qualified or binary.stat().st_mode & 0o111 != 0o111
            or hashlib.sha256(onboarding_release.regular(binary, uid=uid)).hexdigest() != value['binary_sha256']):
        raise OnboardingError('qualified_telegram_binary_required')
    return value


def connections(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {'telegram_bot_token', 'telegram_chat_id'}
            or not isinstance(value['telegram_bot_token'], str)
            or not re.fullmatch(r'[0-9]{6,15}:[A-Za-z0-9_-]{30,100}', value['telegram_bot_token'])
            or type(value['telegram_chat_id']) is not int or not 0 < value['telegram_chat_id'] < 2**53):
        raise OnboardingError('connection_data_required')
    return value


def configuration(home: Path, code: Path, codex: Path, human: int, profile: dict) -> bytes:
    state = home / '.local/state/daimon-onboarding/telegram'
    # Values use TOML-compatible JSON strings; no token or source instruction
    # is interpolated into this file or any executable command.
    quote = json.dumps
    lines = [f'db_path = {quote(str(state / "telegram.sqlite3"))}',
        f'startup_admin_ids = [{human}]', 'poll_timeout_seconds = 30', 'edit_debounce_ms = 900',
        'max_text_chunk = 3500', f'tmp_dir = {quote(str(state / "tmp"))}',
        'background_maintenance = false', '[telegram]',
        f'bot_token_file = {quote(str(state / "bot.token"))}', 'api_base = "https://api.telegram.org"',
        'use_message_drafts = false', 'show_unfinished_messages = false',
        'lifecycle_notifications = false', 'auto_create_topics = false',
        'stale_topic_action = "none"', 'completion_notify_usernames = []', '[codex]',
        f'binary = {quote(str(codex))}', 'shared_app_server = true',
        'auto_attach_latest_history = false', f'default_cwd = {quote(str(home / "Projects/being"))}',
        f'default_model = {quote(profile["model"])}',
        f'default_reasoning_effort = {quote(profile["reasoning"])}',
        f'default_sandbox = {quote(profile["sandbox"])}',
        f'default_approval = {quote(profile["approval"])}', 'default_search_mode = "live"',
        'import_desktop_history = false', 'import_cli_history = false',
        'seed_workspaces = []', 'default_add_dirs = []']
    return ('\n'.join(lines) + '\n').encode()


def service(home: Path, code: Path, codex: Path = Path('/usr/local/bin/codex')) -> bytes:
    argv = [str(code / 'telegram/telecodex'), str(home / '.local/state/daimon-onboarding/telegram/config.toml')]
    encoded = ' '.join(json.dumps(arg.replace('%', '%%').replace('$', '$$')) for arg in argv)
    return ('[Unit]\nDescription=Dedicated receiving Telegram human listener\n'
        f'After=network-online.target daimon-onboarding-matrix.service {NATIVE_UNIT}\n'
        f'Requires={NATIVE_UNIT}\nWants=network-online.target\n'
        '[Service]\nType=simple\nUser=agent\nGroup=agent\n'
        f'Environment=HOME={home}\nEnvironment=CODEX_HOME={home}/.codex\n'
        'Environment=PATH=/usr/local/bin:/usr/bin:/bin\nUMask=0077\n'
        'Restart=on-failure\nRestartSec=5\nKillMode=control-group\nTimeoutStartSec=180\nTimeoutStopSec=30\n'
        f'WorkingDirectory={home}/Projects/being\n'
        f'ExecStart={encoded}\n'
        '[Install]\nWantedBy=multi-user.target\n').encode()



def native_service(home: Path, codex: Path, code: Path) -> bytes:
    # Separate cgroups preserve the shared native daemon across listener restarts.
    launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                'from clusterctl.onboarding_telegram import main;raise SystemExit(main())')
    args = ['/usr/bin/python3', '-B', '-I', '-c', launcher, str(code), 'native-serve',
            '--code', str(code), '--plan', str(home / '.onboarding-input/plan.json')]
    encoded = ' '.join(json.dumps(arg.replace('%', '%%').replace('$', '$$')) for arg in args)
    command = json.dumps(str(codex))
    return ('[Unit]\nDescription=Receiving native Codex daemon\n'
        'After=network-online.target\nWants=network-online.target\n'
        '[Service]\nType=simple\nUser=agent\nGroup=agent\n'
        f'Environment=HOME={home}\nEnvironment=CODEX_HOME={home}/.codex\n'
        'Environment=PATH=/usr/local/bin:/usr/bin:/bin\nUMask=0077\n'
        f'ExecStart={encoded}\nExecStop={command} app-server daemon stop\n'
        'Restart=on-failure\nRestartSec=5\nTimeoutStopSec=30\nKillMode=control-group\n'
        'StandardOutput=null\nStandardError=null\n[Install]\nWantedBy=multi-user.target\n').encode()


def native_serve(home: Path, codex: Path, *, run=subprocess.run, wait=time.sleep, cycles=None) -> None:
    """Supervise the native singleton without inference or Matrix attention."""
    env = dict(HOME=str(home), CODEX_HOME=str(home / '.codex'), PATH='/usr/local/bin:/usr/bin:/bin')
    count = 0
    while cycles is None or count < cycles:
        # Native start is idempotent and waits for the control handshake. It
        # recovers a departed daemon without replaying any conversation turn.
        result = run([str(codex), 'app-server', 'daemon', 'start'], capture_output=True,
                     text=True, timeout=180, check=False, env=env)
        if result.returncode:
            raise OnboardingError('native_codex_daemon_start_failed')
        count += 1
        wait(5)


def api(token: str, method: str) -> dict:
    if method not in {'getMe', 'getWebhookInfo'}:
        raise OnboardingError('unsupported_telegram_preflight')
    try:
        request = urllib.request.Request('https://api.telegram.org/bot' + token + '/' + method, data=b'')
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(65537)
        value = json.loads(raw)
        if (len(raw) > 65536 or not isinstance(value, dict) or value.get('ok') is not True
                or not isinstance(value.get('result'), dict)):
            raise ValueError()
        return value['result']
    except (OSError, ValueError, urllib.error.URLError):
        # Never disclose a credential-bearing URL, vendor description or trace.
        raise OnboardingError('telegram_preflight_failed') from None


def prepare(home: Path, code: Path, codex: Path, plan: dict, profile: dict,
            supplied: dict, *, request=api) -> dict:
    validate_plan(plan)
    value = connections(supplied)
    token = value['telegram_bot_token']
    bot = request(token, 'getMe')
    if (bot.get('is_bot') is not True or type(bot.get('id')) is not int or bot['id'] <= 0
            or bot['id'] != int(token.split(':', 1)[0])
            or not isinstance(bot.get('username'), str) or not re.fullmatch(r'[A-Za-z0-9_]{5,64}', bot['username'])):
        raise OnboardingError('telegram_preflight_failed')
    if bot.get('has_topics_enabled') is not True:
        raise OnboardingError('telegram_topics_required')
    webhook = request(token, 'getWebhookInfo')
    if webhook.get('url') != '':
        raise OnboardingError('existing_telegram_consumer_preserved')
    state = home / '.local/state/daimon-onboarding/telegram'
    mkdir_chain(home, state)
    binding = dict(schema=SCHEMA, plan_digest=digest(plan), bot_id=bot['id'],
                   human_id=value['telegram_chat_id'], token_sha256=hashlib.sha256(token.encode()).hexdigest())
    # Invalid or incompatible bot data never freezes the receiving binding.
    with being_seed._locked(state):
        new_bytes(state / 'binding.json', json.dumps(binding, sort_keys=True).encode())
        new_bytes(state / 'bot.token', token.encode())
        mkdir_chain(home, state / 'tmp')
        new_bytes(state / 'config.toml', configuration(home, code, codex, value['telegram_chat_id'], profile))
    return dict(configured=True, plan_digest=digest(plan), bot_id=bot['id'], topics_enabled=True)


def reserve(root: Path, plan: dict, supplied: dict) -> None:
    """Keep one durable bot reservation across all jobs, including crashes."""
    from .onboarding import private_directory
    validate_plan(plan)
    supplied = connections(supplied)
    private_directory(root)
    catalog = root / 'telegram-consumers'
    private_directory(catalog, create=True)
    bot_id = int(supplied['telegram_bot_token'].split(':', 1)[0])
    record = dict(schema='cluster-onboarding-telegram-consumer/v1', bot_id=bot_id,
                  plan_digest=digest(plan))
    with being_seed._locked(catalog):
        path = catalog / (str(bot_id) + '.json')
        if path.exists():
            if being_seed._read(path) != record:
                raise OnboardingError('existing_telegram_consumer_preserved')
        else:
            being_seed._write(path, record)


def idle(database: Path, *, uid: int) -> bool:
    """Read operational activity only, never message text or native history."""
    being_seed._path(database)
    info = database.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise OnboardingError('private_telegram_database_required')
    for suffix in ('-wal', '-shm'):
        path = database.with_name(database.name + suffix)
        if path.exists():
            being_seed._path(path)
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
                raise OnboardingError('private_telegram_database_required')
    if os.geteuid() != uid:
        # The database owner also owns SQLite's operational SHM read marks.
        script = ("import sqlite3,sys,json;from pathlib import Path;"
                  "c=sqlite3.connect(Path(sys.argv[1]).as_uri()+'?mode=ro',uri=True,timeout=5);"
                  "v=c.execute('SELECT count(*) FROM sessions WHERE busy != 0').fetchone()[0]==0 "
                  "and c.execute(\"SELECT count(*) FROM turns WHERE status='running'\").fetchone()[0]==0;"
                  "c.close();print(json.dumps(v))")
        result = subprocess.run([sys.executable, '-B', '-I', '-c', script, str(database)],
            user=uid, group=database.stat().st_gid, capture_output=True, text=True, timeout=15, check=False)
        if result.returncode or result.stdout.strip() not in {'true', 'false'}:
            raise OnboardingError('telegram_activity_requires_attention')
        return result.stdout.strip() == 'true'
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        return (connection.execute('SELECT count(*) FROM sessions WHERE busy != 0').fetchone()[0] == 0
                and connection.execute("SELECT count(*) FROM turns WHERE status='running'").fetchone()[0] == 0)
    finally:
        connection.close()


def upgrade(home: Path, base: Path, code: Path, codex: Path, plan: dict, *,
            directory: Path = Path('/etc/systemd/system'),
            journal_root: Path = Path('/var/lib/daimon-onboarding-telegram-upgrade'),
            owner_uid: int = 1000, run=subprocess.run) -> dict:
    """One idle consumer; back up SQLite but never roll back accepted inputs."""
    from .onboarding import private_directory
    private_directory(journal_root, create=True)
    with being_seed._locked(journal_root):
        return _upgrade(home, base, code, codex, plan, directory=directory,
                        journal_root=journal_root, owner_uid=owner_uid, run=run)


def _upgrade(home: Path, base: Path, code: Path, codex: Path, plan: dict, *,
             directory: Path, journal_root: Path, owner_uid: int, run) -> dict:
    validate_plan(plan)
    if code == base:
        raise OnboardingError('qualified_telegram_successor_required')
    unit = directory / UNIT
    old, new = service(home, base, codex), service(home, code, codex)
    current = onboarding_release.regular(unit, uid=os.geteuid(), limit=65536)
    if current not in (old, new):
        raise OnboardingError('existing_telegram_service_preserved')
    database = home / '.local/state/daimon-onboarding/telegram/telegram.sqlite3'
    transaction = journal_root / (digest(plan) + '.json')
    binding = dict(schema='cluster-onboarding-telegram-upgrade/v1', plan_digest=digest(plan),
                   before_sha256=hashlib.sha256(old).hexdigest(), after_sha256=hashlib.sha256(new).hexdigest())
    record = being_seed._read(transaction) if transaction.exists() else None
    if record is not None and any(record.get(k) != v for k, v in binding.items()):
        raise OnboardingError('existing_telegram_upgrade_preserved')
    def command(argv):
        result = run(['systemctl', *argv], capture_output=True, text=True, timeout=40, check=False)
        if result.returncode:
            raise OnboardingError('telegram_service_failed')
    if current == new:
        # Recover a crash after publication, with the current DB untouched.
        command(['daemon-reload'])
        command(['start', UNIT])
        if record is not None:
            being_seed._write(transaction, {**binding, 'phase': 'active'})
        return dict(plan_digest=digest(plan), upgraded=True, database_restored=False)
    if not idle(database, uid=owner_uid):
        return dict(plan_digest=digest(plan), upgraded=False, upgrade_waiting=True)
    being_seed._write(transaction, {**binding, 'phase': 'prepared'})
    command(['stop', UNIT])
    if not idle(database, uid=owner_uid):
        command(['start', UNIT])
        return dict(plan_digest=digest(plan), upgraded=False, upgrade_waiting=True)
    def replace(before, after):
        if onboarding_release.regular(unit, uid=os.geteuid(), limit=65536) != before:
            raise OnboardingError('existing_telegram_service_preserved')
        import uuid
        temporary = unit.with_name('.telegram-upgrade-' + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            with os.fdopen(fd, 'wb') as output:
                os.fchmod(output.fileno(), 0o644)
                output.write(after)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, unit)
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            temporary.unlink(missing_ok=True)
    try:
        backup = journal_root / (digest(plan) + '.sqlite3')
        if not backup.exists():
            # SQLite's readonly connection may write SHM read marks. Copy the
            # stopped consumer's DB and journals before the backup API; never
            # create root-owned sidecars in the receiving user's runtime.
            with tempfile.TemporaryDirectory(prefix='.telegram-backup-', dir=journal_root) as scratch:
                snapshot = Path(scratch) / 'source.sqlite3'
                observed = {}
                for suffix in ('', '-wal', '-shm'):
                    original = database.with_name(database.name + suffix)
                    if not original.exists():
                        continue
                    being_seed._path(original)
                    fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, 'rb') as incoming:
                        info = os.fstat(incoming.fileno())
                        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                                or info.st_mode & 0o077 or info.st_nlink != 1):
                            raise OnboardingError('private_telegram_database_required')
                        copied = snapshot.with_name(snapshot.name + suffix)
                        with copied.open('xb') as output:
                            shutil.copyfileobj(incoming, output)
                        copied.chmod(0o600)
                        observed[original] = (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                for original, before in observed.items():
                    info = original.stat()
                    if before != (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns):
                        raise OnboardingError('telegram_snapshot_changed')
                pending = Path(scratch) / 'verified.sqlite3'
                source = sqlite3.connect(snapshot.as_uri() + '?mode=ro', uri=True, timeout=5)
                target = sqlite3.connect(pending)
                try:
                    source.backup(target)
                    if target.execute('PRAGMA quick_check').fetchone() != ('ok',):
                        raise OnboardingError('verified_telegram_backup_required')
                finally:
                    source.close()
                    target.close()
                pending.chmod(0o600)
                fd = os.open(pending, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                if backup.exists():
                    raise OnboardingError('existing_telegram_upgrade_preserved')
                os.replace(pending, backup)
                parent = os.open(journal_root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        being_seed._path(backup)
        info = backup.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise OnboardingError('verified_telegram_backup_required')
        check = sqlite3.connect(backup.as_uri() + '?mode=ro', uri=True)
        try:
            if check.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise OnboardingError('verified_telegram_backup_required')
        finally:
            check.close()
        being_seed._write(transaction, {**binding, 'phase': 'backed-up'})
        replace(old, new)
        being_seed._write(transaction, {**binding, 'phase': 'published'})
        command(['daemon-reload'])
        command(['start', UNIT])
        being_seed._write(transaction, {**binding, 'phase': 'active'})
    except BaseException:
        # Software rollback never restores the DB, WAL, thread map or offset.
        current = onboarding_release.regular(unit, uid=os.geteuid(), limit=65536)
        if current not in (old, new):
            raise OnboardingError('existing_telegram_service_preserved')
        if current == new:
            command(['stop', UNIT])
            replace(new, old)
        command(['daemon-reload'])
        command(['start', UNIT])
        being_seed._write(transaction, {**binding, 'phase': 'rolled-back'})
        raise
    return dict(plan_digest=digest(plan), upgraded=True, database_restored=False)


def native_budget(timeout_seconds: float | None, expires_at_ms: int | None):
    """One guest-local budget, established before code/plan verification."""
    if timeout_seconds is None and expires_at_ms is None:
        return lambda maximum: maximum
    import math
    if (timeout_seconds is None or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60
            or type(expires_at_ms) is not int or not 0 < expires_at_ms < 2**53):
        raise OnboardingError('native_codex_preparation_expired')
    deadline = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
    def remaining(maximum):
        value = min(maximum, (deadline - time.monotonic_ns()) / 1_000_000_000,
            (expires_at_ms - time.time_ns() // 1_000_000) / 1000)
        if value <= 0:
            raise OnboardingError('native_codex_preparation_expired')
        return value
    remaining(60)
    return remaining


def install_native(home: Path, codex: Path, code: Path, *, budget,
                   unit_directory: Path = Path('/etc/systemd/system'), run=subprocess.run) -> None:
    budget(180)
    publish(unit_directory / NATIVE_UNIT, native_service(home, codex, code))
    for command in (['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', NATIVE_UNIT]):
        result = run(command, capture_output=True, text=True, timeout=budget(180), check=False)
        budget(180)
        if result.returncode:
            raise OnboardingError('native_codex_daemon_start_failed')


def native_observation(home: Path, codex: Path, code: Path, *,
                       unit_directory: Path = Path('/etc/systemd/system'), run=subprocess.run,
                       timeout_seconds: float = 30) -> dict:
    """Observe the exact native unit; never start, stop or reload it."""
    unit = unit_directory / NATIVE_UNIT
    expected = native_service(home, codex, code)
    exists = unit.exists() or unit.is_symlink()
    if exists and onboarding_release.regular(unit, uid=0) != expected:
        raise OnboardingError('existing_native_codex_service_preserved')
    result = run(['systemctl', 'show', NATIVE_UNIT, '--property=LoadState', '--property=ActiveState',
        '--property=MainPID', '--property=FragmentPath', '--property=DropInPaths'],
        capture_output=True, text=True, timeout=timeout_seconds, check=False)
    fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if (not fields.get('MainPID', '').isdecimal() or fields.get('DropInPaths') != ''
            or fields.get('LoadState') not in {'loaded', 'not-found'}):
        raise OnboardingError('native_codex_daemon_observation_failed')
    pid = int(fields['MainPID'])
    if not exists:
        if (fields['LoadState'] != 'not-found' or fields.get('FragmentPath') != ''
                or fields.get('ActiveState') not in {'inactive', 'failed'} or pid):
            raise OnboardingError('existing_native_codex_service_preserved')
        state = 'absent'
    else:
        if (fields.get('FragmentPath') not in {'', str(unit)}
                or result.returncode and fields['LoadState'] != 'not-found'):
            raise OnboardingError('existing_native_codex_service_preserved')
        state = ('active' if fields.get('ActiveState') == 'active' and pid > 0 else
                 'inactive' if fields.get('ActiveState') in {'inactive', 'failed'} and pid == 0 else 'pending')
    return dict(native_state=state)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'install', 'observe', 'probe', 'native-install', 'native-observe', 'native-serve', 'upgrade'))
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--runtime-code', type=Path)
    parser.add_argument('--runtime-digest')
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--operation-timeout-seconds', type=float)
    parser.add_argument('--authorization-expires-at-ms', type=int)
    args = parser.parse_args(argv)
    try:
        budget = native_budget(args.operation_timeout_seconds, args.authorization_expires_at_ms)
        if (args.operation_timeout_seconds is not None or args.authorization_expires_at_ms is not None) and args.action not in {
                'native-install', 'native-observe', 'probe'}:
            raise OnboardingError('native_codex_preparation_expired')
        import pwd
        account = pwd.getpwnam('agent')
        if (account.pw_uid != 1000 or account.pw_gid != 1000 or account.pw_dir != '/home/agent'
                or args.plan != Path('/home/agent/.onboarding-input/plan.json')):
            raise OnboardingError('qualified_guest_telegram_required')
        plan = validate_plan(json.loads(onboarding_release.regular(args.plan, uid=1000)))
        if args.code != Path('/opt/daimon-onboarding') / plan['release_digest']:
            raise OnboardingError('qualified_guest_telegram_required')
        release = onboarding_release.verify(args.code, plan['release_digest'], uid=0)
        from . import onboarding_code_successor
        code = onboarding_code_successor.selection(args.runtime_code, args.runtime_digest,
            args.code, plan['release_digest'], uid=0)
        native_runtime = (args.action in {'native-install', 'native-observe', 'probe'}
            and args.runtime_digest is not None
            and code == Path('/opt/daimon-onboarding-runtime') / args.runtime_digest
            and bool(onboarding_code_successor.sdk_parameters(code)))
        if args.runtime_digest is not None and code != Path('/opt/daimon-onboarding-telegram') / args.runtime_digest:
            if not native_runtime:
                raise OnboardingError('qualified_telegram_successor_required')
        binary_code = args.code if native_runtime else code
        artifact(binary_code, uid=0)
        binary = binary_code / 'telegram/telecodex'
        home = Path('/home/agent')
        state = home / '.local/state/daimon-onboarding/telegram'
        codex_path = shutil.which('codex', path='/usr/local/bin:/usr/bin:/bin')
        if not codex_path:
            raise OnboardingError('native_codex_required')
        codex = Path(codex_path)
        if args.action == 'prepare':
            if os.geteuid() != 1000:
                raise OnboardingError('qualified_guest_telegram_required')
            incoming = Path('/home/agent/.onboarding-connections/connections.json')
            supplied = json.loads(onboarding_release.regular(incoming, uid=1000, limit=65536))
            if incoming.stat().st_mode & 0o077:
                raise OnboardingError('private_telegram_connections_required')
            value = prepare(home, code, codex, plan, release['profile'], supplied)
        elif args.action == 'native-serve':
            if os.geteuid() != 1000:
                raise OnboardingError('qualified_guest_telegram_required')
            native_serve(home, codex)
            return 0
        elif args.action == 'native-observe':
            if os.geteuid() != 0:
                raise OnboardingError('qualified_guest_telegram_required')
            value = dict(native_observation(home, codex, args.code, timeout_seconds=budget(30)), plan_digest=digest(plan))
            budget(30)
        elif args.action == 'native-install':
            if os.geteuid() != 0:
                raise OnboardingError('qualified_guest_telegram_required')
            install_native(home, codex, args.code, budget=budget)
            value = dict(native_started=True, plan_digest=digest(plan))
        elif args.action == 'probe':
            if os.geteuid() != 1000:
                raise OnboardingError('qualified_guest_telegram_required')
            # No bot read, listener, history import or model inference.
            result = subprocess.run([str(binary), '--probe-native', str(codex), str(home / 'Projects/being')],
                capture_output=True, text=True, timeout=budget(60), check=False,
                env=dict(HOME=str(home), CODEX_HOME=str(home / '.codex'), PATH='/usr/local/bin:/usr/bin:/bin'))
            if result.returncode:
                raise OnboardingError('native_telegram_probe_failed')
            budget(60)
            value = dict(native_probe=json.loads(result.stdout), inference=False, bot_read=False)
        else:
            if os.geteuid() != 0:
                raise OnboardingError('qualified_guest_telegram_required')
            marker = state / 'binding.json'
            if not marker.exists():
                value = dict(configured=False, listening=False, plan_digest=digest(plan))
            else:
                binding = json.loads(onboarding_release.regular(marker, uid=1000, limit=65536))
                if binding.get('schema') != SCHEMA or binding.get('plan_digest') != digest(plan):
                    raise OnboardingError('existing_telegram_binding_preserved')
                expected = configuration(home, args.code, codex, binding['human_id'], release['profile'])
                if not (state / 'config.toml').exists() or not (state / 'bot.token').exists():
                    if args.action == 'install':
                        raise OnboardingError('telegram_preparation_required')
                    print(json.dumps(dict(configured=False, listening=False, plan_digest=digest(plan))))
                    return 0
                configured = onboarding_release.regular(state / 'config.toml', uid=1000, limit=65536)
                token_path = state / 'bot.token'
                token = onboarding_release.regular(token_path, uid=1000, limit=1024)
                if (configured != expected or marker.stat().st_mode & 0o077
                        or (state / 'config.toml').stat().st_mode & 0o077 or token_path.stat().st_mode & 0o077
                        or hashlib.sha256(token).hexdigest() != binding['token_sha256']):
                    raise OnboardingError('existing_telegram_binding_preserved')
                unit = Path('/etc/systemd/system') / UNIT
                unit_bytes = service(home, code, codex)
                previous_unit = service(home, args.code, codex)
                current_unit = onboarding_release.regular(unit, uid=0) if unit.exists() else None
                if args.action == 'upgrade':
                    value = upgrade(home, args.code, code, codex, plan)
                    print(json.dumps(value))
                    return 0
                if current_unit == previous_unit and code != args.code:
                    value = dict(configured=True, listening=False, plan_digest=digest(plan),
                                 upgrade_required=True, upgrade_waiting=not idle(state / 'telegram.sqlite3', uid=1000))
                    print(json.dumps(value))
                    return 0
                if args.action == 'install':
                    publish(unit, unit_bytes)
                    for command in (['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', UNIT]):
                        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                        if result.returncode:
                            raise OnboardingError('telegram_service_failed')
                if unit.exists() and onboarding_release.regular(unit, uid=0) != unit_bytes:
                    raise OnboardingError('existing_telegram_service_preserved')
                result = subprocess.run(['systemctl', 'show', UNIT, '--property=ActiveState', '--property=MainPID'],
                                        capture_output=True, text=True, timeout=30, check=False)
                fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
                pid = fields.get('MainPID', '')
                listening = (fields.get('ActiveState') == 'active' and pid.isdecimal() and int(pid) > 0
                             and Path('/proc', pid, 'exe').resolve() == binary)
                value = dict(configured=True, listening=listening, plan_digest=digest(plan),
                             bot_id=binding['bot_id'], telegram_verified=False)
        print(json.dumps(value))
        return 0
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        print(json.dumps(dict(error='native_onboarding_telegram_refused')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
