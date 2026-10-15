"""Dedicated listener defaults and preservation before any live bot consumer."""
import json
import os
import sqlite3
from contextlib import closing
import tomllib
from pathlib import Path

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_telegram import configuration, native_service, prepare, service
from tests.test_onboarding import plan

PROFILE = dict(model='gpt-6.1-sol', reasoning='xhigh', approval='never', sandbox='danger-full-access')
TOKEN = '123456789:' + 'x' * 40


def bot_request(token, method):
    assert token == TOKEN
    if method == 'getMe':
        return dict(id=123456789, is_bot=True, username='fixture_bot', has_topics_enabled=True)
    assert method == 'getWebhookInfo'
    return dict(url='')


def test_configuration_displays_only_completed_responses_and_uses_own_harness():
    home, code, codex = Path('/home/agent'), Path('/opt/qualified-code'), Path('/usr/bin/codex')
    value = tomllib.loads(configuration(home, code, codex, 1234, PROFILE).decode())
    assert value['telegram']['show_unfinished_messages'] is False
    assert value['telegram']['use_message_drafts'] is False
    assert value['codex']['shared_app_server'] is True
    assert value['codex']['import_cli_history'] is False
    assert value['codex']['import_desktop_history'] is False
    assert value['codex']['auto_attach_latest_history'] is False
    assert value['background_maintenance'] is False
    assert value['startup_admin_ids'] == [1234]
    assert value['codex']['default_cwd'] == '/home/agent/Projects/being'
    assert TOKEN not in json.dumps(value) + service(home, code).decode()


def test_retry_preserves_later_conversations_and_refuses_changed_bot_or_human(tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    supplied = dict(telegram_bot_token=TOKEN, telegram_chat_id=1234)
    first = prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE, supplied, request=bot_request)
    state = home / '.local/state/daimon-onboarding/telegram'
    conversation = state / 'telegram.sqlite3'
    conversation.write_bytes(b'later conversation/input journal fixture')
    conversation.chmod(0o600)
    assert prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE, supplied, request=bot_request) == first
    assert conversation.read_bytes() == b'later conversation/input journal fixture'
    with pytest.raises(OnboardingError, match='preserved'):
        prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE,
                {**supplied, 'telegram_chat_id': 5678}, request=bot_request)
    assert (state / 'bot.token').stat().st_mode & 0o777 == 0o600
    assert TOKEN not in (state / 'config.toml').read_text() + (state / 'binding.json').read_text()


@pytest.mark.parametrize('problem', ['topics', 'webhook'])
def test_incompatible_bot_never_freezes_binding_or_changes_existing_gateway(tmp_path, problem):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    def request(token, method):
        value = bot_request(token, method)
        if problem == 'topics' and method == 'getMe':
            return {**value, 'has_topics_enabled': False}
        if problem == 'webhook' and method == 'getWebhookInfo':
            return dict(url='https://private-existing-gateway.invalid')
        return value
    with pytest.raises(OnboardingError):
        prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE,
                dict(telegram_bot_token=TOKEN, telegram_chat_id=1234), request=request)
    assert not (home / '.local/state/daimon-onboarding/telegram/binding.json').exists()
    assert prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE,
                   dict(telegram_bot_token=TOKEN, telegram_chat_id=1234), request=bot_request)['configured']


def test_interrupted_preparation_recovers_without_resetting_conversations(tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    supplied = dict(telegram_bot_token=TOKEN, telegram_chat_id=1234)
    prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE, supplied, request=bot_request)
    state = home / '.local/state/daimon-onboarding/telegram'
    (state / 'config.toml').unlink()
    (state / 'bot.token').unlink()
    (state / 'telegram.sqlite3').write_bytes(b'later-history')
    prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE, supplied, request=bot_request)
    assert (state / 'telegram.sqlite3').read_bytes() == b'later-history'
    assert (state / 'bot.token').read_text() == TOKEN


def test_same_bot_cannot_be_reserved_by_another_job_after_retry(tmp_path):
    from clusterctl.onboarding_telegram import reserve
    tmp_path.chmod(0o700)
    supplied = dict(telegram_bot_token=TOKEN, telegram_chat_id=1234)
    reserve(tmp_path, plan(), supplied)
    original = (tmp_path / 'telegram-consumers/123456789.json').read_bytes()
    reserve(tmp_path, plan(), supplied)
    with pytest.raises(OnboardingError, match='existing_telegram_consumer_preserved'):
        reserve(tmp_path, plan(name='oliva', owner='ani'), supplied)
    assert (tmp_path / 'telegram-consumers/123456789.json').read_bytes() == original
    assert TOKEN not in original.decode()


def test_listener_readiness_does_not_satisfy_final_telegram_acceptance(tmp_path):
    from clusterctl import onboarding as ob
    from tests.test_onboarding import FixtureBackend, advance
    backend = FixtureBackend()
    backend.wait = 'acceptance'
    store = ob.JobStore(tmp_path / 'jobs')
    store.submit(plan(), backend)
    result = advance(store, backend)
    assert result['active'] is False
    assert result['stage'] == 'acceptance'
    assert ob.STAGE_FACTS['telegram'] == dict(telegram_ready=True)
    assert 'telegram_verified' in ob.ACCEPTANCE


def test_shared_codex_daemon_has_its_own_lifecycle_outside_listener_cgroup():
    home, code, codex = Path('/home/agent'), Path('/opt/code'), Path('/usr/local/bin/codex')
    listener = service(home, code, codex).decode()
    native = native_service(home, codex, code).decode()
    assert 'Requires=daimon-onboarding-codex.service' in listener
    assert 'ExecStartPre=' not in listener
    assert 'Type=simple' in native and 'Restart=on-failure' in native
    assert 'native-serve' in native and 'app-server daemon stop' in native
    assert 'StandardOutput=null' in native and 'CODEX_HOME=/home/agent/.codex' in native


def test_native_supervisor_reconciles_singleton_without_model_or_message_commands():
    from types import SimpleNamespace
    from clusterctl.onboarding_telegram import native_serve
    calls, waits = [], []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)
    native_serve(Path('/home/agent'), Path('/usr/local/bin/codex'), run=run, wait=waits.append, cycles=3)
    assert waits == [5, 5, 5]
    assert all(argv == ['/usr/local/bin/codex', 'app-server', 'daemon', 'start'] for argv, _ in calls)
    assert all(options['env']['CODEX_HOME'] == '/home/agent/.codex' for _, options in calls)
    with pytest.raises(OnboardingError, match='native_codex_daemon_start_failed'):
        native_serve(Path('/home/agent'), Path('/usr/local/bin/codex'),
                     run=lambda *a, **k: SimpleNamespace(returncode=1), wait=waits.append, cycles=1)


def upgrade_fixture(tmp_path):
    from types import SimpleNamespace
    home = tmp_path / 'home'
    state = home / '.local/state/daimon-onboarding/telegram'
    state.mkdir(mode=0o700, parents=True)
    database = state / 'telegram.sqlite3'
    connection = sqlite3.connect(database)
    connection.executescript('CREATE TABLE sessions(id INTEGER PRIMARY KEY,busy INTEGER, codex_thread_id TEXT);'
                            'CREATE TABLE turns(status TEXT);'
                            'CREATE TABLE incoming_updates(update_id INTEGER PRIMARY KEY,status TEXT);'
                            'CREATE TABLE bot_state(key TEXT PRIMARY KEY,value TEXT);'
                            "INSERT INTO sessions VALUES(1,0,'preserved-native-thread');"
                            "INSERT INTO turns VALUES('completed');"
                            "INSERT INTO incoming_updates VALUES(1,'completed');"
                            "INSERT INTO bot_state VALUES('offset','2');")
    connection.commit()
    connection.close()
    database.chmod(0o600)
    base, new, codex = tmp_path / 'old-code', tmp_path / 'new-code', Path('/usr/bin/codex')
    directory = tmp_path / 'units'
    directory.mkdir(mode=0o755)
    unit = directory / 'daimon-onboarding-telegram.service'
    unit.write_bytes(service(home, base, codex))
    unit.chmod(0o644)
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0)
    args = dict(directory=directory, journal_root=tmp_path / 'journal', owner_uid=os.geteuid(), run=run)
    return home, base, new, codex, database, unit, calls, args


def test_idle_upgrade_preserves_bindings_input_journal_and_verified_sqlite_backup(tmp_path):
    from clusterctl.onboarding_telegram import UNIT, upgrade
    from clusterctl.onboarding import digest
    home, base, new, codex, database, unit, calls, args = upgrade_fixture(tmp_path)
    original = database.read_bytes()
    result = upgrade(home, base, new, codex, plan(), **args)
    assert result['upgraded'] and result['database_restored'] is False
    assert database.read_bytes() == original
    assert unit.read_bytes() == service(home, new, codex)
    assert calls == [['systemctl', 'stop', UNIT], ['systemctl', 'daemon-reload'], ['systemctl', 'start', UNIT]]
    backup = args['journal_root'] / (digest(plan()) + '.sqlite3')
    with closing(sqlite3.connect(backup)) as restored, restored:
        assert restored.execute('PRAGMA quick_check').fetchone() == ('ok',)
        assert restored.execute('SELECT codex_thread_id FROM sessions').fetchone() == ('preserved-native-thread',)
        assert restored.execute('SELECT value FROM bot_state').fetchone() == ('2',)
    assert backup.stat().st_mode & 0o077 == 0
    # An idempotent retry and recovery after unit publication never use backup
    # contents to rewind subsequent accepted inputs or their polling offset.
    with closing(sqlite3.connect(database)) as current, current:
        current.execute("INSERT INTO incoming_updates VALUES(2,'received')")
        current.execute("UPDATE bot_state SET value='3'")
    assert upgrade(home, base, new, codex, plan(), **args)['upgraded']
    with closing(sqlite3.connect(database)) as current, current:
        assert current.execute('SELECT count(*) FROM incoming_updates').fetchone() == (2,)
        assert current.execute('SELECT value FROM bot_state').fetchone() == ('3',)
    assert all('daimon-onboarding-codex.service' not in argv for argv in calls)


def test_busy_turn_waits_without_stopping_consumer_or_changing_unit(tmp_path):
    from clusterctl.onboarding_telegram import upgrade
    home, base, new, codex, database, unit, calls, args = upgrade_fixture(tmp_path)
    original = unit.read_bytes()
    with closing(sqlite3.connect(database)) as current, current:
        current.execute('UPDATE sessions SET busy=1')
    result = upgrade(home, base, new, codex, plan(), **args)
    assert result['upgrade_waiting'] and not result['upgraded']
    assert not calls and unit.read_bytes() == original


def test_verified_backup_includes_committed_wal_without_changing_original_writers_files(tmp_path):
    from clusterctl.onboarding_telegram import upgrade
    from clusterctl.onboarding import digest
    home, base, new, codex, database, _, _, args = upgrade_fixture(tmp_path)
    connection = sqlite3.connect(database)
    try:
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA wal_autocheckpoint=0')
        connection.execute("INSERT INTO incoming_updates VALUES(2,'received')")
        connection.execute("UPDATE bot_state SET value='3'")
        connection.commit()
        wal = database.with_name(database.name + '-wal')
        original_db, original_wal = database.read_bytes(), wal.read_bytes()
        assert upgrade(home, base, new, codex, plan(), **args)['upgraded']
        assert database.read_bytes() == original_db and wal.read_bytes() == original_wal
        backup = args['journal_root'] / (digest(plan()) + '.sqlite3')
        with closing(sqlite3.connect(backup)) as saved:
            assert saved.execute('SELECT count(*) FROM incoming_updates').fetchone() == (2,)
            assert saved.execute('SELECT value FROM bot_state').fetchone() == ('3',)
    finally:
        connection.close()


def test_failed_new_consumer_rolls_back_software_preserving_newly_accepted_input(tmp_path):
    from types import SimpleNamespace
    from clusterctl.onboarding_telegram import UNIT, upgrade
    home, base, new, codex, database, unit, calls, args = upgrade_fixture(tmp_path)
    original = unit.read_bytes()
    def run(argv, **kwargs):
        calls.append(argv)
        if argv == ['systemctl', 'start', UNIT] and unit.read_bytes() != original:
            with closing(sqlite3.connect(database)) as current, current:
                current.execute("INSERT INTO incoming_updates VALUES(2,'undetermined')")
                current.execute("UPDATE bot_state SET value='3'")
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)
    with pytest.raises(OnboardingError, match='telegram_service_failed'):
        upgrade(home, base, new, codex, plan(), **{**args, 'run': run})
    assert unit.read_bytes() == original
    with closing(sqlite3.connect(database)) as current, current:
        assert current.execute('SELECT count(*) FROM incoming_updates').fetchone() == (2,)
        assert current.execute('SELECT value FROM bot_state').fetchone() == ('3',)


def test_foreign_unit_is_preserved_before_any_upgrade_effect(tmp_path):
    from clusterctl.onboarding_telegram import upgrade
    home, base, new, codex, _, unit, calls, args = upgrade_fixture(tmp_path)
    unit.write_bytes(b'An unrelated receiving service.')
    with pytest.raises(OnboardingError, match='existing_telegram_service_preserved'):
        upgrade(home, base, new, codex, plan(), **args)
    assert unit.read_bytes() == b'An unrelated receiving service.' and not calls


@pytest.mark.parametrize("retained", [False, True])
def test_sessions_release_preserves_goal_predecessor_and_rejects_mixed_pins(tmp_path, monkeypatch, retained):
    import hashlib
    from clusterctl import onboarding_telegram as telegram
    binary = b"qualified isolated text runtime fixture"
    (tmp_path / "telecodex").write_bytes(binary)
    (tmp_path / "telecodex").chmod(0o755)
    prefix = "RETAINED_GOAL_" if retained else ""
    monkeypatch.setattr(telegram, prefix + "BINARY", hashlib.sha256(binary).hexdigest())
    artifact = dict(commit=getattr(telegram, prefix + "COMMIT"),
                    archive_sha256=getattr(telegram, prefix + "ARCHIVE"),
                    binary_sha256=getattr(telegram, prefix + "BINARY"),
                    rust_toolchain="1.95.0", features="--no-default-features")
    manifest = tmp_path / "artifact.json"
    manifest.write_text(json.dumps(artifact))
    manifest.chmod(0o644)
    assert telegram.artifact_directory(tmp_path, uid=os.getuid()) == artifact
    artifact["archive_sha256"] = "0" * 64
    manifest.write_text(json.dumps(artifact))
    manifest.chmod(0o644)
    with pytest.raises(OnboardingError, match="qualified_telegram_binary_required"):
        telegram.artifact_directory(tmp_path, uid=os.getuid())


@pytest.mark.parametrize('state', ['absent', 'inactive', 'active', 'pending', 'foreign', 'drop-in', 'unlinked-active'])
def test_native_manager_observation_is_read_only_and_preserves_foreign_units(tmp_path, monkeypatch, state):
    from types import SimpleNamespace
    from clusterctl import onboarding_telegram as telegram
    unit = tmp_path/telegram.NATIVE_UNIT
    home, codex, code = Path('/home/agent'), Path('/usr/bin/codex'), Path('/opt/qualified')
    if state not in {'absent', 'unlinked-active'}:
        unit.write_bytes(b'foreign' if state == 'foreign' else telegram.native_service(home, codex, code))
        unit.chmod(0o600)
    regular = telegram.onboarding_release.regular
    monkeypatch.setattr(telegram.onboarding_release, 'regular', lambda path, **kw: regular(path, uid=os.geteuid()))
    fields = dict(LoadState='loaded', FragmentPath=str(unit), DropInPaths='',
        MainPID='41' if state in {'active', 'unlinked-active'} else '0',
        ActiveState='active' if state in {'active', 'unlinked-active'} else 'activating' if state == 'pending' else 'inactive')
    if state == 'absent':
        fields.update(LoadState='not-found', FragmentPath='')
    if state == 'drop-in':
        fields['DropInPaths'] = '/foreign/override.conf'
    calls = []
    def run(argv, **kwargs):
        assert argv[:2] == ['systemctl', 'show']
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout='\n'.join(key+'='+value for key, value in fields.items()))
    if state in {'foreign', 'drop-in', 'unlinked-active'}:
        with pytest.raises(OnboardingError):
            telegram.native_observation(home, codex, code, unit_directory=tmp_path, run=run)
    else:
        assert telegram.native_observation(home, codex, code, unit_directory=tmp_path, run=run) == {'native_state': state}
    assert len(calls) == (0 if state == 'foreign' else 1)


@pytest.mark.parametrize('expire', [None, 'before-publish', 'after-publish', 'after-reload'])
def test_guest_native_install_keeps_one_budget_through_verification_and_each_effect(tmp_path, monkeypatch, expire):
    from types import SimpleNamespace
    from clusterctl import onboarding_telegram as telegram
    clock = {'mono': 0, 'wall': 100_000_000_000}
    monkeypatch.setattr(telegram, 'time', SimpleNamespace(
        monotonic_ns=lambda: clock['mono'], time_ns=lambda: clock['wall']))
    budget = telegram.native_budget(2, 101_000)
    published, commands = [], []
    def publish(path, raw):
        published.append(raw)
        if expire == 'after-publish':
            clock['mono'] = 3_000_000_000
    monkeypatch.setattr(telegram, 'publish', publish)
    if expire == 'before-publish':
        # Verification consumed the original guest budget; do not reset it.
        clock['mono'] = 3_000_000_000
    def run(argv, **kwargs):
        assert 0 < kwargs['timeout'] <= 1
        commands.append(argv)
        if expire == 'after-reload':
            # A wall-clock authorization expiry is independent of monotonic time.
            clock['wall'] = 102_000_000_000
        return SimpleNamespace(returncode=0)
    def install():
        telegram.install_native(Path('/home/agent'), Path('/usr/bin/codex'), Path('/opt/qualified'),
            unit_directory=tmp_path, budget=budget, run=run)
    if expire:
        with pytest.raises(OnboardingError, match='native_codex_preparation_expired'):
            install()
        assert len(commands) == (1 if expire == 'after-reload' else 0)
        assert len(published) == (0 if expire == 'before-publish' else 1)
    else:
        install()
        assert commands == [['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', telegram.NATIVE_UNIT]]


@pytest.mark.parametrize('timeout, expiry', [(None, 1), (1, None), (0, 101000), (61, 101000), (float('nan'), 101000)])
def test_guest_native_budget_refuses_incomplete_or_invalid_bounds(timeout, expiry):
    from clusterctl.onboarding_telegram import native_budget
    with pytest.raises(OnboardingError, match='native_codex_preparation_expired'):
        native_budget(timeout, expiry)
