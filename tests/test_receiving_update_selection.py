"""Actual immutable SDK successors and kernel-owned unit selection recovery."""
import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
from pathlib import Path

import pytest

from clusterctl import being_seed, onboarding_code_successor, onboarding_release, onboarding_sdk
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_service import UNIT, code_command, entrypoint, install, select_entrypoint, selection_lock
from tests.test_onboarding_code_successor import sdk_generations
from tests.test_receiving_update_preflight import fixture as candidate_fixture, REVISION


def fixture(tmp_path):
    original = tmp_path / 'old'
    original.mkdir()
    base, checksum, source, _, _, home = sdk_generations(original)
    replacement = tmp_path / 'new'
    replacement.mkdir()
    code, _, _, _, manifest, _ = candidate_fixture(replacement)
    sdk = code / 'sdk'
    output = tmp_path / 'selected-code'
    result = onboarding_code_successor.build(base, checksum, source,
        ('onboarding_target.py',), output, sdk=sdk, matrix_commit=REVISION,
        matrix_wheel_sha256=manifest['artifacts']['matrix_sdk'])
    return base, checksum, output, result, home, manifest


def test_explicit_qualified_successor_preserves_original_context_and_uses_its_exact_sdk(tmp_path):
    base, original, output, result, home, manifest = fixture(tmp_path)
    before = {p: p.read_bytes() for p in base.rglob('*') if p.is_file()}
    onboarding_code_successor.verify(output, result['runtime_digest'], base, original, uid=os.geteuid())
    parameters = onboarding_code_successor.sdk_parameters(output, uid=os.geteuid())
    assert parameters == dict(matrix_commit=REVISION, matrix_wheel_sha256=manifest['artifacts']['matrix_sdk'])
    marker = json.loads((output / onboarding_code_successor.MARKER).read_bytes())
    assert marker['schema'] == onboarding_code_successor.QUALIFIED_SDK_SCHEMA
    assert marker['base_release_digest'] == original
    old = onboarding_sdk.install(home, base, original, code_uid=os.geteuid(),
        matrix_commit=onboarding_sdk.PREVIOUS_MATRIX_COMMIT)
    old_bytes = {p: p.read_bytes() for p in old.parent.rglob('*') if p.is_file()}
    new = onboarding_sdk.install(home, output, result['runtime_digest'], code_uid=os.geteuid(), **parameters)
    assert new != old and onboarding_sdk.observe(home, output, code_uid=os.geteuid(), **parameters) == new
    assert onboarding_sdk.interpreter(new)['version'] == list(__import__('sys').version_info[:3])
    assert all(p.read_bytes() == raw for p, raw in before.items())
    assert all(p.read_bytes() == raw for p, raw in old_bytes.items())
    for name in ('inheritance.md', 'hmk/scripts/memoryctl.py', 'telegram/telecodex'):
        assert (base / name).read_bytes() == (output / name).read_bytes()
    assert not list(home.rglob('custody.json'))


@pytest.mark.parametrize('field,value', [('matrix_commit', 'c' * 40),
    ('matrix_wheel_sha256', 'c' * 64), ('previous_sdk_digest', 'c' * 64), ('extra', True)])
def test_resealed_marker_cannot_substitute_sdk_or_original_base(tmp_path, field, value):
    base, original, output, _, _, _ = fixture(tmp_path)
    marker = output / onboarding_code_successor.MARKER
    body = json.loads(marker.read_bytes())
    body[field] = value
    marker.write_text(json.dumps(body))
    profile = json.loads((output / 'release.json').read_bytes())['profile']
    (output / 'release.json').unlink()
    checksum = onboarding_release.seal(output, profile)
    with pytest.raises(OnboardingError):
        onboarding_code_successor.verify(output, checksum, base, original, uid=os.geteuid())


def test_qualified_builder_rejects_incomplete_or_wrong_selection_before_output(tmp_path):
    old = tmp_path / 'old'
    old.mkdir()
    base, checksum, source, _, sdk, _ = sdk_generations(old)
    for arguments in (dict(matrix_commit=REVISION), dict(matrix_wheel_sha256='f' * 64),
                      dict(matrix_commit=REVISION, matrix_wheel_sha256='f' * 64)):
        output = tmp_path / 'refused'
        with pytest.raises(OnboardingError):
            onboarding_code_successor.build(base, checksum, source, ('onboarding_target.py',), output,
                sdk=sdk, **arguments)
        assert not output.exists()


def test_target_launcher_selects_qualified_sdk_before_body_or_native_reexec(tmp_path, monkeypatch, capsys):
    from clusterctl import onboarding_target
    from tests.test_onboarding import plan
    base, original, output, result, home, manifest = fixture(tmp_path)
    selected_parameters = onboarding_code_successor.sdk_parameters(output, uid=os.geteuid())
    parameters = onboarding_code_successor.sdk_parameters
    selection = onboarding_code_successor.selection
    monkeypatch.setattr(onboarding_code_successor, 'selection', lambda *a, **k: selection(*a, uid=os.geteuid()))
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda code, **k: parameters(code, uid=os.geteuid()))
    calls = []
    def prepare(home_arg, code_arg, fingerprint, **kwargs):
        calls.append((home_arg, code_arg, fingerprint, kwargs))
        return home / 'prepared-venv'
    def prepare_imports(venv, code, **kwargs):
        assert calls == [(home, output, result['runtime_digest'], selected_parameters)]
        assert (venv, code, kwargs) == (home / 'prepared-venv', output, selected_parameters)
        calls.append('closed-imports-prepared')
        return home / 'closed-imports'
    def no_body(*a, **k):
        pytest.fail('SDK preparation loaded private native state')
    monkeypatch.setattr(onboarding_sdk, 'install', prepare)
    monkeypatch.setattr(onboarding_sdk, 'runtime_imports', prepare_imports)
    monkeypatch.setattr(onboarding_target, 'Target', no_body)
    path = tmp_path / 'plan.json'
    being_seed._write(path, {**plan(), 'release_digest': original})
    assert onboarding_target.main(['sdk-prepare', '--home', str(home), '--code', str(base),
        '--runtime-code', str(output), '--runtime-digest', result['runtime_digest'],
        '--plan', str(path), '--genesis', str(tmp_path / 'absent-genesis.json')]) == 0
    assert calls == [(home, output, result['runtime_digest'], selected_parameters), 'closed-imports-prepared']
    assert json.loads(capsys.readouterr().out) == dict(ready=True, matrix_commit=REVISION)
    assert manifest['artifacts']['matrix_sdk'] == selected_parameters['matrix_wheel_sha256']


def unit_fixture(tmp_path):
    unit = tmp_path / UNIT
    original = (b'[Unit]\nDescription=Retained body\nAfter=custom.target\n[Service]\n'
                b'User=agent\nEnvironment=PRIVATE_VALUE=retained\nLoadCredential=matrix-password:retained\n'
                b'ExecStart=/old/exact-loader --native-root /private/original\n'
                b'KillMode=control-group\nTimeoutStopSec=30\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n')
    unit.write_bytes(original)
    unit.chmod(0o640)
    return unit, original, hashlib.sha256(original).hexdigest(), ['/new/qualified-loader', '--runtime', 'candidate']


def test_unit_cas_preserves_all_other_directives_mode_and_exact_retry(tmp_path):
    unit, original, checksum, argv = unit_fixture(tmp_path)
    expected = entrypoint(original, argv)
    first = select_entrypoint(unit, argv, previous_sha256=checksum)
    assert select_entrypoint(unit, argv, previous_sha256=checksum) == first
    assert unit.read_bytes() == expected and unit.stat().st_mode & 0o777 == 0o640
    retained = unit.with_name(unit.name + '.' + checksum + '.previous')
    assert retained.read_bytes() == original and retained.stat().st_mode & 0o777 == 0o640
    assert first['loaded_readiness'] == 'unobserved'
    assert [line for line in original.splitlines() if not line.startswith(b'ExecStart=')] == [
        line for line in expected.splitlines() if not line.startswith(b'ExecStart=')]
    assert not list(tmp_path.glob('.onboarding-selection-*'))


def test_lost_publication_ack_reconciles_actual_unit_without_replacing_again(tmp_path, monkeypatch):
    from clusterctl import onboarding_service
    unit, original, checksum, argv = unit_fixture(tmp_path)
    replace = onboarding_service.os.replace
    replacements = []
    def lost_ack(source, target):
        replace(source, target)
        replacements.append(target)
        raise OSError('synthetic lost acknowledgement after actual atomic replacement')
    monkeypatch.setattr(onboarding_service.os, 'replace', lost_ack)
    with pytest.raises(OSError):
        select_entrypoint(unit, argv, previous_sha256=checksum)
    assert unit.read_bytes() == entrypoint(original, argv)
    result = select_entrypoint(unit, argv, previous_sha256=checksum)
    assert result['selected'] is True and result['loaded_readiness'] == 'unobserved'
    assert replacements == [unit]


def test_stale_selector_preserves_newer_selection_and_retained_history(tmp_path):
    unit, original, checksum, argv = unit_fixture(tmp_path)
    select_entrypoint(unit, argv, previous_sha256=checksum)
    newer_argv = ['/newer/qualified-loader']
    selected = hashlib.sha256(unit.read_bytes()).hexdigest()
    select_entrypoint(unit, newer_argv, previous_sha256=selected)
    before = {p: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}
    with pytest.raises(OnboardingError, match='existing_onboarding_service_preserved'):
        select_entrypoint(unit, argv, previous_sha256=checksum)
    assert all(p.read_bytes() == raw for p, raw in before.items())
    assert unit.read_bytes() == entrypoint(original, newer_argv)


@pytest.mark.parametrize('kind', ['qualified-sdk', 'stdlib-bootstrap', 'directive-looking-argument'])
def test_multiline_arguments_remain_data_in_one_selected_unit_line(tmp_path, kind):
    unit, original, checksum, _ = unit_fixture(tmp_path)
    if kind == 'qualified-sdk':
        argv = onboarding_sdk.runtime_command(Path('/approved/sdk/venv'), Path('/approved/sdk/runtime-imports'),
            Path('/approved/code'), 'clusterctl.onboarding_source', ['--config', '/approved/source.json'])
    elif kind == 'stdlib-bootstrap':
        argv = code_command(Path('/approved/python'), Path('/approved/code'),
            'clusterctl.onboarding_source', ['--config', '/approved/source.json'])
    else:
        argv = ['/approved/loader', 'argument\nExecStart=/another/loader\rEnvironment=UNEXPECTED=yes']
    assert any('\n' in arg for arg in argv)
    select_entrypoint(unit, argv, previous_sha256=checksum)
    lines = unit.read_bytes().splitlines()
    assert [line for line in lines if not line.startswith(b'ExecStart=')] == [
        line for line in original.splitlines() if not line.startswith(b'ExecStart=')]
    encoded = next(line[len(b'ExecStart='):] for line in lines if line.startswith(b'ExecStart=')).decode()
    decoder, decoded = json.JSONDecoder(), []
    while encoded:
        value, end = decoder.raw_decode(encoded)
        decoded.append(value)
        encoded = encoded[end:].lstrip()
    assert decoded == argv


@pytest.mark.parametrize('argv', [[], ['/new/loader', 'bad\0'], ['relative']])
def test_invalid_entrypoint_cannot_replace_or_execute_anything(tmp_path, argv):
    unit, original, checksum, _ = unit_fixture(tmp_path)
    with pytest.raises(OnboardingError):
        select_entrypoint(unit, argv, previous_sha256=checksum)
    assert unit.read_bytes() == original
    assert not list(tmp_path.glob('*.previous'))


def _hold(unit, started):
    with selection_lock(unit):
        started.set()
        __import__('time').sleep(30)


def test_actual_process_lock_blocks_select_and_install_then_recovers_on_owner_exit(tmp_path):
    unit, original, checksum, argv = unit_fixture(tmp_path)
    context = multiprocessing.get_context('fork')
    started = context.Event()
    child = context.Process(target=_hold, args=(unit, started))
    child.start()
    try:
        assert started.wait(5)
        for operation in (lambda: select_entrypoint(unit, argv, previous_sha256=checksum),
                          lambda: install(Path('/qualified/original'), receive_only=True,
                                          directory=tmp_path, run=lambda _: pytest.fail('live command escaped lock'))):
            with pytest.raises(being_seed.SeedError, match='seed_operation_in_progress'):
                operation()
        assert unit.read_bytes() == original
    finally:
        child.terminate()
        child.join(5)
        if child.is_alive():
            child.kill()
            child.join(5)
    assert not child.is_alive()
    assert select_entrypoint(unit, argv, previous_sha256=checksum)['selected'] is True


def test_runtime_launch_ignores_site_hooks_extra_modules_and_existing_code_bytecode(tmp_path):
    import importlib.util
    import marshal
    base, original, output, result, home, _ = fixture(tmp_path)
    parameters = onboarding_code_successor.sdk_parameters(output, uid=os.geteuid())
    venv = onboarding_sdk.install(home, output, result['runtime_digest'], code_uid=os.geteuid(), **parameters)
    imports = onboarding_sdk.runtime_imports(venv, output, code_uid=os.geteuid(), **parameters)
    receipt = (imports.parent / 'runtime-imports.json').read_bytes()
    assert onboarding_sdk.runtime_imports(venv, output, code_uid=os.geteuid(), **parameters) == imports
    assert (imports.parent / 'runtime-imports.json').read_bytes() == receipt
    marker = tmp_path / 'unqualified-executed'
    site = next(venv.glob('lib/python*/site-packages'))
    (site / 'unqualified_optional.py').write_text('from pathlib import Path;Path(' + repr(str(marker)) + ').touch()')
    # A deliberately corrupt bytecode cache with a matching source hash would
    # execute under ordinary startup. The verified runtime redirects its lookup.
    probe_code = tmp_path / 'approved-probe-code'
    module = probe_code / 'clusterctl/probe.py'
    module.parent.mkdir(parents=True)
    (module.parent / '__init__.py').write_text('')
    source = '''import json,sys
from pathlib import Path
from daimon_matrix import canonical
try:
    import unqualified_optional
except ModuleNotFoundError:
    absent = True
else:
    absent = False
print(json.dumps(dict(prefix=sys.prefix, no_site=sys.flags.no_site,
    isolated=sys.flags.isolated, absent=absent, imported=canonical.__file__,
    cache_prefix=sys.pycache_prefix, arguments=sys.argv[1:])))
'''
    module.write_text(source)
    cached = Path(importlib.util.cache_from_source(str(module)))
    cached.parent.mkdir()
    malicious = compile('from pathlib import Path;Path(' + repr(str(marker)) + ').touch()', str(module), 'exec')
    cached.write_bytes(importlib.util.MAGIC_NUMBER + (3).to_bytes(4, 'little')
        + importlib.util.source_hash(source.encode()) + marshal.dumps(malicious))
    command = onboarding_sdk.runtime_command(venv, imports, probe_code, 'clusterctl.probe', ['retained-argument'])
    process = subprocess.run(command, capture_output=True, text=True, timeout=10, check=True)
    observed = json.loads(process.stdout)
    assert observed['prefix'] == str(venv) and observed['no_site'] == observed['isolated'] == 1
    assert observed['absent'] and observed['arguments'] == ['retained-argument']
    assert Path(observed['imported']) == imports / 'daimon_matrix/canonical.py'
    assert not marker.exists() and not list(imports.rglob('__pycache__'))
    assert all((base / name).exists() for name in ('inheritance.md', 'telegram/telecodex'))


def test_closed_runtime_tree_rejects_extra_changed_and_symlink_bytes_without_repair(tmp_path):
    _, _, output, result, home, _ = fixture(tmp_path)
    parameters = onboarding_code_successor.sdk_parameters(output, uid=os.geteuid())
    venv = onboarding_sdk.install(home, output, result['runtime_digest'], code_uid=os.geteuid(), **parameters)
    root = onboarding_sdk.runtime_imports(venv, output, code_uid=os.geteuid(), **parameters)
    original = (root / 'daimon_matrix/canonical.py').read_bytes()
    extra = root / 'unexpected.py'
    extra.write_bytes(b'Unqualified optional module.')
    with pytest.raises(OnboardingError, match='qualified_runtime_imports_required'):
        onboarding_sdk.runtime_imports(venv, output, code_uid=os.geteuid(), **parameters)
    assert extra.read_bytes() == b'Unqualified optional module.'
    extra.unlink()
    changed = root / 'daimon_matrix/canonical.py'
    changed.write_bytes(b'Changed completed runtime module.')
    with pytest.raises(OnboardingError, match='qualified_runtime_imports_required'):
        onboarding_sdk.runtime_imports(venv, output, code_uid=os.geteuid(), **parameters)
    assert changed.read_bytes() == b'Changed completed runtime module.'
    changed.write_bytes(original)
    extra.symlink_to(changed)
    with pytest.raises((OnboardingError, ValueError)):
        onboarding_sdk.runtime_imports(venv, output, code_uid=os.geteuid(), **parameters)
    assert extra.is_symlink() and changed.read_bytes() == original


def test_first_bootstrap_uses_no_site_and_ignores_existing_cluster_bytecode(tmp_path):
    import importlib.util
    import marshal
    from clusterctl.onboarding_service import code_command
    module = tmp_path / 'clusterctl/probe.py'
    module.parent.mkdir()
    (module.parent / '__init__.py').write_text('')
    source = ('import json,sys\ndef main():\n'
              ' print(json.dumps(dict(no_site=sys.flags.no_site, isolated=sys.flags.isolated))); return 0\n')
    module.write_text(source)
    cached = Path(importlib.util.cache_from_source(str(module)))
    cached.parent.mkdir()
    cached.write_bytes(importlib.util.MAGIC_NUMBER + (3).to_bytes(4, 'little')
        + importlib.util.source_hash(source.encode()) + marshal.dumps(compile('raise RuntimeError("bad cache")', str(module), 'exec')))
    result = subprocess.run(code_command(Path(sys.executable), tmp_path, 'clusterctl.probe', []),
                            capture_output=True, text=True, timeout=10, check=True)
    assert json.loads(result.stdout) == dict(no_site=1, isolated=1)


def test_closed_tree_dependency_check_cannot_use_extra_installed_distribution(tmp_path, monkeypatch):
    from tests.test_onboarding_sdk import fixture as sdk_fixture
    code, checksum, home = sdk_fixture(tmp_path, requirements=['extra-synthetic>=1'])
    pip = onboarding_sdk._pip
    def existing_extra(venv, mode, *arguments):
        if mode == 'check':
            site = next(venv.glob('lib/python*/site-packages'))
            metadata = site / 'extra_synthetic-1.0.dist-info'
            metadata.mkdir(exist_ok=True)
            (metadata / 'METADATA').write_text('Metadata-Version: 2.1\nName: extra-synthetic\nVersion: 1.0\n')
        return pip(venv, mode, *arguments)
    monkeypatch.setattr(onboarding_sdk, '_pip', existing_extra)
    venv = onboarding_sdk.install(home, code, checksum, code_uid=os.geteuid())
    original = (venv.parent / 'installation.json').read_bytes()
    monkeypatch.setattr(onboarding_sdk, '_pip', pip)
    with pytest.raises(OnboardingError, match='native_onboarding_sdk_refused'):
        onboarding_sdk.runtime_imports(venv, code, code_uid=os.geteuid())
    assert not (venv.parent / 'runtime-imports.json').exists()
    assert (venv.parent / 'installation.json').read_bytes() == original


def test_unit_recovery_reestablishes_directory_durability(tmp_path, monkeypatch):
    from clusterctl import onboarding_service
    unit, _, checksum, argv = unit_fixture(tmp_path)
    select_entrypoint(unit, argv, previous_sha256=checksum)
    synced = []
    fsync = onboarding_service.os.fsync
    def observed(descriptor):
        synced.append(Path('/proc/self/fd/' + str(descriptor)).resolve())
        return fsync(descriptor)
    monkeypatch.setattr(onboarding_service.os, 'fsync', observed)
    select_entrypoint(unit, argv, previous_sha256=checksum)
    assert tmp_path in synced


def test_matching_prefix_without_qualified_startup_must_reexec_before_loading_body(tmp_path, monkeypatch):
    from clusterctl import onboarding_target
    from tests.test_onboarding import plan
    base, original, output, result, home, _ = fixture(tmp_path)
    selection = onboarding_code_successor.selection
    parameters = onboarding_code_successor.sdk_parameters
    monkeypatch.setattr(onboarding_code_successor, 'selection', lambda *a, **k: selection(*a, uid=os.geteuid()))
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda code, **k: parameters(code, uid=os.geteuid()))
    sdk_parameters = parameters(output, uid=os.geteuid())
    venv = onboarding_sdk.install(home, output, result['runtime_digest'], code_uid=os.geteuid(), **sdk_parameters)
    onboarding_sdk.runtime_imports(venv, output, code_uid=os.geteuid(), **sdk_parameters)
    # The prefix alone cannot qualify the actual process. Use the prepared
    # generation that V4 resolves instead of mocking the legacy observe path.
    monkeypatch.setattr(sys, 'prefix', str(venv))
    regular, runtime_imports = onboarding_release.regular, onboarding_sdk.runtime_imports
    monkeypatch.setattr(onboarding_release, 'regular', lambda path, **kw:
        regular(path, **{**kw, 'uid': os.geteuid()}) if path == output / 'sdk/sdk.json' else regular(path, **kw))
    monkeypatch.setattr(onboarding_sdk, 'runtime_imports', lambda *a, **kw:
        runtime_imports(*a, code_uid=os.geteuid(), **kw))
    commands = []
    def execute(path, argv):
        commands.append((path, argv))
        raise RuntimeError('captured qualified reexec')
    monkeypatch.setattr(onboarding_target.os, 'execv', execute)
    monkeypatch.setattr(onboarding_target, 'Target', lambda *a, **k: pytest.fail('unqualified startup loaded Body'))
    path = tmp_path / 'plan.json'
    being_seed._write(path, {**plan(), 'release_digest': original})
    assert onboarding_target.main(['observe', '--home', str(home), '--code', str(base),
        '--runtime-code', str(output), '--runtime-digest', result['runtime_digest'],
        '--plan', str(path), '--genesis', str(tmp_path / 'absent-genesis.json')]) == 1
    assert len(commands) == 1 and commands[0][0] == venv / 'bin/python'
    assert commands[0][1][1:4] == ['-B', '-I', '-S']


def test_closed_tree_publication_persists_nested_directories_before_receipt(tmp_path, monkeypatch):
    _, _, output, result, home, _ = fixture(tmp_path)
    parameters = onboarding_code_successor.sdk_parameters(output, uid=os.geteuid())
    venv = onboarding_sdk.install(home, output, result['runtime_digest'], code_uid=os.geteuid(), **parameters)
    synced = []
    fsync = onboarding_sdk.os.fsync
    def observed(descriptor):
        p = Path('/proc/self/fd/' + str(descriptor)).resolve()
        if p.is_dir():
            synced.append(p)
        return fsync(descriptor)
    monkeypatch.setattr(onboarding_sdk.os, 'fsync', observed)
    root = onboarding_sdk.runtime_imports(venv, output, code_uid=os.geteuid(), **parameters)
    assert any(p.name == 'daimon_matrix' for p in synced)
    assert any(p.name.startswith('runtime-imports-') for p in synced)
    assert venv.parent in synced and (root.parent / 'runtime-imports.json').exists()
