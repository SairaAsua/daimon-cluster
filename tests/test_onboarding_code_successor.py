"""Runtime updates preserve frozen receiving context and dependency artifacts."""
import os
import json
import subprocess
import sys
from dataclasses import replace

import pytest

from clusterctl import being_seed, onboarding_release
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_code_successor import build, selected, verify


def fixture(tmp_path):
    base = tmp_path / 'original'
    base.mkdir(mode=0o755)
    files = {'inheritance.md': b'Previously approved Source text.',
        'hmk/scripts/memoryctl.py': b'Original memory tooling.',
        'hmk/scripts/native_records.py': b'Original record tooling.',
        'sdk/pinned.whl': b'Existing qualified dependency artifact.',
        'telegram/telecodex': b'Existing qualified consumer artifact.',
        'clusterctl/__init__.py': b'', 'clusterctl/onboarding_target.py': b'Original runtime.'}
    files.update({'support/being-seed-tools/tools/' + name: b'Original tool.' for name in being_seed.TOOL_HASHES})
    for name, raw in files.items():
        p = base / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
        p.chmod(0o644)
    for directory in base.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    profile = dict(schema=onboarding_release.PROFILE, model='gpt-6.1', reasoning='medium',
        approval='never', sandbox='danger-full-access', skills=[], primary_store=None)
    fingerprint = onboarding_release.seal(base, profile)
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'onboarding_target.py').write_bytes(b'Updated runtime.')
    return base, fingerprint, source, profile


def test_runtime_successor_preserves_original_code_and_context_bytes(tmp_path):
    base, original, source, _ = fixture(tmp_path)
    output = tmp_path / 'successor'
    result = build(base, original, source, ('onboarding_target.py',), output)
    assert result['base_release_digest'] == original
    assert selected(output, result['runtime_digest'], base, original, uid=os.geteuid()) == output
    assert selected(base, None, base, original, uid=os.geteuid()) == base
    assert (base / 'clusterctl/onboarding_target.py').read_bytes() == b'Original runtime.'
    assert (output / 'clusterctl/onboarding_target.py').read_bytes() == b'Updated runtime.'


def telegram_fixture(tmp_path, monkeypatch):
    from clusterctl import onboarding_telegram as telegram
    import hashlib
    base, _, source, profile = fixture(tmp_path)
    old, new = b'original fixture consumer', b'qualified fixture consumer'
    monkeypatch.setattr(telegram, 'PREVIOUS_BINARY', hashlib.sha256(old).hexdigest())
    monkeypatch.setattr(telegram, 'BINARY', hashlib.sha256(new).hexdigest())
    (base / 'telegram/telecodex').write_bytes(old)
    (base / 'telegram/telecodex').chmod(0o755)
    previous = dict(commit=telegram.PREVIOUS_COMMIT, archive_sha256=telegram.PREVIOUS_ARCHIVE,
                    binary_sha256=telegram.PREVIOUS_BINARY, rust='1.95.0', features='--no-default-features')
    (base / 'telegram/artifact.json').write_text(json.dumps(previous))
    (base / 'telegram/artifact.json').chmod(0o644)
    (base / 'release.json').unlink()
    fingerprint = onboarding_release.seal(base, profile)
    candidate = tmp_path / 'qualified-telegram'
    candidate.mkdir(mode=0o755)
    (candidate / 'telecodex').write_bytes(new)
    (candidate / 'telecodex').chmod(0o755)
    (candidate / 'artifact.json').write_text(json.dumps(dict(commit=telegram.COMMIT,
        archive_sha256=telegram.ARCHIVE, binary_sha256=telegram.BINARY,
        rust_toolchain='1.95.0', features='--no-default-features')))
    (candidate / 'artifact.json').chmod(0o644)
    return base, fingerprint, source, profile, candidate


@pytest.mark.parametrize('retained', [False, True])
def test_qualified_telegram_successor_changes_only_explicit_software(tmp_path, monkeypatch, retained):
    from clusterctl import onboarding_telegram as telegram
    base, original, source, _, candidate = telegram_fixture(tmp_path, monkeypatch)
    expected_commit = telegram.COMMIT
    if retained:
        # An unrelated SDK successor can retain the already-qualified consumer.
        value = json.loads((candidate / 'artifact.json').read_bytes())
        monkeypatch.setattr(telegram, 'RETAINED_CURRENT_BINARY', value['binary_sha256'])
        value.update(commit=telegram.RETAINED_CURRENT_COMMIT,
            archive_sha256=telegram.RETAINED_CURRENT_ARCHIVE)
        (candidate / 'artifact.json').write_text(json.dumps(value))
        expected_commit = telegram.RETAINED_CURRENT_COMMIT
    output = tmp_path / 'telegram-successor'
    result = build(base, original, source, ('onboarding_target.py',), output, telegram=candidate)
    verify(output, result['runtime_digest'], base, original, uid=os.geteuid())
    assert telegram.artifact(output, uid=os.geteuid())['commit'] == expected_commit
    assert telegram.artifact(base, uid=os.geteuid())['commit'] == telegram.PREVIOUS_COMMIT
    for name in ('inheritance.md', 'hmk/scripts/memoryctl.py', 'sdk/pinned.whl'):
        assert (output / name).read_bytes() == (base / name).read_bytes()
    marker = json.loads((output / 'runtime-successor.json').read_text())
    assert marker['schema'] == 'cluster-onboarding-runtime-successor/v3'
    assert 'previous_telegram_digest' in marker and 'sdk_digest' not in marker


def test_telegram_successor_refuses_resealed_unqualified_binary_and_extra_assets(tmp_path, monkeypatch):
    base, original, source, profile, candidate = telegram_fixture(tmp_path, monkeypatch)
    output = tmp_path / 'telegram-successor'
    build(base, original, source, ('onboarding_target.py',), output, telegram=candidate)
    (output / 'release.json').unlink()
    (output / 'telegram/telecodex').write_bytes(b'unqualified replacement')
    replacement = onboarding_release.seal(output, profile)
    with pytest.raises(OnboardingError, match='qualified_telegram_binary_required'):
        verify(output, replacement, base, original, uid=os.geteuid())
    (output / 'release.json').unlink()
    (output / 'telegram/telecodex').write_bytes((candidate / 'telecodex').read_bytes())
    (output / 'sdk/pinned.whl').write_bytes(b'unqualified SDK replacement')
    replacement = onboarding_release.seal(output, profile)
    with pytest.raises(OnboardingError, match='original_onboarding_context_preserved'):
        verify(output, replacement, base, original, uid=os.geteuid())


def test_telegram_selection_does_not_select_a_new_matrix_runtime(tmp_path, monkeypatch):
    from pathlib import Path
    from clusterctl.onboarding_host import HostBackend, HostConfig
    from tests.test_onboarding import plan
    base, original, source, _, candidate = telegram_fixture(tmp_path, monkeypatch)
    output = tmp_path / 'telegram-successor'
    result = build(base, original, source, ('onboarding_target.py',), output, telegram=candidate)
    value = dict(schema='cluster-onboarding-host/v1', native_image='3'*64, browser_image='4'*64,
        release_digest=original, pool='daimon-cluster', profile='daimon-agent', concurrency=1,
        code=str(base), telegram_code=str(output), telegram_digest=result['runtime_digest'])
    for key in ('jobs', 'grants', 'inputs', 'views', 'progress'):
        directory = tmp_path / key
        directory.mkdir(mode=0o700)
        value[key] = str(directory)
    config = tmp_path / 'host.json'
    being_seed._write(config, value)
    loaded = HostConfig.load(config)
    backend = HostBackend(loaded)
    body_plan = {**plan(), 'release_digest': original}
    guest, args, mounts = backend._telegram_paths(body_plan, Path('/original'))
    assert guest.parent.name == 'daimon-onboarding-telegram' and guest.name == result['runtime_digest']
    assert args[-1] == result['runtime_digest'] and next(iter(mounts.values()))['readonly'] == 'true'
    assert backend._runtime_selection(body_plan) == (None, None)
    assert backend._runtime_paths(body_plan, Path('/original')) == (Path('/original'), [], {})
    for missing in ('telegram_code', 'telegram_digest'):
        being_seed._write(config, {k: v for k, v in value.items() if k != missing})
        with pytest.raises(OnboardingError):
            HostConfig.load(config)


@pytest.mark.parametrize('asset', ['inheritance.md', 'hmk/scripts/memoryctl.py',
    'sdk/pinned.whl', 'telegram/telecodex'])
def test_even_resealed_successor_cannot_change_approved_context_or_dependencies(tmp_path, asset):
    base, original, source, profile = fixture(tmp_path)
    output = tmp_path / 'successor'
    build(base, original, source, ('onboarding_target.py',), output)
    (output / 'release.json').unlink()
    (output / asset).write_bytes(b'Unapproved replacement.')
    replacement = onboarding_release.seal(output, profile)
    with pytest.raises(OnboardingError, match='original_onboarding_context_preserved'):
        verify(output, replacement, base, original, uid=os.geteuid())


def test_successor_requires_matching_profile_and_explicit_selection(tmp_path):
    base, original, source, profile = fixture(tmp_path)
    output = tmp_path / 'successor'
    build(base, original, source, ('onboarding_target.py',), output)
    with pytest.raises(OnboardingError, match='qualified_onboarding_runtime_required'):
        selected(output, None, base, original, uid=os.geteuid())
    (output / 'release.json').unlink()
    replacement = onboarding_release.seal(output, {**profile, 'model': 'another-model'})
    with pytest.raises(OnboardingError, match='compatible_onboarding_runtime_successor_required'):
        verify(output, replacement, base, original, uid=os.geteuid())


def test_builder_refuses_base_descendant_and_non_module_input_before_writes(tmp_path):
    base, original, source, _ = fixture(tmp_path)
    for output, names in [(base / 'successor', ('onboarding_target.py',)),
                          (tmp_path / 'successor', ('../private.txt',))]:
        with pytest.raises(OnboardingError):
            build(base, original, source, names, output)
        assert not output.exists()
    onboarding_release.verify(base, original, uid=os.geteuid())


@pytest.mark.parametrize('missing', ['runtime_code', 'runtime_digest'])
def test_host_configuration_requires_both_qualified_runtime_coordinates(tmp_path, missing):
    from clusterctl.onboarding_host import HostConfig
    base, original, source, _ = fixture(tmp_path)
    output = tmp_path / 'successor'
    result = build(base, original, source, ('onboarding_target.py',), output)
    value = dict(schema='cluster-onboarding-host/v1', native_image='3' * 64, browser_image='4' * 64,
        release_digest=original, pool='daimon-cluster', profile='daimon-agent', concurrency=1,
        code=str(base), runtime_code=str(output), runtime_digest=result['runtime_digest'])
    for key in ('jobs', 'grants', 'inputs', 'views', 'progress'):
        directory = tmp_path / key
        directory.mkdir(mode=0o700)
        value[key] = str(directory)
    config = tmp_path / 'host.json'
    being_seed._write(config, value)
    loaded = HostConfig.load(config)
    assert loaded.runtime_code == output and loaded.release_digest == original
    being_seed._write(config, {key: item for key, item in value.items() if key != missing})
    with pytest.raises(OnboardingError, match='invalid_onboarding_host_configuration'):
        HostConfig.load(config)


def test_per_being_runtime_selection_preserves_an_existing_body_generation(tmp_path):
    from pathlib import Path
    from clusterctl.onboarding_host import HostConfig, HostBackend
    from tests.test_onboarding import plan
    base, original, source, _ = fixture(tmp_path)
    old = tmp_path / 'already-hosted-code'
    first = build(base, original, source, ('onboarding_target.py',), old)
    (source / 'onboarding_target.py').write_bytes(b'Existing-Root compatible successor.')
    new = tmp_path / 'new-body-code'
    second = build(base, original, source, ('onboarding_target.py',), new)
    value = dict(schema='cluster-onboarding-host/v1', native_image='3' * 64, browser_image='4' * 64,
        release_digest=original, pool='daimon-cluster', profile='daimon-agent', concurrency=1,
        code=str(base), runtime_code=str(new), runtime_digest=second['runtime_digest'],
        runtime_by_name={'eko': dict(runtime_code=str(old), runtime_digest=first['runtime_digest'])})
    for key in ('jobs', 'grants', 'inputs', 'views', 'progress'):
        directory = tmp_path / key
        directory.mkdir(mode=0o700)
        value[key] = str(directory)
    config = tmp_path / 'host.json'
    being_seed._write(config, value)
    loaded = HostConfig.load(config)
    backend = HostBackend(loaded)
    for name, selected_code, selected_digest in (('eko', old, first['runtime_digest']),
            ('oliva', new, second['runtime_digest'])):
        body_plan = {**plan(name=name), 'release_digest': original}
        assert backend._runtime_selection(body_plan) == (selected_code, selected_digest)
        path, argv, mounts = backend._runtime_paths(body_plan, Path('/original-code'))
        assert path.name == selected_digest and argv[-1] == selected_digest
        assert next(iter(mounts.values()))['source'] == str(selected_code)
        assert backend._sdk_successor(body_plan) is False
    assert (old / 'clusterctl/onboarding_target.py').read_bytes() == b'Updated runtime.'
    for invalid in ({'eko': {'runtime_code': str(new)}}, {'../eko': value['runtime_by_name']['eko']},
            {'eko': {**value['runtime_by_name']['eko'], 'runtime_digest': '0' * 64}}):
        being_seed._write(config, {**value, 'runtime_by_name': invalid})
        with pytest.raises(OnboardingError):
            HostConfig.load(config)


def test_host_attaches_runtime_once_before_v8_observation_and_preserves_foreign_mount(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from clusterctl.onboarding_host import HostBackend
    from tests.test_onboarding_host import configured
    base, original, source, _ = fixture(tmp_path)
    output = tmp_path / 'successor'
    result = build(base, original, source, ('onboarding_target.py',), output)
    config, plan, run, _ = configured(tmp_path)
    plan = {**plan, 'release_digest': original}
    config = replace(config, code=base, release_digest=original, runtime_code=output,
                     runtime_digest=result['runtime_digest'], views=tmp_path / 'views')
    being_seed._write(config.grants / 'eko.json', dict(schema='cluster-onboarding-host-grant/v1', plan=plan, revoked=False))
    config.views.mkdir(mode=0o700)
    backend = HostBackend(config, run=run)
    backend.execute(plan, 'environment', 'unused')
    run.instances[0]['expanded_devices']['onboarding-matrix-public'] = backend._matrix_mount(plan)
    root = tmp_path / 'custody'
    from clusterctl.onboarding import digest
    (root / digest(plan)).mkdir(mode=0o700, parents=True)
    being_seed._write(root / digest(plan) / 'genesis.json', {})
    monkeypatch.setattr('clusterctl.onboarding_mounts.prepare_matrix_public', lambda *args: None)
    actions = []
    def observe(_plan, action):
        actions.append(action)
        assert 'runtime-' + result['runtime_digest'][:55] in run.instances[0]['expanded_devices']
        return dict(phase='v8')
    monkeypatch.setattr(backend, '_matrix_command', observe)
    run.calls.clear()
    backend._matrix_execute(plan, SimpleNamespace(root=root))
    backend._matrix_execute(plan, SimpleNamespace(root=root))
    assert actions == ['observe', 'observe'] and len(run.calls) == 1
    device = run.instances[0]['expanded_devices']['runtime-' + result['runtime_digest'][:55]]
    assert device['readonly'] == 'true' and device['source'] == str(output)
    device['source'] = '/foreign/runtime'
    with pytest.raises(OnboardingError, match='foreign_receiving_mount_preserved'):
        backend._matrix_execute(plan, SimpleNamespace(root=root))
    assert len(run.calls) == 1 and len(actions) == 2


def test_service_launches_selected_runtime_while_retaining_original_code_argument(tmp_path):
    from clusterctl.onboarding_service import command
    base, original, source, _ = fixture(tmp_path)
    (source / 'onboarding_target.py').write_text(
        'import json,sys\ndef main():\n print(json.dumps(sys.argv[1:]));return 0\n')
    output = tmp_path / 'successor'
    result = build(base, original, source, ('onboarding_target.py',), output)
    argv = command(base, receive_only=True, runtime_code=output, runtime_digest=result['runtime_digest'])
    launched = subprocess.run([sys.executable, *argv[1:]], capture_output=True, check=True, text=True)
    options = json.loads(launched.stdout)
    assert options[0] == 'admitted-serve'
    assert options[options.index('--code') + 1] == str(base)
    assert options[options.index('--runtime-code') + 1] == str(output)
    assert options[options.index('--runtime-digest') + 1] == result['runtime_digest']
    assert not list(output.rglob('__pycache__'))
    with pytest.raises(OnboardingError, match='qualified_onboarding_runtime_required'):
        command(base, receive_only=True, runtime_code=output)


def test_target_reexec_preserves_selected_runtime_and_uses_qualified_runtime_sdk(tmp_path, monkeypatch):
    from clusterctl import onboarding_code_successor, onboarding_target
    base, original, source, _ = fixture(tmp_path)
    output = tmp_path / 'successor'
    result = build(base, original, source, ('onboarding_target.py',), output)
    plan_path = tmp_path / 'plan.json'
    from tests.test_onboarding import plan
    being_seed._write(plan_path, {**plan(), 'release_digest': original})
    venv = tmp_path / 'private-venv'
    sdk_codes, execs = [], []
    actual = onboarding_code_successor.selection
    def owned_selection(*args, **kwargs):
        return actual(*args, uid=os.geteuid())
    def sdk(_home, code):
        sdk_codes.append(code)
        return venv
    def execute(executable, argv):
        execs.append((executable, argv))
        raise RuntimeError('captured SDK reexec')
    monkeypatch.setattr(onboarding_code_successor, 'selection', owned_selection)
    parameters = onboarding_code_successor.sdk_parameters
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters',
        lambda code, **kw: parameters(code, uid=os.geteuid()))
    monkeypatch.setattr(onboarding_target.onboarding_sdk, 'observe', sdk)
    monkeypatch.setattr(onboarding_target.os, 'execv', execute)
    args = ['observe', '--home', str(tmp_path / 'home'), '--code', str(base), '--plan', str(plan_path),
        '--genesis', str(tmp_path / 'genesis.json'), '--runtime-code', str(output),
        '--runtime-digest', result['runtime_digest']]
    assert onboarding_target.main(args) == 1
    assert sdk_codes == [output] and len(execs) == 1
    executable, argv = execs[0]
    assert executable == venv / 'bin/python'
    assert argv[5] == str(output) and argv[6:] == args
    assert '--runtime-digest' in argv


def sdk_generations(tmp_path):
    import shutil
    import zipfile
    from clusterctl import onboarding_sdk
    from tests.test_onboarding_sdk import fixture as sdk_fixture
    from tools.build_onboarding_sdk import seal
    base, _, source, profile = fixture(tmp_path)
    (base / 'release.json').unlink()
    (base / 'sdk/pinned.whl').unlink()
    sdk_root = tmp_path / 'replacement'
    sdk_root.mkdir()
    current, _, home = sdk_fixture(sdk_root)
    shutil.copytree(current / 'sdk', base / 'sdk', dirs_exist_ok=True)
    previous = json.loads((base / 'sdk/sdk.json').read_bytes())
    previous['matrix_commit'] = onboarding_sdk.PREVIOUS_MATRIX_COMMIT
    (base / 'sdk/sdk.json').write_text(json.dumps(previous))
    fingerprint = onboarding_release.seal(base, profile)
    wheel = next((current / 'sdk/wheels').iterdir())
    with zipfile.ZipFile(wheel) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    entries['daimon_matrix/__init__.py'] = b'# Qualified replacement fixture.\n'
    with zipfile.ZipFile(wheel, 'w') as archive:
        for name, raw in entries.items():
            archive.writestr(name, raw)
    seal(current / 'sdk')
    return base, fingerprint, source, profile, current / 'sdk', home


def test_explicit_sdk_successor_installs_new_generation_without_touching_previous(tmp_path):
    from clusterctl import onboarding_sdk
    from clusterctl.onboarding import digest
    base, original, source, _, sdk, home = sdk_generations(tmp_path)
    old = onboarding_sdk.install(home, base, original, code_uid=os.geteuid(),
        matrix_commit=onboarding_sdk.PREVIOUS_MATRIX_COMMIT)
    before = {p.relative_to(old.parent).as_posix(): p.read_bytes()
        for p in old.parent.rglob('*') if p.is_file() and not p.is_symlink()}
    original_files = {p.relative_to(base).as_posix(): p.read_bytes() for p in base.rglob('*') if p.is_file()}
    output = tmp_path / 'sdk-successor'
    result = build(base, original, source, ('onboarding_target.py',), output, sdk=sdk)
    marker = json.loads((output / 'runtime-successor.json').read_bytes())
    assert marker['schema'] == 'cluster-onboarding-runtime-successor/v2'
    assert marker['previous_sdk_digest'] == digest(json.loads((base / 'sdk/sdk.json').read_bytes()))
    installed = onboarding_sdk.install(home, output, result['runtime_digest'], code_uid=os.geteuid())
    assert installed != old
    assert onboarding_sdk.observe(home, output, code_uid=os.geteuid()) == installed
    assert onboarding_sdk.install(home, output, result['runtime_digest'], code_uid=os.geteuid()) == installed
    assert before == {p.relative_to(old.parent).as_posix(): p.read_bytes()
        for p in old.parent.rglob('*') if p.is_file() and not p.is_symlink()}
    assert original_files == {p.relative_to(base).as_posix(): p.read_bytes() for p in base.rglob('*') if p.is_file()}
    assert not list(home.rglob('custody.json'))


@pytest.mark.parametrize('asset', ['inheritance.md', 'hmk/scripts/memoryctl.py',
    'telegram/telecodex', 'sdk/sdk.json', 'runtime-successor.json'])
def test_sdk_successor_rejects_resealed_context_or_marker_changes(tmp_path, asset):
    base, original, source, profile, sdk, _ = sdk_generations(tmp_path)
    output = tmp_path / 'sdk-successor'
    build(base, original, source, ('onboarding_target.py',), output, sdk=sdk)
    (output / 'release.json').unlink()
    if asset.endswith('.json'):
        value = json.loads((output / asset).read_bytes())
        if asset == 'runtime-successor.json':
            value['previous_sdk_digest'] = '0' * 64
        else:
            value['matrix_commit'] = '0' * 40
        (output / asset).write_text(json.dumps(value))
    else:
        (output / asset).write_bytes(b'Unapproved replacement.')
    replacement = onboarding_release.seal(output, profile)
    with pytest.raises(OnboardingError):
        verify(output, replacement, base, original, uid=os.geteuid())


def test_target_sdk_observation_and_retry_do_not_load_body_custody(tmp_path, monkeypatch, capsys):
    from clusterctl import onboarding_code_successor, onboarding_sdk, onboarding_target
    from tests.test_onboarding import plan
    base, original, source, _, sdk, home = sdk_generations(tmp_path)
    output = tmp_path / 'sdk-successor'
    result = build(base, original, source, ('onboarding_target.py',), output, sdk=sdk)
    plan_path = tmp_path / 'plan.json'
    being_seed._write(plan_path, {**plan(), 'release_digest': original})
    selection = onboarding_code_successor.selection
    install, observe = onboarding_sdk.install, onboarding_sdk.observe
    monkeypatch.setattr(onboarding_code_successor, 'selection',
        lambda *a, **kw: selection(*a, uid=os.geteuid()))
    parameters = onboarding_code_successor.sdk_parameters
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters',
        lambda code, **kw: parameters(code, uid=os.geteuid()))
    monkeypatch.setattr(onboarding_sdk, 'install',
        lambda *a, **kw: install(*a, code_uid=os.geteuid()))
    monkeypatch.setattr(onboarding_sdk, 'observe',
        lambda *a, **kw: observe(*a, code_uid=os.geteuid()))
    def no_custody(*args, **kwargs):
        raise AssertionError('dependency preparation must not load a Body')
    monkeypatch.setattr(onboarding_target, 'Target', no_custody)
    common = ['--home', str(home), '--code', str(base), '--plan', str(plan_path),
        '--genesis', str(tmp_path / 'absent-genesis.json'), '--runtime-code', str(output),
        '--runtime-digest', result['runtime_digest']]
    assert onboarding_target.main(['sdk-observe', *common]) == 0
    assert json.loads(capsys.readouterr().out)['ready'] is False
    assert not (home / '.local').exists()
    for action in ['sdk-prepare', 'sdk-observe', 'sdk-prepare']:
        assert onboarding_target.main([action, *common]) == 0
        assert json.loads(capsys.readouterr().out)['ready'] is True
    assert not list(home.rglob('custody.json'))


def test_host_reconciles_missing_sdk_before_reading_existing_body(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from clusterctl.onboarding_host import HostBackend
    from tests.test_onboarding_host import configured
    base, original, source, _, sdk, _ = sdk_generations(tmp_path)
    output = tmp_path / 'sdk-successor'
    result = build(base, original, source, ('onboarding_target.py',), output, sdk=sdk)
    host = tmp_path / 'host'
    host.mkdir()
    config, plan, run, _ = configured(host)
    config = replace(config, code=base, runtime_code=output, runtime_digest=result['runtime_digest'],
        release_digest=original, views=host / 'views', custody=host / 'custody', custody_grants=host / 'custody-grants')
    plan = {**plan, 'release_digest': original}
    being_seed._write(config.grants / 'eko.json', dict(schema='cluster-onboarding-host-grant/v1', plan=plan, revoked=False))
    backend = HostBackend(config, run=run)
    monkeypatch.setattr(backend, '_consented', lambda *a, **kw: True)
    monkeypatch.setattr(backend, '_decision', lambda p: dict(matrix_identity_mode='first'))
    monkeypatch.setattr('clusterctl.onboarding_host.FirstCustody', lambda *a: SimpleNamespace(
        authorize=lambda p: True, observe=lambda p: dict(backup_restore_verified=True)))
    monkeypatch.setattr(backend, '_guest_paths', lambda p: (None, base, {}))
    monkeypatch.setattr(backend, '_mounted', lambda *a: True)
    ready = []
    actions = []
    def sdk_observe(p, action):
        actions.append(action)
        return dict(ready=bool(ready))
    def matrix_observe(p, action):
        actions.append('matrix-' + action)
        return dict(phase='v8')
    monkeypatch.setattr(backend, '_target_call', sdk_observe)
    monkeypatch.setattr(backend, '_matrix_command', matrix_observe)
    observed = backend.observe(plan, 'matrix', 'same-operation')
    assert observed.state == 'absent' and observed.safe_to_execute
    assert actions == ['sdk-observe']
    ready.append(True)
    backend.observe(plan, 'matrix', 'same-operation')
    assert actions == ['sdk-observe', 'sdk-observe', 'matrix-observe']
