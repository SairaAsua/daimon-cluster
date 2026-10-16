"""Typed substrate commands preserve foreign bodies and reconcile partial creation."""
import copy
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import JobStore, OnboardingError, digest
from clusterctl.onboarding_host import HostBackend, HostConfig
from tests.test_onboarding import plan


def test_only_typed_context_install_has_the_large_archive_deadline(monkeypatch):
    from clusterctl import onboarding_host
    calls = []

    def run(argv, **kwargs):
        calls.append(kwargs['timeout'])
        return SimpleNamespace(returncode=0, stdout='{}')

    monkeypatch.setattr(onboarding_host.subprocess, 'run', run)
    HostBackend._run(['exec', 'dm-fixture', '--', 'python3', 'execute', 'context', '--home', '/home/agent'])
    HostBackend._run(['exec', 'dm-fixture', '--', 'python3', 'execute', 'memory', '--home', '/home/agent'])
    HostBackend._run(['list', '--format=json'])
    assert calls == [7200, 1800, 1800]


class IncusFixture:
    def __init__(self):
        self.instances = []
        self.volumes = []
        self.calls = []
        self.fail_after = None

    def __call__(self, argv):
        if argv[0] == "list":
            return json.dumps(self.instances)
        if argv[:3] == ["storage", "volume", "list"]:
            return json.dumps(self.volumes)
        if argv[0] == "query":
            return json.dumps(next(v for v in self.volumes if argv[1].endswith("/" + v["name"])))
        self.calls.append(argv)
        if argv[0] == "init":
            self.instances.append(dict(name=argv[2], status="Stopped", config={
                "volatile.base_image": argv[1], "user.dm.onboarding-plan": argv[-1].split("=", 1)[1]},
                expanded_devices={"root": dict(type="disk", path="/", pool=argv[6], size="8GiB")}))
        elif argv[:3] == ["storage", "volume", "create"]:
            self.volumes.append(dict(name=argv[4], type="custom", config={
                "size": "22GiB", "user.dm.onboarding-plan": argv[6].split("=", 1)[1]}))
        elif argv[:3] == ["config", "device", "add"]:
            if not 1 <= len(argv[4]) <= 63:
                raise OnboardingError("incus_device_name_limit")
            row = next(row for row in self.instances if row["name"] == argv[3])
            row["expanded_devices"][argv[4]] = dict(type="disk", **dict(item.split("=", 1) for item in argv[6:]))
        elif argv[0] == "start":
            next(row for row in self.instances if row["name"] == argv[1])["status"] = "Running"
        else:
            raise AssertionError("unexpected command")
        if len(self.calls) == self.fail_after:
            raise RuntimeError("transport disconnected after effect")
        return ""


def configured(tmp_path):
    for name in ("jobs", "grants"):
        (tmp_path / name).mkdir(mode=0o700)
    config = HostConfig(tmp_path / "jobs", tmp_path / "grants", "3" * 64, "4" * 64,
                        "2" * 64, "daimon-cluster", "daimon-agent", 2)
    value = plan()
    being_seed._write(config.grants / "eko.json", dict(schema="cluster-onboarding-host-grant/v1",
                                                      plan=value, revoked=False))
    run = IncusFixture()
    return config, value, run, HostBackend(config, run=run)


@pytest.mark.parametrize('action', ['native-install', 'native-observe', 'probe', 'prepare', 'install'])
def test_native_harness_commands_do_not_require_bot_connections(tmp_path, action):
    from clusterctl.onboarding import Observation
    _, value, _, backend = configured(tmp_path)
    backend._environment = lambda p: Observation('complete')
    mounts = {'qualified-code': {'source': '/public/code'}}
    backend._guest_paths = lambda p: (Path('/guest'), Path('/guest/code'), dict(mounts))
    backend._telegram_paths = lambda p, base: (base, [], {})
    observed = []
    backend._mounted = lambda p, selected: observed.append(selected) or True
    calls = []
    def dispatch(p, argv):
        calls.append(argv)
        return json.dumps({'plan_digest': digest(p)})
    backend._dispatch = dispatch
    # No views or private connection data exists for the native-only phase.
    if action in {'prepare', 'install'}:
        with pytest.raises(OnboardingError, match='receiving_code_configuration_required'):
            backend._telegram_command(value, action)
        assert calls == []
        return
    assert backend._telegram_command(value, action) == {'plan_digest': digest(value)}
    assert observed == [mounts]
    assert ('--user' in calls[0]) == (action == 'probe')


def test_receiving_base_keeps_original_release_without_requiring_participant_archive(tmp_path):
    from tests.test_onboarding_code_successor import fixture as code_fixture
    (tmp_path/'code-fixture').mkdir()
    (tmp_path/'host-fixture').mkdir()
    base,checksum,_,_=code_fixture(tmp_path/'code-fixture')
    config,value,run,_=configured(tmp_path/'host-fixture')
    value={**value,'release_digest':checksum}
    config=replace(config,code=base,release_digest=checksum,
        inputs=tmp_path/'missing-inputs',views=tmp_path/'missing-views')
    backend=HostBackend(config,run=run)
    original=copy.deepcopy(value)
    assert backend._receiving_base(value)==Path('/opt/daimon-onboarding')/checksum
    assert value==original and not run.calls
    # Initial onboarding still requires and verifies the participant input.
    with pytest.raises(FileNotFoundError):
        backend._guest_paths(value)
    assert not run.calls
    with pytest.raises(OnboardingError,match='configuration_required'):
        backend._receiving_base({**value,'release_digest':'0'*64})
    (base/'inheritance.md').write_text('Unqualified replacement source context.\n')
    with pytest.raises(OnboardingError,match='release_digest_mismatch'):
        backend._receiving_base(value)
    assert value==original and not run.calls


@pytest.mark.parametrize('optional', [{}, {'group': {}}, {'receiving_controller': {}},
                                     {'group': {}, 'receiving_controller': {}}])
def test_matrix_observation_wrapper_retains_supported_selection_metadata(tmp_path, optional):
    """Wrapper seam; Target tests authenticate these receiving observations."""
    _,value,_,backend=configured(tmp_path)
    observed=dict(phase='v8',request={},receipt={},**optional)
    backend._target_call=lambda *_args,**_kwargs:observed
    assert backend._matrix_command(value,'observe') is observed


@pytest.mark.parametrize('change', ['unknown-field','missing-receipt','invalid-phase'])
def test_matrix_observation_wrapper_still_rejects_unrecognized_contract(tmp_path, change):
    _,value,_,backend=configured(tmp_path)
    observed=dict(phase='v8',request={},receipt={})
    if change=='unknown-field':
        observed['unexpected']={}
    elif change=='missing-receipt':
        del observed['receipt']
    else:
        observed['phase']='controller-ready'
    backend._target_call=lambda *_args,**_kwargs:observed
    with pytest.raises(OnboardingError,match='invalid_onboarding_observation'):
        backend._matrix_command(value,'observe')


def test_exact_receiving_mount_can_keep_its_existing_operational_alias(tmp_path):
    _, value, run, backend = configured(tmp_path)
    desired = {"type": "disk", "source": "/qualified/source", "path": "/opt/qualified-code",
               "readonly": "true", "shift": "true"}
    run.instances.append({"name": "dm-eko", "expanded_devices": {"existing-alias": desired.copy()}})
    expected = {"generated-name": desired}
    assert backend._mounted(value, expected)
    for field in desired:
        run.instances[0]["expanded_devices"]["existing-alias"][field] = "different"
        assert not backend._mounted(value, expected)
        run.instances[0]["expanded_devices"]["existing-alias"][field] = desired[field]
    # An occupied canonical name with different contents is still a conflict.
    run.instances[0]["expanded_devices"]["generated-name"] = {**desired, "source": "/foreign"}
    with pytest.raises(OnboardingError, match="foreign_receiving_mount_preserved"):
        backend._mounted(value, expected)
    assert not run.calls


@pytest.mark.parametrize("failed_command", [1, 2, 3, 4])
def test_each_partial_effect_reconciles_without_recreating(tmp_path, failed_command):
    config, value, run, backend = configured(tmp_path)
    store = JobStore(config.jobs)
    store.submit(value, backend)
    run.fail_after = failed_command
    assert store.tick("eko", backend)["active"] is False
    run.fail_after = None
    assert store.tick("eko", backend)["completed_steps"] == ["environment"]
    assert len(run.calls) == 4
    assert backend.observe(value, "environment", "unused").facts == {
        "verified": True, "root_gib": 8, "home_gib": 22}


@pytest.mark.parametrize("foreign", ["body", "volume", "device"])
def test_foreign_state_is_not_mutated(tmp_path, foreign):
    config, value, run, backend = configured(tmp_path)
    if foreign == "body":
        run.instances.append(dict(name="dm-eko", config={}, expanded_devices={}))
    elif foreign == "volume":
        run.volumes.append(dict(name="dm-eko-home", type="custom", config={"size": "22GiB"}))
    else:
        backend.execute(value, "environment", "unused")
        run.instances[0]["expanded_devices"]["home"]["source"] = "other-being-home"
        run.calls.clear()
    before = copy.deepcopy((run.instances, run.volumes))
    assert backend.observe(value, "environment", "unused").state == "conflict"
    with pytest.raises(OnboardingError):
        backend.execute(value, "environment", "unused")
    assert (run.instances, run.volumes) == before and run.calls == []


def test_intake_label_and_revoked_or_different_grant_cannot_authorize(tmp_path):
    config, value, run, backend = configured(tmp_path)
    assert backend.authorize(value, digest(value))
    assert not backend.authorize(plan(owner="ani"), digest(plan(owner="ani")))
    assert not backend.authorize(value, "5" * 64)
    grant = config.grants / "eko.json"
    being_seed._write(grant, dict(schema="cluster-onboarding-host-grant/v1", plan=value, revoked=True))
    assert not backend.authorize(value, digest(value))
    with pytest.raises(OnboardingError, match="host_authorization_required"):
        backend.execute(value, "environment", "unused")
    assert not run.calls


def test_revocation_during_creation_stops_before_the_next_resource_effect(tmp_path):
    config, value, run, backend = configured(tmp_path)
    original = backend.run
    def revoke_after_init(argv):
        result = original(argv)
        if argv[0] == "init":
            being_seed._write(config.grants / "eko.json", dict(schema="cluster-onboarding-host-grant/v1",
                                                              plan=value, revoked=True))
        return result
    backend.run = revoke_after_init
    with pytest.raises(OnboardingError, match="host_authorization_required"):
        backend.execute(value, "environment", "unused")
    assert len(run.calls) == 1
    assert len(run.instances) == 1 and not run.volumes


def test_verified_v8_lifecycle_retry_never_reenters_credential_writer(tmp_path, monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace

    config, value, run, _ = configured(tmp_path)
    (tmp_path / 'views').mkdir(mode=0o700)
    config = replace(config, views=tmp_path / 'views')
    backend = HostBackend(config, run=run)
    backend.execute(value, 'environment', 'unused')
    run.instances[0]['expanded_devices']['onboarding-matrix-public'] = backend._matrix_mount(value)
    run.calls.clear()
    root = tmp_path / 'custody'
    (root / digest(value)).mkdir(mode=0o700, parents=True)
    being_seed._write(root / digest(value) / 'genesis.json', {})
    published, actions = [], []
    monkeypatch.setattr('clusterctl.onboarding_mounts.prepare_matrix_public',
                        lambda _views, _plan, documents: published.append(documents))
    def current(_plan, action):
        actions.append(action)
        assert action == 'observe'
        return dict(phase='v8')
    backend._matrix_command = current
    backend._matrix_execute(value, SimpleNamespace(root=root))
    assert actions == ['observe'] and published == [{'genesis.json': {}}]
    assert run.calls == []


def test_access_installs_only_dedicated_ssh_and_does_not_claim_provider(tmp_path, monkeypatch):
    from dataclasses import replace
    config, value, run, _ = configured(tmp_path)
    backend = HostBackend(replace(config, code=tmp_path, consent_state=tmp_path), run=run)
    monkeypatch.setattr(backend, '_ssh_key', lambda _plan: 'public fixture key')
    calls = []
    def ssh(_plan, action, key):
        calls.append(action)
        return dict(installed='install' in calls)
    monkeypatch.setattr(backend, '_ssh_command', ssh)
    assert backend.observe(value, 'access', 'unused').state == 'absent'
    backend.execute(value, 'access', 'unused')
    result = backend.observe(value, 'access', 'unused')
    assert result.state == 'waiting' and result.facts == {}
    assert calls == ['observe', 'install', 'observe']


def test_private_connections_are_owner_scoped_and_never_return_bot_token(tmp_path, monkeypatch):
    import os
    from dataclasses import replace
    config, value, run, _ = configured(tmp_path)
    backend = HostBackend(replace(config, consent_state=tmp_path, consent_uid=os.geteuid()), run=run)
    monkeypatch.setattr(backend, '_decision', lambda _plan: {'approved': True})
    directory = tmp_path / 'being-seeds/eko'
    directory.mkdir(mode=0o700, parents=True)
    record = dict(schema=being_seed.SCHEMA, name='eko', created_by=value['owner'])
    being_seed._write(directory / 'record.json', record)
    key = 'ssh-ed25519 ' + 'A' * 43
    being_seed._write(directory / 'connections.json', dict(ssh_public_key=key, telegram_bot_token='fixture secret'))
    assert backend._ssh_key(value) == key
    (directory / 'connections.json').chmod(0o644)
    with pytest.raises(OnboardingError, match='private_onboarding_connections_required'):
        backend._ssh_key(value)
    (directory / 'connections.json').chmod(0o600)
    being_seed._write(directory / 'record.json', {**record, 'created_by': 'other'})
    with pytest.raises(OnboardingError, match='account_authorization_required'):
        backend._ssh_key(value)


def candidate_call_fixture(tmp_path, monkeypatch):
    """Real sealed public code; fake Incus transport/authorization only."""
    import hashlib
    import os
    from dataclasses import replace
    from pathlib import Path
    from clusterctl import onboarding_code_successor, onboarding_sdk
    from tests.test_onboarding_code_successor import sdk_generations
    base, original, source, _, sdk, _ = sdk_generations(tmp_path)
    output = tmp_path / 'candidate'
    wheel = next((sdk / 'wheels').glob('*.whl'))
    result = onboarding_code_successor.build(base, original, source, ('onboarding_target.py',), output,
        sdk=sdk, matrix_commit=onboarding_sdk.MATRIX_COMMIT,
        matrix_wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest())
    config, value, run, _ = configured(tmp_path)
    config = replace(config, code=base, release_digest=original,
        custody=tmp_path / 'custody', custody_grants=tmp_path / 'custody-grants')
    value = {**value, 'release_digest': original}
    being_seed._write(config.grants / 'eko.json', dict(schema='cluster-onboarding-host-grant/v1',
        plan=value, revoked=False))
    calls = []
    def execute(argv, **kwargs):
        if argv[0] == 'exec':
            calls.append((argv, kwargs))
            return '{"observed": true}'
        return run(argv)
    backend = HostBackend(config, run=execute)
    monkeypatch.setattr(backend, '_ceremony', lambda _plan: SimpleNamespace(authorize=lambda _plan: True))
    guest_base = Path('/opt/daimon-onboarding') / original
    monkeypatch.setattr(backend, '_guest_paths', lambda _plan: (tmp_path, guest_base, {}))
    candidate = (output, result['runtime_digest'])
    guest = Path('/opt/daimon-onboarding-runtime') / candidate[1]
    run.instances.append(dict(name='dm-eko', expanded_devices={'retained-candidate': dict(
        type='disk', source=str(output), path=str(guest), readonly='true', shift='true')}))
    assert output.stat().st_uid == os.geteuid()
    return backend, value, run, candidate, calls


def test_host_probes_exact_mounted_candidate_without_selecting_it(tmp_path, monkeypatch):
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    config = backend.config
    original = {path: path.read_bytes() for path in candidate[0].rglob('*') if path.is_file()}
    monkeypatch.setattr(backend, '_runtime_selection', lambda _: pytest.fail('active selection used for candidate'))
    result = backend._target_call(value, 'admitted-running', candidate=candidate,
        observation_timeout_seconds=5, require_loaded=True)
    assert result == {'observed': True} and backend.config is config
    assert len(calls) == 1
    argv, options = calls[0]
    assert argv[:6] == ['exec', 'dm-eko', '--user', '1000', '--group', '1000']
    sdk = json.loads((candidate[0] / 'sdk/sdk.json').read_bytes())
    venv = Path('/home/agent/.local/share/daimon-matrix/sdk') / digest(sdk) / 'venv'
    entry = argv.index('--') + 1
    assert argv[entry:entry + 4] == [str(venv / 'bin/python'), '-B', '-I', '-S']
    assert str(venv.parent / 'runtime-imports') in argv
    assert argv[argv.index('--runtime-digest') + 1] == candidate[1]
    assert argv[argv.index('--runtime-code') + 1].endswith(candidate[1])
    assert '--require-loaded' in argv
    assert 0 < float(argv[argv.index('--observation-timeout-seconds') + 1]) <= 5
    assert 0 < options['timeout_seconds'] <= 5
    assert original == {path: path.read_bytes() for path in original}
    assert not list(tmp_path.rglob('custody.json'))


@pytest.mark.parametrize('action', ['sdk-prepare', 'sdk-observe'])
def test_host_sdk_preparation_keeps_its_system_interpreter(tmp_path, monkeypatch, action):
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    backend._target_call(value, action, candidate=candidate)
    argv = calls[0][0]
    assert argv[argv.index('--') + 1] == '/usr/bin/python3'
    assert not any('/venv/' in argument for argument in argv)


@pytest.mark.parametrize('change', ['missing-mount', 'writable-mount', 'other-source', 'changed-code',
                                  'wrong-digest', 'authority-action', 'public-profile'])
def test_host_candidate_refusal_precedes_owner_command(tmp_path, monkeypatch, change):
    backend, value, run, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    action, options = 'observe', {}
    mount = run.instances[0]['expanded_devices']['retained-candidate']
    if change == 'missing-mount':
        run.instances[0]['expanded_devices'].clear()
    elif change == 'writable-mount':
        mount['readonly'] = 'false'
    elif change == 'other-source':
        mount['source'] = '/different-source'
    elif change == 'changed-code':
        (candidate[0] / 'clusterctl/onboarding_target.py').write_bytes(b'changed')
    elif change == 'wrong-digest':
        candidate = (candidate[0], 'f' * 64)
    elif change == 'authority-action':
        action = 'activate'
    else:
        options['profile'] = {'unexpected': True}
    with pytest.raises(OnboardingError):
        backend._target_call(value, action, candidate=candidate, **options)
    assert not calls and not run.calls


@pytest.mark.parametrize('timeout', [0, -1, float('nan'), float('inf'), 61])
def test_host_observation_budget_rejects_invalid_values_before_transport(tmp_path, timeout):
    _, value, run, backend = configured(tmp_path)
    with pytest.raises(OnboardingError, match='deadline_required'):
        backend._target_call(value, 'admitted-running', observation_timeout_seconds=timeout)
    assert not run.calls


def test_host_rejects_late_observation_without_retry(tmp_path, monkeypatch):
    from clusterctl import onboarding_host
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    clock = [1_000_000_000]
    monkeypatch.setattr(onboarding_host.time, 'monotonic_ns', lambda: clock[0])
    execute = backend.run
    def late(argv, **kwargs):
        result = execute(argv, **kwargs)
        if argv[0] == 'exec':
            clock[0] += 6_000_000_000
        return result
    backend.run = late
    with pytest.raises(OnboardingError, match='deadline_expired'):
        backend._target_call(value, 'admitted-running', candidate=candidate, observation_timeout_seconds=5)
    assert len(calls) == 1


def test_host_deadline_exhausted_by_authorization_dispatches_nothing(tmp_path, monkeypatch):
    from clusterctl import onboarding_host
    _, value, run, backend = configured(tmp_path)
    clock = [1_000_000_000]
    monkeypatch.setattr(onboarding_host.time, 'monotonic_ns', lambda: clock[0])
    authorize = backend.authorize
    def late(*args):
        allowed = authorize(*args)
        clock[0] += 6_000_000_000
        return allowed
    monkeypatch.setattr(backend, 'authorize', late)
    with pytest.raises(OnboardingError, match='deadline_expired'):
        backend._dispatch(value, ['exec', 'dm-eko'], timeout_seconds=5, deadline_ns=6_000_000_000)
    assert not run.calls


def test_incus_observation_timeout_is_not_a_guest_exit_receipt(monkeypatch):
    import subprocess
    from clusterctl import onboarding_host
    def timeout(argv, **kwargs):
        assert kwargs['timeout'] == 3
        raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
    monkeypatch.setattr(onboarding_host.subprocess, 'run', timeout)
    with pytest.raises(OnboardingError, match='host_operation_failed'):
        HostBackend._run(['exec', 'dm-fixture'], timeout_seconds=3)


def test_candidate_mount_and_owner_observation_share_one_budget(tmp_path, monkeypatch):
    from clusterctl import onboarding_host
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    clock = [1_000_000_000]
    monkeypatch.setattr(onboarding_host.time, 'monotonic_ns', lambda: clock[0])
    execute, inspections = backend.run, []
    def mounted(argv, **kwargs):
        result = execute(argv, **kwargs)
        if argv[0] == 'list':
            inspections.append((argv, kwargs))
            clock[0] += 3_000_000_000
        elif argv[0] == 'storage':
            pytest.fail('volume inventory is unrelated to candidate mount inspection')
        return result
    backend.run = mounted
    backend._target_call(value, 'admitted-running', candidate=candidate, observation_timeout_seconds=5)
    assert len(inspections) == len(calls) == 1
    assert inspections[0][1]['timeout_seconds'] == 5
    assert calls[0][1]['timeout_seconds'] == 2
    argv = calls[0][0]
    assert float(argv[argv.index('--observation-timeout-seconds') + 1]) == 2


def test_slow_candidate_mount_inspection_never_starts_owner_command(tmp_path, monkeypatch):
    from clusterctl import onboarding_host
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    clock = [1_000_000_000]
    monkeypatch.setattr(onboarding_host.time, 'monotonic_ns', lambda: clock[0])
    execute, inspections = backend.run, []
    def late(argv, **kwargs):
        assert argv[0] == 'list'
        inspections.append(kwargs['timeout_seconds'])
        result = execute(argv, **kwargs)
        clock[0] += 6_000_000_000
        return result
    backend.run = late
    with pytest.raises(OnboardingError, match='deadline_expired'):
        backend._target_call(value, 'admitted-running', candidate=candidate, observation_timeout_seconds=5)
    assert inspections == [5] and not calls


@pytest.mark.parametrize('phase', ['freeze', 'stage', 'publish', 'initial-freeze', 'initial-service-freeze'])
def test_host_forwards_owner_bootstrap_only_as_guest_owner(tmp_path, monkeypatch, phase):
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    options = dict(candidate=candidate, bootstrap_timeout_seconds=5)
    initial = phase == 'initial-freeze'
    initial_service = phase == 'initial-service-freeze'
    if initial:
        phase = 'freeze'
        options['bootstrap_initial'] = True
    if initial_service:
        phase = 'freeze'
        options['bootstrap_initial_service'] = True
    if phase != 'freeze':
        options['bootstrap_request'] = {'operation_id': 'synthetic', 'plan_digest': digest(value)}
    if phase == 'publish':
        options['bootstrap_ready_sha256'] = 'a' * 64
    backend._target_call(value, 'receiving-bootstrap-' + phase, **options)
    argv, bounds = calls[0]
    assert argv[:6] == ['exec', 'dm-eko', '--user', '1000', '--group', '1000']
    assert argv[argv.index('--') + 1].endswith('/venv/bin/python')
    assert 0 < bounds['timeout_seconds'] <= 5
    assert '--bootstrap-timeout-seconds' in argv and '--observation-timeout-seconds' not in argv
    assert ('--bootstrap-initial' in argv) is initial
    assert ('--bootstrap-initial-service' in argv) is initial_service
    if phase != 'freeze':
        assert json.loads(argv[argv.index('--bootstrap-request-json') + 1]) == options['bootstrap_request']
    if phase == 'publish':
        assert argv[argv.index('--bootstrap-ready-sha256') + 1] == 'a' * 64


@pytest.mark.parametrize('action', ['bootstrap-inspect', 'bootstrap-validate', 'bootstrap-quiesce',
                                  'bootstrap-select', 'bootstrap-start', 'bootstrap-steady'])
def test_host_root_service_route_never_executes_private_sdk_or_installer(tmp_path, monkeypatch, action):
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    options = dict(candidate=candidate, timeout_seconds=5)
    if action == 'bootstrap-inspect':
        options['owner_observation'] = {'process': {'pid': 123}, 'admission_parent': {'pid': 122}}
    else:
        options['request'] = {'plan_digest': digest(value)}
    backend._guest_service_call(value, action, **options)
    argv, bounds = calls[0]
    assert argv[:6] == ['exec', 'dm-eko', '--user', '0', '--group', '0']
    assert '--' in argv and argv[argv.index('--') + 1] == '/usr/bin/python3'
    assert argv[argv.index('--action') + 1] == action
    assert 'clusterctl.onboarding_service' in ''.join(argv)
    assert not any('site-packages' in item or '/venv/' in item for item in argv)
    assert '--receive-only' not in argv and '--visibility-installation' not in argv
    assert 0 < bounds['timeout_seconds'] <= 5


@pytest.mark.parametrize('phase', ['freeze', 'stage', 'publish'])
def test_host_bootstrap_rejects_unqualified_or_incomplete_parameters_before_dispatch(tmp_path, phase):
    _, value, run, backend = configured(tmp_path)
    with pytest.raises(OnboardingError, match='invalid_receiving_bootstrap_request'):
        backend._target_call(value, 'receiving-bootstrap-' + phase, bootstrap_timeout_seconds=5)
    assert not run.calls


@pytest.mark.parametrize('action', ['observe', 'receiving-bootstrap-stage'])
@pytest.mark.parametrize('flag', ['bootstrap_initial', 'bootstrap_initial_service'])
def test_initial_freeze_flag_cannot_change_other_owner_actions(action, flag):
    backend = object.__new__(HostBackend)
    with pytest.raises(OnboardingError, match='invalid_receiving_bootstrap_request'):
        backend._target_call({}, action, **{flag: True})


def test_initial_freeze_variants_cannot_be_combined():
    backend = object.__new__(HostBackend)
    with pytest.raises(OnboardingError, match='invalid_receiving_bootstrap_request'):
        backend._target_call({}, 'receiving-bootstrap-freeze', bootstrap_initial=True,
            bootstrap_initial_service=True)


def test_host_forwards_control_paths_without_fabricating_a_native_request(tmp_path, monkeypatch):
    from pathlib import Path
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    private = Path('/home/agent/body/runtime/receiving-control/test.json')
    command = Path('/home/agent/approved-control.json')
    backend._target_call(value, 'receiving-control-prepare', candidate=candidate,
        control_file=private, control_command=command)
    argv = calls[0][0]
    assert argv[argv.index('--control-file') + 1] == str(private)
    assert argv[argv.index('--control-command') + 1] == str(command)


def test_guest_control_uses_bounded_stdin_and_owner_retained_request_path(tmp_path, monkeypatch):
    from pathlib import Path
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    command = {'phase': 'revoke', 'readers': [], 'operation_id': 'synthetic'}
    backend._target_call(value, 'receiving-control-prepare', candidate=candidate,
        control_file=Path('/home/agent/body/runtime/receiving-control/test.json'),
        control_value=command, observation_timeout_seconds=5)
    argv, options = calls[0]
    assert argv[:6] == ['exec', 'dm-eko', '--user', '1000', '--group', '1000']
    assert argv[argv.index('--') + 1].endswith('/venv/bin/python')
    assert argv[argv.index('--control-command') + 1] == '-'
    assert not any('synthetic' in part for part in argv)
    assert json.loads(options['input_data']) == command
    assert 0 < options['timeout_seconds'] <= 5


def test_receiving_identity_uses_prepared_candidate_and_one_finite_owner_budget(tmp_path, monkeypatch):
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    backend._target_call(value, 'receiving-identity', candidate=candidate,
        identity_expires_at_ms=12345, observation_timeout_seconds=5)
    argv, options = calls[0]
    assert argv[:6] == ['exec', 'dm-eko', '--user', '1000', '--group', '1000']
    assert argv[argv.index('--') + 1].endswith('/venv/bin/python')
    assert argv[argv.index('--identity-expires-at-ms') + 1] == '12345'
    assert 0 < options['timeout_seconds'] <= 5


@pytest.mark.parametrize('publication', [False, True])
def test_group_request_uses_prepared_owner_stdin_without_requiring_running_group(tmp_path, monkeypatch, publication):
    import uuid
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    packet = dict(command=dict(operation_id=str(uuid.uuid4()), step='accept',
        method='tribe.membership.accept', params={'payload': {}}), offline=True, authority_closure={})
    action = 'group-publication' if publication else 'group-relationship'
    if publication:
        packet['command'] = dict(operation_id=str(uuid.uuid4()), step='select', action='selection',
                                 params=dict(expected_selection_sha256=None))
    backend._target_call(value, action, candidate=candidate,
        group_request=packet, observation_timeout_seconds=5)
    argv, options = calls[0]
    assert argv[:6] == ['exec', 'dm-eko', '--user', '1000', '--group', '1000']
    assert argv[argv.index('--') + 1].endswith('/venv/bin/python')
    assert argv[argv.index('--group-request') + 1] == '-'
    assert json.loads(options['input_data']) == packet
    assert packet['command']['operation_id'] not in argv
    assert 0 < options['timeout_seconds'] <= 5
    with pytest.raises(OnboardingError, match='writer_required'):
        backend._target_call(value, action, candidate=candidate, group_request=packet)
    with pytest.raises(OnboardingError, match='writer_required'):
        backend._target_call(value, 'group-relationship' if publication else 'group-publication',
            candidate=candidate, group_request=packet, observation_timeout_seconds=5)
    assert len(calls) == 1


def test_incus_stdin_is_bounded_and_never_routed_through_a_shell(monkeypatch):
    from clusterctl import onboarding_host
    calls = []
    def execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout='{}')
    monkeypatch.setattr(onboarding_host.subprocess, 'run', execute)
    HostBackend._run(['exec', 'fixture'], timeout_seconds=3, input_data='{"phase":"revoke"}')
    assert calls[0][0] == ['incus', 'exec', 'fixture']
    assert calls[0][1]['input'] == '{"phase":"revoke"}'
    assert calls[0][1]['timeout'] == 3 and 'shell' not in calls[0][1]
    with pytest.raises(OnboardingError, match='invalid_receiving_control_request'):
        HostBackend._run(['exec', 'fixture'], input_data='x' * (being_seed.MAX_SELECTION + 1))
    assert len(calls) == 1


@pytest.mark.parametrize('action', ['observe', 'sdk-observe', 'sdk-prepare'])
def test_host_prepared_target_observations_keep_supported_finite_cli_budget(tmp_path, monkeypatch, action):
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    result = backend._target_call(value, action, candidate=candidate, observation_timeout_seconds=2)
    assert result == {'observed': True}
    command, options = calls[-1]
    assert '--observation-timeout-seconds' in command
    assert 0 < options['timeout_seconds'] <= 2


def test_group_target_prepares_approved_candidate_only_after_original_v8(tmp_path, monkeypatch):
    import time
    config, value, run, backend = configured(tmp_path)
    backend.config = replace(config, code=tmp_path/'base', views=tmp_path/'views')
    backend._guest_paths = lambda p: (tmp_path, Path('/guest/base'), {})
    candidate = (tmp_path/'candidate', 'a'*64)
    mount = dict(type='disk', source=str(candidate[0]), path='/guest/candidate', readonly='true')
    backend._runtime_paths = lambda p, base, **kw: (Path('/guest/code'), [],
        {'approved-candidate': mount} if kw else {})
    backend._matrix_mount = lambda p: {}
    attached, ready, calls = {'value': False}, {'v8': False, 'sdk': False}, []
    def mounted(p, mounts, **kw):
        return attached['value'] if 'approved-candidate' in mounts else True
    backend._mounted = mounted
    backend._sdk_successor = lambda p: False
    def target(p, action, **options):
        calls.append(action)
        if action == 'observe':
            return {'phase': 'v8' if ready['v8'] else 'v8-published'}
        if action == 'sdk-observe':
            return {'ready': ready['sdk']}
        assert action == 'sdk-prepare' and attached['value']
        ready['sdk'] = True
        return {'ready': True}
    backend._target_call = target
    def dispatch(p, command, **options):
        assert ready['v8'] and command[:3] == ['config', 'device', 'add']
        attached['value'] = True
        calls.append('mount')
        return ''
    backend._dispatch = dispatch
    deadline = time.monotonic_ns()+2_000_000_000
    assert not backend.prepare_group_target(value, candidate, deadline_ns=deadline)
    assert calls == ['observe']
    ready['v8'] = True
    assert backend.prepare_group_target(value, candidate, deadline_ns=deadline)
    assert calls[-4:] == ['observe', 'mount', 'sdk-observe', 'sdk-prepare']
    assert backend.prepare_group_target(value, candidate, deadline_ns=deadline)
    assert calls[-2:] == ['observe', 'sdk-observe']


@pytest.mark.parametrize('expired', [False, True])
def test_host_native_budget_and_frozen_expiry_reach_guest_before_effect(tmp_path, monkeypatch, expired):
    import time
    from clusterctl import onboarding_host
    _, value, _, backend = configured(tmp_path)
    clock = [time.monotonic_ns()]
    monkeypatch.setattr(onboarding_host, 'time', SimpleNamespace(
        monotonic_ns=lambda: clock[0], time_ns=time.time_ns))
    def environment(p, **options):
        if expired:
            clock[0] += 3_000_000_000
        return SimpleNamespace(state='complete')
    backend._environment = environment
    backend._guest_paths = lambda p: (tmp_path, Path('/guest/code'), {})
    backend._telegram_paths = lambda p, base: (base, [], {})
    backend._mounted = lambda *a, **k: True
    calls = []
    def dispatch(p, command, **options):
        calls.append(command)
        return json.dumps({'plan_digest': digest(p)})
    backend._dispatch = dispatch
    deadline, expiry = clock[0]+2_000_000_000, time.time_ns()//1_000_000+10000
    def invoke():
        backend._telegram_command(value, 'native-install', deadline_ns=deadline, authorization_expires_at_ms=expiry)
    if expired:
        with pytest.raises(OnboardingError, match='deadline_expired'):
            invoke()
        assert calls == []
    else:
        invoke()
        command = calls[-1]
        assert float(command[command.index('--operation-timeout-seconds')+1]) == 2
        assert command[command.index('--authorization-expires-at-ms')+1] == str(expiry)


@pytest.mark.parametrize('action', ['admission-prepare', 'admission-check', 'admission-enroll'])
def test_candidate_physical_admission_retains_budget_and_original_expiry(tmp_path, monkeypatch, action):
    import time
    backend, value, _, candidate, calls = candidate_call_fixture(tmp_path, monkeypatch)
    expiry = time.time_ns() // 1_000_000 + 10000
    options = {} if action == 'admission-prepare' else {'profile': {'synthetic': 'public-only'}}
    assert backend._target_call(value, action, candidate=candidate, observation_timeout_seconds=2,
        authorization_expires_at_ms=expiry, **options) == {'observed': True}
    command, observed = calls[-1]
    assert command[command.index('--authorization-expires-at-ms')+1] == str(expiry)
    assert '--observation-timeout-seconds' in command and 0 < observed['timeout_seconds'] <= 2
    with pytest.raises(OnboardingError, match='deadline_required'):
        backend._target_call(value, action, candidate=candidate, observation_timeout_seconds=2, **options)
    with pytest.raises(OnboardingError, match='deadline_expired'):
        backend._target_call(value, action, candidate=candidate, observation_timeout_seconds=2,
            authorization_expires_at_ms=1, **options)
    assert len(calls) == 1, 'expired/missing authorization must never dispatch'
