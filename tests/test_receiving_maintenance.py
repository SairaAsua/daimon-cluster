"""Retained orchestration boundaries; native owner/lifecycle proof is separate."""
import json
from types import SimpleNamespace

import pytest

from clusterctl import receiving_maintenance as maintenance
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.operation_journal import OperationJournal


@pytest.mark.parametrize('effects,expected', [
    ({}, ['quiesce', 'publish', 'start']),
    ({'quiesced': {}}, ['publish', 'start']),
    ({'unit_selected': {}}, ['start']),
    ({'unit_selected': {}, 'start_intent': {}}, ['start']),
    ({'unit_selected': {}, 'controlled_loaded': {}}, ['start']),
])
def test_source_dispatch_resumes_only_missing_effects(tmp_path, effects, expected):
    journal = OperationJournal(tmp_path / 'owner-journal')
    row = plan_update(journal, manifest_digest='a' * 64, target='source-bootstrap:fixture',
        expected_precondition={}, intended_transition={}, audit_identity={'actor': 'fixture'})
    row = journal.advance(row['operation_id'], row['state'],
        runtime_observation={'source_bootstrap': effects})
    calls = []
    class Controller:
        def _row(self):
            return journal.get(row['operation_id']), {}, {}
        def quiesce(self, **kwargs): calls.append('quiesce')
        def publish(self): calls.append('publish')
        def start(self, **kwargs):
            calls.append('start')
            return {'same_retained_process': True}
    assert maintenance.resume_source(Controller()) == {'same_retained_process': True}
    assert calls == expected


def test_source_inconsistent_start_never_replays_publication():
    controller = SimpleNamespace(_row=lambda: ({'runtime_observation': {
        'source_bootstrap': {'start_intent': {}}}}, {}, {}),
        quiesce=lambda **kwargs: pytest.fail('replayed stop'),
        publish=lambda: pytest.fail('replayed publication'),
        start=lambda **kwargs: pytest.fail('accepted inconsistent start'))
    with pytest.raises(OnboardingError, match='child_conflict'):
        maintenance.resume_source(controller)


def test_source_prepare_retry_finds_original_child_before_new_observation(tmp_path):
    journal = OperationJournal(tmp_path / 'owner-journal')
    spec = {'candidate': {'manifest_digest': 'a' * 64}, 'explicit': 'fixed selection'}
    row = plan_update(journal, manifest_digest='a' * 64,
        target='source-bootstrap:maintenance:' + digest(spec),
        expected_precondition={'maintenance_binding': digest(spec),
                               'source_bootstrap': {'observed_at_ms': 123}},
        intended_transition={'source_bootstrap': {'fixed': 'request'}},
        audit_identity={'actor': 'fixture'})
    assert maintenance._source_row(journal, spec)['operation_id'] == row['operation_id']
    assert maintenance._source_row(journal, spec)['expected_precondition']['source_bootstrap']['observed_at_ms'] == 123
    assert len(journal.list_all()) == 1


def test_owner_diagnostic_retains_safe_code_without_arbitrary_output():
    import time
    deadline = time.monotonic_ns() + 1_000_000_000
    for payload, expected in [({'error': 'receiving_control_process_changed'}, 'receiving_control_process_changed'),
                              ({'error': '/private/credential detail'}, 'receiving_maintenance_owner_refused'),
                              ({'error': 'sensitive_token_fragment'}, 'receiving_maintenance_owner_refused')]:
        response = SimpleNamespace(returncode=1, stdout='', stderr=json.dumps(payload))
        with pytest.raises(OnboardingError, match=expected):
            maintenance._response(response, deadline_ns=deadline)
    response = SimpleNamespace(returncode=0, stdout='{}', stderr='')
    with pytest.raises(OnboardingError, match='deadline_expired'):
        maintenance._response(response, deadline_ns=time.monotonic_ns() - 1)


@pytest.mark.parametrize('timeout', [False, True])
def test_source_owner_transport_retains_closed_failure_class(tmp_path, monkeypatch, timeout):
    import os
    config = tmp_path/'source.json'
    config.write_text('{}')
    config.chmod(0o600)
    base = SimpleNamespace(root=tmp_path/'runtime', socket=tmp_path/'tribe.sock', config=config,
        owner_uid=os.geteuid(), owner_gid=os.getegid(), timeout_seconds=1, deadline_ns=None,
        venv=tmp_path/'sdk'/'old'/'venv')
    owner = maintenance.PinnedOwnerClient(base, {'code':str(tmp_path/'code'), 'code_digest':'a'*64},
        {}, body_code=tmp_path/'code')
    monkeypatch.setattr(maintenance, '_sdk', lambda *args: ({'sdk':'fixture'}, {}))
    def fail(*args, **kwargs):
        if timeout:
            raise maintenance.subprocess.TimeoutExpired('private argv', 1, stderr='private credential')
        raise OSError('private path or credential')
    monkeypatch.setattr(maintenance.subprocess, 'run', fail)
    code = 'receiving_host_deadline_expired' if timeout else 'receiving_host_launch_failed'
    with pytest.raises(OnboardingError, match='^' + code + '$'):
        owner.status()


def reassessment_fixture(tmp_path, monkeypatch):
    """Real cohort journal/manifest, fake native owners; no SDK/lifecycle effects."""
    import copy
    import os
    from pathlib import Path
    from clusterctl import onboarding_receiving_update as updates
    from tests.test_receiving_cohort_control import activation_fixture
    controller, owners, journal, previous = activation_fixture(tmp_path)
    controller.prepare_activation()
    monkeypatch.setattr(controller, '_current_activation', lambda *a, **k:
        (_ for _ in ()).throw(OnboardingError('receiving_cohort_activation_changed')))
    with pytest.raises(OnboardingError, match='activation_changed'):
        controller.activate()
    row = journal.get(previous)
    plan = row['intended_transition']['cohort_activation']
    manifest = json.loads(Path(plan['manifest_path']).read_text())
    for receiver in manifest['required_receivers']:
        name = next(name for name, owner in owners.items() if owner.being == receiver['being_ref'])
        receiver['expected_selection_sha256'] = digest(plan['receivers'][name]['selection'])
    path = tmp_path/'reassessment.json'
    from clusterctl import being_seed
    being_seed._write(path, manifest)
    spec = {'fixture':'fixed specification'}
    parent = plan_update(journal, manifest_digest='f'*64, target='receiving-maintenance:reassessment-fixture',
        expected_precondition={'maintenance_spec':spec}, intended_transition={}, audit_identity={'actor':'fixture'})
    loaded = {}
    for name, owner in owners.items():
        loaded['loaded:'+name] = dict(process=copy.deepcopy(owner.process),
            loaded_runtime={**copy.deepcopy(owner.loaded), 'local_origin':copy.deepcopy(owner.server)},
            loaded_application=copy.deepcopy(owner.application))
    journal.advance(parent['operation_id'], parent['state'], runtime_observation={'maintenance':{
        'cohort':{'operation_id':previous}, **loaded}})
    operation = maintenance.ReceivingMaintenance.__new__(maintenance.ReceivingMaintenance)
    operation.spec, operation.journal, operation.operation_id = spec, journal, parent['operation_id']
    operation._owners = lambda values: owners
    recipe = next(iter(plan['receivers'].values()))
    lifecycle = journal.get(recipe['lifecycle_operation_id'])
    operation.body = (Path(lifecycle['intended_transition']['source_bootstrap']['qualification']['code']),
        recipe['selection']['receiving_code'])
    # Exercise real verification with this fixture's UID instead of production0.
    manifest_read, preflight = updates._manifest, updates.preflight
    monkeypatch.setattr(updates, '_manifest', lambda path, fingerprint, **kw:
        manifest_read(path, fingerprint, uid=os.geteuid()))
    monkeypatch.setattr(updates, 'preflight', lambda *args, **kw:
        preflight(*args, **{**kw,'code_uid':os.geteuid(),'manifest_uid':os.geteuid()}))
    return operation, owners, path, manifest, previous


@pytest.mark.parametrize('loss', [None, 'child', 'tip'])
def test_activation_only_reassessment_retains_one_child_after_lost_reply(tmp_path, monkeypatch, loss):
    operation, owners, path, manifest, previous = reassessment_fixture(tmp_path, monkeypatch)
    journal = operation.journal
    before = len(journal.list_all())
    effects_before = [owner.effects for owner in owners.values()]
    if loss == 'child':
        original = operation._prepare_reassessment
        def lose(*args):
            original(*args)
            raise OSError('lost child reply')
        monkeypatch.setattr(operation, '_prepare_reassessment', lose)
    elif loss == 'tip':
        original = operation._record
        def lose(*args):
            original(*args)
            raise OSError('lost tip reply')
        monkeypatch.setattr(operation, '_record', lose)
    if loss:
        with pytest.raises(OSError):
            operation.reassess(path, digest(manifest), previous)
    def unexpected(*args, **kwargs):
        pytest.fail('replayed lifecycle, SDK, installation or fresh freeze')
    if loss == 'tip':
        monkeypatch.setattr(operation, '_record', unexpected)
    if loss:
        monkeypatch.setattr(operation, '_prepare_reassessment', unexpected)
    operation.reassess(path, digest(manifest), previous)
    assert len(journal.list_all()) == before + 1
    assert [owner.effects for owner in owners.values()] == effects_before
    effects = operation._effects()
    assert effects['cohort']['operation_id'] == previous
    child = journal.get(operation._cohort_tip(effects))
    old = journal.get(previous)
    assert child['expected_precondition']['previous_cohort'] == previous
    assert child['runtime_observation']['native_tooling'] == old['runtime_observation'].get('native_tooling', {})
    assert child['intended_transition']['cohort_activation']['expires_at_ms'] == old['intended_transition']['cohort_activation']['expires_at_ms']


@pytest.mark.parametrize('fault', ['artifact', 'authority', 'provenance', 'nonempty', 'process'])
def test_reassessment_refuses_changed_release_or_unfinished_gate(tmp_path, monkeypatch, fault):
    from clusterctl import being_seed
    operation, owners, path, manifest, previous = reassessment_fixture(tmp_path, monkeypatch)
    before = len(operation.journal.list_all())
    if fault == 'artifact':
        manifest['artifacts']['receiving_code'] = '0'*64
    elif fault == 'authority':
        manifest['authorities']['candidate'][0]['control_head'] = 'changed'
    elif fault == 'provenance':
        manifest['provenance']['qualification_sha256'] = '0'*64
    elif fault == 'nonempty':
        owners['eko'].gate['readers'] = [{}]
    else:
        owners['eko'].process['start_ticks'] += 1
    being_seed._write(path, manifest)
    with pytest.raises(OnboardingError):
        operation.reassess(path, digest(manifest), previous)
    assert len(operation.journal.list_all()) == before


def test_cohort_tip_refuses_forks_and_disconnected_children():
    resolve = maintenance.ReceivingMaintenance._cohort_tip
    root = {'cohort':{'operation_id':'original'}}
    one = {**root,'assessment:a':{'operation_id':'one','previous_operation_id':'original'}}
    assert resolve(one) == 'one'
    for parent in ('original','missing','one'):
        bad = {**one,'assessment:b':{'operation_id':'one' if parent=='one' else 'two','previous_operation_id':parent}}
        with pytest.raises(OnboardingError, match='child_conflict'):
            resolve(bad)


def test_reassessment_tip_cannot_be_replaced_by_another_request(tmp_path, monkeypatch):
    operation, _, path, manifest, previous = reassessment_fixture(tmp_path, monkeypatch)
    operation.reassess(path, digest(manifest), previous)
    tip = operation._cohort_tip(operation._effects())
    with pytest.raises(OnboardingError, match='child_conflict'):
        operation.reassess(path.with_name('another.json'), digest(manifest), previous)
    assert operation._cohort_tip(operation._effects()) == tip


def test_reassessment_preserves_expiry_and_refuses_after_horizon(tmp_path, monkeypatch):
    import time
    operation, _, path, manifest, previous = reassessment_fixture(tmp_path, monkeypatch)
    horizon = operation.journal.get(previous)['intended_transition']['cohort_activation']['expires_at_ms']
    monkeypatch.setattr(time, 'time_ns', lambda: (horizon + 1)*1_000_000)
    with pytest.raises(OnboardingError, match='authorization_expired'):
        operation.reassess(path, digest(manifest), previous)
    assert operation._cohort_tip(operation._effects()) == previous


def test_apply_uses_published_assessment_without_replaying_lifecycle(tmp_path, monkeypatch):
    from clusterctl import being_seed, onboarding_host, onboarding_receiving_update as updates
    journal = OperationJournal(tmp_path/'journal')
    host = tmp_path/'host.json'
    being_seed._write(host, {'selected':'host'})
    original = plan_update(journal, manifest_digest='a'*64, target='original',
        expected_precondition={'host_configuration':{'selected':'host'}}, intended_transition={'host_runtime':{}},
        audit_identity={'actor':'fixture'})
    child = plan_update(journal, manifest_digest='b'*64, target='assessment',
        expected_precondition={}, intended_transition={}, audit_identity={'actor':'fixture'})
    spec = {'fixture':'immutable spec'}
    parent = plan_update(journal, manifest_digest='a'*64, target='maintenance',
        expected_precondition={'maintenance_spec':spec}, intended_transition={}, audit_identity={'actor':'fixture'})
    journal.advance(parent['operation_id'], parent['state'], runtime_observation={'maintenance':{
        'cohort':{'operation_id':original['operation_id']}, 'host-selected':{'selected':True},
        'loaded:source':{'retained':'source'}, 'loaded:eko':{'retained':'eko'},
        'assessment:b':{'operation_id':child['operation_id'],'previous_operation_id':original['operation_id']}}})
    events = []
    class Cohort:
        def __init__(self, actual_journal, identifier, owners):
            assert actual_journal is journal and identifier == child['operation_id']
        def _row(self): return journal.get(child['operation_id'])
        def revoke_senders(self): events.append('revoke-current')
        def reconcile_tooling(self): events.append('retained-tooling')
        def activate(self):
            events.append('select-current')
            return {'operation_id':child['operation_id']}
    def unexpected(*args, **kwargs):
        pytest.fail('activation-only recovery replayed SDK/lifecycle/host selection')
    monkeypatch.setattr(updates, 'CohortController', Cohort)
    monkeypatch.setattr(updates, 'GuestBootstrapController', unexpected)
    monkeypatch.setattr(onboarding_host.HostConfig, 'load', lambda *_: {})
    monkeypatch.setattr(onboarding_host, 'HostBackend', lambda *_: object())
    operation = maintenance.ReceivingMaintenance.__new__(maintenance.ReceivingMaintenance)
    operation.spec, operation.journal, operation.operation_id = spec, journal, parent['operation_id']
    operation.config_path, operation.plans = host, {'eko':{}}
    operation.source = SimpleNamespace(call=unexpected)
    operation._owners = lambda loaded: {'retained':'owners'}
    assert operation.apply()['phase'] == 'receiving-selected'
    assert events == ['revoke-current','retained-tooling','select-current']


@pytest.mark.parametrize('lost', ['source-start', 'host-selection'])
def test_coordinator_resumes_same_journal_after_effect_and_lost_response(tmp_path, monkeypatch, lost):
    from clusterctl import onboarding_host, onboarding_receiving_update as updates
    journal = OperationJournal(tmp_path / 'root-journal')
    spec = {'fixture': 'immutable specification'}
    row = plan_update(journal, manifest_digest='a' * 64, target='receiving-maintenance:fixture',
        expected_precondition={'maintenance_spec': spec}, intended_transition={},
        audit_identity={'actor': 'fixture'})
    journal.advance(row['operation_id'], row['state'], runtime_observation={'maintenance': {
        'cohort': {'operation_id': 'cohort:retained'}, 'before': {'original': 'processes'},
        'child:eko': {'operation_id': 'guest:retained'}}})
    from clusterctl import being_seed
    host = tmp_path / 'fixed-host.json'
    being_seed._write(host, {'selected': 'host'})
    cohort = plan_update(journal, manifest_digest='a' * 64, target='cohort:fixture',
        expected_precondition={'host_configuration': {'selected': 'host'}},
        intended_transition={'host_runtime': {}}, audit_identity={'actor': 'fixture'})
    monkeypatch.setattr(journal, 'get', (lambda get: lambda operation_id: get(cohort['operation_id'])
        if operation_id == 'cohort:retained' else get(operation_id))(journal.get))
    events, effects = [], {'host': 0, 'source': 0, 'guest': 0}
    failed = []
    class Cohort:
        def __init__(self, current_journal, operation_id, owners):
            assert current_journal is journal and operation_id == 'cohort:retained'
        def revoke_senders(self): events.append('revoke-originals')
        def apply_host_selection(self, path):
            events.append('host-selection')
            if not effects['host']:
                effects['host'] += 1
                if lost == 'host-selection' and not failed:
                    failed.append(True)
                    raise TimeoutError('lost CAS response')
            return {'selected': True}
        def reconcile_tooling(self): events.append('tooling')
        def prepare_activation(self): pytest.fail('coordinator replayed activation preparation')
        def activate(self):
            events.append('receiving-selected')
            return {'readers': ['actual source', 'actual guest']}
    class Guest:
        def __init__(self, current_journal, operation_id, backend, name):
            assert current_journal is journal and operation_id == 'guest:retained' and name == 'eko'
        def execute(self, **kwargs):
            events.append('guest-load')
            effects['guest'] += 1
            return {'process': 'guest retained'}
    class Source:
        def call(self, action):
            assert action == 'execute'
            events.append('source-load')
            if not effects['source']:
                effects['source'] += 1
                if lost == 'source-start' and not failed:
                    failed.append(True)
                    raise TimeoutError('lost Source start response')
            return {'loaded': {'process': 'same retained source'}}
    monkeypatch.setattr(updates, 'CohortController', Cohort)
    monkeypatch.setattr(updates, 'GuestBootstrapController', Guest)
    monkeypatch.setattr(onboarding_host.HostConfig, 'load', lambda *_: {'selected': 'host'})
    monkeypatch.setattr(onboarding_host, 'HostBackend', lambda *_: object())
    def reopen():
        controller = maintenance.ReceivingMaintenance.__new__(maintenance.ReceivingMaintenance)
        controller.spec, controller.journal, controller.operation_id = spec, journal, row['operation_id']
        controller.plans = {'eko': {}}
        controller.config_path = tmp_path / 'fixed-host.json'
        controller.source = Source()
        controller._owners = lambda *_: {'selected': 'owners'}
        return controller
    with pytest.raises(TimeoutError):
        reopen().apply()
    assert effects['guest'] == 0
    if lost == 'source-start':
        assert events[:3] == ['revoke-originals', 'host-selection', 'source-load']
        assert reopen()._effects()['host-selected'] == {'selected': True}
    before = len(events)
    result = reopen().apply()
    assert result['phase'] == 'receiving-selected' and result['worker_paused'] is False
    assert effects == {'host': 1, 'source': 1, 'guest': 1}
    assert events[-2:] == ['tooling', 'receiving-selected']
    if lost == 'source-start':
        assert 'revoke-originals' not in events[before:] and 'host-selection' not in events[before:]
    assert len(journal.list_all()) == 2


def spec_fixture(tmp_path):
    import time
    code = str(tmp_path / 'approved-code')
    source = {key: str(tmp_path / ('source-' + key)) for key in (
        'home', 'config', 'unit', 'root', 'socket', 'bootstrap_venv', 'bootstrap_imports', 'journal', 'transaction')}
    generation = tmp_path / 'private-sdk' / ('d' * 64)
    source.update(bootstrap_venv=str(generation / 'venv'), bootstrap_imports=str(generation / 'runtime-imports'))
    source.update(uid=1000, gid=1000, config_sha256='c' * 64, tooling={'profile': 'matrix-only'})
    return dict(schema=maintenance.SCHEMA, name='fixture', journal=str(tmp_path / 'root-journal'),
        host_config=str(tmp_path / 'host.json'), observer={'code': code, 'code_digest': 'a' * 64},
        candidate=dict(code=code, code_digest='a' * 64, manifest_path=str(tmp_path / 'release.json'),
            manifest_digest='b' * 64, expires_at_ms=time.time_ns() // 1_000_000 + 10000),
        source=source, guests={'eko': dict(grant=str(tmp_path / 'grant.json'), tooling={'profile': 'matrix-only'})})


def test_source_adapter_drops_privileges_before_private_interpreter_and_never_reads_it(tmp_path, monkeypatch):
    import stat
    from pathlib import Path
    spec = spec_fixture(tmp_path)
    monkeypatch.setattr(maintenance, '_sdk', lambda *_: ({'public': 'sdk'}, {}))
    original = Path.lstat
    def info(path):
        if path == Path(spec['source']['config']):
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000, st_gid=1000, st_nlink=1)
        if 'private-sdk' in str(path) or '.local/share/daimon-matrix/sdk' in str(path):
            pytest.fail('root inspected the private interpreter')
        return original(path)
    monkeypatch.setattr(Path, 'lstat', info)
    calls = []
    def dispatch(argv, **options):
        calls.append((argv, options))
        assert options['user'] == options['group'] == 1000 and options['extra_groups'] == ()
        assert argv[0] == spec['source']['bootstrap_venv'] + '/bin/python'
        assert argv[1:4] == ['-B', '-I', '-S']
        assert argv[-2:] == ['--owner', 'prepare-sdk']
        assert json.loads(options['input']) == spec
        return SimpleNamespace(returncode=0, stdout='{"sdk_prepared":true}', stderr='')
    monkeypatch.setattr(maintenance.subprocess, 'run', dispatch)
    assert maintenance.SourceMaintenanceClient(spec).call('prepare-sdk') == {'sdk_prepared': True}
    assert len(calls) == 1


@pytest.mark.parametrize('change', ['root-owner', 'relative-code', 'unknown-hook'])
def test_maintenance_spec_refuses_unsupported_owner_or_execution_surface(tmp_path, change):
    spec = spec_fixture(tmp_path)
    if change == 'root-owner':
        spec['source']['uid'] = 0
    if change == 'relative-code':
        spec['observer']['code'] = '../other-code'
    if change == 'unknown-hook':
        spec['command'] = ['arbitrary', 'program']
    with pytest.raises(OnboardingError, match='binding_required'):
        maintenance.validate(spec)


def test_source_child_lookup_is_not_limited_by_recent_journal_page(tmp_path):
    journal = OperationJournal(tmp_path / 'journal')
    spec = {'candidate': {'manifest_digest': 'a' * 64}}
    target = 'source-bootstrap:maintenance:' + digest(spec)
    original = plan_update(journal, manifest_digest='a' * 64, target=target,
        expected_precondition={'maintenance_binding': digest(spec)}, intended_transition={},
        audit_identity={'actor': 'fixture'})
    for index in range(101):
        plan_update(journal, manifest_digest='b' * 64, target='newer:' + str(index),
            expected_precondition={}, intended_transition={}, audit_identity={'actor': 'fixture'})
    assert original['operation_id'] not in {row['operation_id'] for row in journal.list_all()}
    assert maintenance._source_row(journal, spec)['operation_id'] == original['operation_id']


def test_selector_drift_refuses_before_resumed_source_lifecycle(tmp_path):
    from clusterctl import being_seed
    journal = OperationJournal(tmp_path / 'journal')
    cohort = plan_update(journal, manifest_digest='a' * 64, target='cohort:fixture',
        expected_precondition={'host_configuration': {'jobs': 'retained', 'runtime_by_name': {}}},
        intended_transition={'host_runtime': {'runtime_by_name': {'eko': {'runtime_code': 'selected'}}}},
        audit_identity={'actor': 'fixture'})
    spec = {'fixture': True}
    parent = plan_update(journal, manifest_digest='a' * 64, target='parent:fixture',
        expected_precondition={'maintenance_spec': spec}, intended_transition={},
        audit_identity={'actor': 'fixture'})
    journal.advance(parent['operation_id'], parent['state'], runtime_observation={'maintenance': {
        'cohort': {'operation_id': cohort['operation_id']}, 'host-selected': {'selected': True}}})
    controller = maintenance.ReceivingMaintenance.__new__(maintenance.ReceivingMaintenance)
    controller.journal, controller.operation_id, controller.spec = journal, parent['operation_id'], spec
    controller.config_path = tmp_path / 'host.json'
    being_seed._write(controller.config_path, {'jobs': 'concurrent change'})
    controller.source = SimpleNamespace(call=lambda *_: pytest.fail('started Source after selector drift'))
    with pytest.raises(OnboardingError, match='receiving_maintenance_host_changed'):
        controller.apply()


def test_public_cli_diagnostic_never_exports_unknown_exception_text():
    from clusterctl import being_seed
    for exception in (OnboardingError, being_seed.SeedError, RuntimeError):
        assert maintenance.public_error(exception('sensitive_token_fragment')) == 'receiving_maintenance_owner_refused'
    assert maintenance.public_error(being_seed.SeedError('seed_operation_in_progress')) == 'seed_operation_in_progress'


@pytest.mark.parametrize('lost', ['first-positive', 'parent-completion'])
def test_coordinator_uses_real_cohort_resume_without_repreparing_selection(tmp_path, monkeypatch, lost):
    from clusterctl import being_seed, onboarding_host
    from tests.test_receiving_cohort_control import activation_fixture
    selected = {'fixture': 'selected-host'}
    cohort, owners, journal, cohort_id = activation_fixture(tmp_path, replacement=True, host_configuration=selected)
    host = tmp_path / 'selected-host.json'
    being_seed._write(host, selected)
    spec = {'fixture': 'maintenance'}
    row = plan_update(journal, manifest_digest='a' * 64, target='maintenance:fixture',
        expected_precondition={'maintenance_spec': spec}, intended_transition={},
        audit_identity={'actor': 'fixture'})
    # The lifecycle outcomes are retained; this test covers the real Cohort
    # state machine under the new coordinator, not native processes.
    observed = {'cohort': {'operation_id': cohort_id}, 'host-selected': {'selected': True}}
    for name in ('source', *owners):
        observed['loaded:' + name] = {'fixture': name}
    journal.advance(row['operation_id'], row['state'], runtime_observation={'maintenance': observed})
    monkeypatch.setattr(onboarding_host.HostConfig, 'load', lambda *_: object())
    monkeypatch.setattr(onboarding_host, 'HostBackend', lambda *_: object())
    controller = maintenance.ReceivingMaintenance.__new__(maintenance.ReceivingMaintenance)
    controller.spec, controller.journal, controller.operation_id = spec, journal, row['operation_id']
    controller.config_path, controller.plans = host, dict.fromkeys(owners)
    controller._owners = lambda *_: owners
    if lost == 'first-positive':
        apply = owners['oliva'].apply_control
        failed = []
        def lose(path):
            value = apply(path)
            if not failed and owners['oliva'].requests[path]['phase'] == 'select':
                failed.append(True)
                raise OSError('fixture lost first positive reply')
            return value
        monkeypatch.setattr(owners['oliva'], 'apply_control', lose)
    else:
        save = controller._record
        failed = []
        def lose(name, value):
            if name == 'receiving-selected' and not failed:
                failed.append(True)
                raise OSError('fixture lost parent completion')
            return save(name, value)
        monkeypatch.setattr(controller, '_record', lose)
    with pytest.raises(OSError):
        controller.apply()
    effects = {name: owner.effects for name, owner in owners.items()}
    assert controller.apply()['phase'] == 'receiving-selected'
    assert {name: owner.effects for name, owner in owners.items()} == effects


@pytest.mark.parametrize('roster', [None, {}, {'schema': 'old'},
    {'schema': 'dm.runtime.tribe-roster/v1', 'roster_sha256': 'not-a-digest'}])
def test_unmigrated_group_view_is_an_explicit_supported_profile_refusal(roster):
    observed = {'runtime_status': {'receiving': {'rosters': {'tribe': roster}}}}
    with pytest.raises(OnboardingError, match='receiving_maintenance_current_roster_required'):
        maintenance.current_roster(observed)
    assert maintenance.public_error(OnboardingError('receiving_maintenance_current_roster_required')) == 'receiving_maintenance_current_roster_required'
    assert maintenance.current_roster({'runtime_status': {'receiving': {'rosters': {'tribe': {
        'schema': 'dm.runtime.tribe-roster/v1', 'roster_sha256': 'a' * 64}}}}}) == 'a' * 64


@pytest.mark.parametrize('different_parent', [False, True])
def test_invalid_source_transaction_is_refused_before_any_prepare_or_effect(tmp_path, different_parent):
    spec = spec_fixture(tmp_path)
    spec['source']['transaction'] = (str(tmp_path / 'elsewhere' / 'transaction')
        if different_parent else spec['source']['root'])
    with pytest.raises(OnboardingError, match='source_transaction_required'):
        maintenance.ReceivingMaintenance(spec)
    assert not (tmp_path / 'root-journal').exists()


def test_source_preparation_checks_real_root_transaction_before_sdk_staging(tmp_path, monkeypatch):
    from clusterctl import onboarding_receiving_update as updates
    source = SimpleNamespace(root=tmp_path / 'package' / 'runtime')
    monkeypatch.setattr(updates, 'prepare_sdk', lambda *a, **kw: pytest.fail('staged SDK before binding check'))
    with pytest.raises(OnboardingError, match='receiving_bootstrap_binding_conflict'):
        updates.prepare_source_bootstrap(source,home=tmp_path,code=tmp_path,code_digest='a'*64,
            config=tmp_path/'config',manifest_path=tmp_path/'manifest',manifest_digest='b'*64,
            transaction=tmp_path/'wrong-parent',expires_at_ms=1)
