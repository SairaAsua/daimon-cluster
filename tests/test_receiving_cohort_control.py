"""Cohort state-machine faults with fake senders and real selector/journal.

These cases prove durable orchestration, not native RPC or receiving readiness.
Native owner RPC/fence qualification is a separate actual integration boundary.
"""
import copy
import hashlib
import os
import time
from pathlib import Path

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.onboarding_receiving_update import CohortController, GuestGroupClient, OwnerGroupClient, apply_host_selection, freeze_senders, receiving_identity, verify_receiving_identity
from clusterctl.operation_journal import OperationJournal
from tests.test_receiving_host_selection import fixture as host_fixture


def identity_fixture():
    origin = dict(body_ref='codex:fixture:eko', embodiment_id='body:eko', incarnation_id='incarnation:eko')
    status = dict(being_ref='being:eko', manifest_hash='a'*64, local_origin=origin)
    scope = dict(schema='dm.scope.me/v1', being_ref=status['being_ref'], manifest_hash=status['manifest_hash'],
        origin=origin, evaluated_at_ms=100, credential_ref='credential:eko',
        incarnation_authorization_ref='authorization:eko', body={**origin, 'state': 'running'},
        heads={'private': 'excluded'}, effective={'private': 'excluded'}, body_capabilities=['excluded'])
    return dict(ok=True, server=origin, result=scope), status, origin


def test_current_identity_projection_excludes_ledger_and_capability_data():
    response, status, origin = identity_fixture()
    result = receiving_identity(response, status, origin)
    assert result['credential_ref'] == 'credential:eko'
    assert result['incarnation_authorization_ref'] == 'authorization:eko'
    assert not {'body', 'heads', 'effective', 'body_capabilities'} & set(result)
    result['origin']['embodiment_id'] = 'changed'
    assert origin['embodiment_id'] == 'body:eko'


def test_source_identity_does_not_invent_a_cluster_admission_requirement():
    response, status, origin = identity_fixture()
    response['result']['body'] = None
    assert receiving_identity(response, status, origin, require_admitted=False)['origin'] == origin
    with pytest.raises(OnboardingError, match='receiving_identity_admission_conflict'):
        receiving_identity(response, status, origin)


@pytest.fixture(params=[False, True], ids=['v1', 'v2-until-revoked'])
def signed_receiving_identity(tmp_path, request):
    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix.weave import BeingManifest
    from tests.test_onboarding_target import receiving
    ceremony, plan, target = receiving(tmp_path)
    target.activate(ceremony.authorize_target(plan, target.prepare()))
    if request.param:
        target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
    bundle = target.document_bundle()
    # Receiving runtime bundle hashing uses Matrix's Unicode canonical codec,
    # not the separate Cluster operation digest codec.
    bundle['ledger'] = 'mémoire-synthétique.sqlite3'
    origin = bundle['local_origin']
    manifest = bundle['manifest']
    member = next(row for row in manifest['embodiments'] if
                  (row['embodiment_id'], row['incarnation_id']) ==
                  (origin['embodiment_id'], origin['incarnation_id']))
    identity = dict(being_ref=manifest['being_ref'], manifest_hash=BeingManifest.from_value(manifest).digest,
        origin=origin, credential_ref=member['embodiment_credential_id'],
        incarnation_authorization_ref=member['incarnation_authorization_id'])
    observed = dict(server=origin, process={'pid': os.getpid()}, identity=identity,
        runtime_status=dict(being_ref=identity['being_ref'], manifest_hash=identity['manifest_hash'],
            local_origin=origin, loaded_runtime=dict(runtime_bundle_sha256=hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
                process_id=os.getpid(), runtime_id=bundle['runtime_id'], local_origin=origin)))
    return bundle, observed


def test_signed_public_bundle_current_validity_without_loading_custody(signed_receiving_identity, monkeypatch):
    from daimon_matrix.canonical import canonical_bytes
    bundle, observed = signed_receiving_identity
    horizon = time.time_ns() // 1_000_000 + 300000
    result = verify_receiving_identity(bundle, observed, expires_at_ms=horizon)
    assert result['identity'] == observed['identity']
    assert result['runtime_bundle_sha256'] == hashlib.sha256(canonical_bytes(bundle)).hexdigest()
    assert 0 < result['expires_at_ms'] <= horizon
    assert not {'signing_key', 'credentials', 'capabilities', 'keystore'} & set(result)
    for fields in (('identity', 'origin'), ('runtime_status', 'local_origin'),
                   ('runtime_status', 'loaded_runtime', 'local_origin')):
        changed = copy.deepcopy(observed)
        row = changed
        for key in fields[:-1]:
            row = row[key]
        row[fields[-1]] = None
        with pytest.raises(OnboardingError, match='loaded_bundle_conflict'):
            verify_receiving_identity(bundle, changed, expires_at_ms=horizon)
    # Verification can consume a short horizon. It must not return expired
    # evidence merely because the initial clock sample was still valid.
    from clusterctl import onboarding_receiving_update as updates
    from types import SimpleNamespace
    instants = iter((result['verified_at_ms'], horizon + 1))
    monkeypatch.setattr(updates, 'time', SimpleNamespace(time_ns=lambda: next(instants) * 1_000_000))
    with pytest.raises(OnboardingError, match='horizon_expired'):
        verify_receiving_identity(bundle, observed, expires_at_ms=horizon)


def test_reselected_public_bundle_is_not_the_loaded_identity(signed_receiving_identity):
    bundle, observed = signed_receiving_identity
    bundle['runtime_label'] = 'another-selected-label'
    with pytest.raises(OnboardingError, match='loaded_bundle_conflict'):
        verify_receiving_identity(bundle, observed, expires_at_ms=time.time_ns() // 1_000_000 + 300000)


def test_current_validity_uses_the_actual_signed_lifetime(signed_receiving_identity, monkeypatch):
    from clusterctl import onboarding_receiving_update as updates
    from types import SimpleNamespace
    bundle, observed = signed_receiving_identity
    credential = next(row for row in bundle['credentials']
                      if row['artifact_id'] == observed['identity']['credential_ref'])
    if 'validity' in credential['body']:
        assert credential['body']['validity']['mode'] == 'until-revoked'
        later = time.time_ns() // 1_000_000 + 3600000
        monkeypatch.setattr(updates, 'time', SimpleNamespace(time_ns=lambda: later * 1_000_000))
        verified = verify_receiving_identity(bundle, observed, expires_at_ms=later + 1000)
        assert verified['credential_validity']['mode'] == 'until-revoked'
        assert verified['expires_at_ms'] == later + 1000
    else:
        expired = credential['body']['valid_until_ms'] + 1
        monkeypatch.setattr(updates, 'time', SimpleNamespace(time_ns=lambda: expired * 1_000_000))
        # The original first-body credential ends at the protocol's maximum
        # instant; its successor request is then outside the finite time domain.
        error = 'horizon_expired' if expired + 1000 >= 2**53 else 'public_verification_failed'
        with pytest.raises(OnboardingError, match=error):
            verify_receiving_identity(bundle, observed, expires_at_ms=expired + 1000)


@pytest.mark.parametrize('part', ['server', 'origin', 'being_ref', 'manifest_hash', 'body',
                                  'credential_ref', 'incarnation_authorization_ref', 'evaluated_at_ms'])
def test_identity_projection_refuses_unbound_or_missing_current_admission(part):
    response, status, origin = identity_fixture()
    response = copy.deepcopy(response)
    if part == 'server':
        response['server']['embodiment_id'] = 'another-body'
    elif part == 'body':
        response['result']['body']['state'] = 'stopped'
    elif part == 'evaluated_at_ms':
        response['result'][part] = True
    else:
        response['result'][part] = None
    with pytest.raises(OnboardingError, match='receiving_identity_admission_conflict'):
        receiving_identity(response, status, origin)


class FakeOwner:
    def __init__(self, root, name):
        self.root = root
        self.socket = root / 'tribe.sock'
        self.requests = {}
        self.effects = 0
        self.process = dict(uid=1, pid=2, start_ticks=3, boot_id='fixture')
        self.being = 'being:' + name
        self.server = dict(embodiment_id='body:' + name)
        self.gate = dict(process_instance_id=name, process_id=2, channel_id='tribe',
            controlled=True, context_sha256='a'*64, head='b'*64, phase='unselected',
            operation_id=None, release_digest=None, request_sha256=None, readers=[])

    def status(self):
        return copy.deepcopy(dict(process=self.process, server=self.server, gate=self.gate,
            runtime_status={'being_ref': self.being, 'local_origin': self.server,
                'loaded_application': {'tribe': {'policy': {'tribe_ref': 'tribe:fixture'}}}}))

    def prepare_control(self, command, path):
        if path in self.requests:
            assert self.requests[path] == command
        else:
            self.requests[path] = copy.deepcopy(command)
            path.parent.mkdir(mode=0o700, exist_ok=True)
            being_seed._write(path, {'command': command})

    def apply_control(self, path):
        command = self.requests[path]
        request = digest(command)
        if self.gate['request_sha256'] != request:
            assert self.gate['head'] == command['expected_head']
            self.effects += 1
            self.gate = {**self.gate, **{k: v for k, v in command.items() if k != 'expected_head'},
                'head': digest([self.gate['head'], request]), 'request_sha256': request}
        return {**self.status(), 'request_sha256': request, 'request_id': request,
                'command_sha256': digest(command)}


def test_guest_owner_adapter_keeps_private_request_paths_receiving_local(monkeypatch):
    from types import SimpleNamespace
    from tests.test_onboarding import plan
    calls = []
    root = Path('/not-mounted-on-host/receiving/runtime')
    origin = dict(body_ref='body:eko', embodiment_id='embodiment:eko', incarnation_id='incarnation:eko')
    gate = dict(controlled=True, process_id=123, phase='revoke', head='a'*64)
    loaded = dict(process_id=123, local_origin=origin)
    status = dict(local_origin=origin, loaded_runtime=loaded, loaded_application={'view':'fixture'},
                  receiving={'channels':{'tribe':gate}})
    def call(_plan, action, **arguments):
        calls.append((action, arguments))
        if action == 'admitted-running':
            return dict(responder_association='same-connection', admission_parent={'pid':122},
                group={'socket':str(root/'tribe.sock')}, group_runtime_status=status,
                runtime_status={'loaded_runtime':loaded}, process={'pid':123}, origin=origin)
        return dict(request_sha256='b'*64)
    native_exists = Path.exists
    def no_host_private_access(path):
        if path == root or root in path.parents:
            pytest.fail('host inspected a guest-private path')
        return native_exists(path)
    monkeypatch.setattr(Path, 'exists', no_host_private_access)
    guest = GuestGroupClient(SimpleNamespace(_target_call=call), plan(), (Path('/candidate'),'c'*64), root=root)
    assert guest.status()['server'] == origin
    private = root/'receiving-control'/'request.json'
    assert guest.prepare_control({'phase':'revoke','readers':[]}, private)['request_sha256'] == 'b'*64
    assert guest.apply_control(private)['request_sha256'] == 'b'*64
    assert [action for action,_ in calls] == ['admitted-running','receiving-control-prepare','receiving-control-apply']
    assert calls[1][1]['control_value'] == {'phase':'revoke','readers':[]}
    assert all(options['observation_timeout_seconds'] == 30 for _,options in calls)


def test_late_durable_prepare_keeps_exact_request_without_reporting_success(tmp_path, monkeypatch):
    from clusterctl import onboarding_receiving_update as module
    root = tmp_path/'owner'
    root.mkdir(mode=0o700)
    clock = [10]
    monkeypatch.setattr(module.time,'monotonic_ns',lambda:clock[0])
    owner = OwnerGroupClient(root, root/'tribe.sock', deadline_ns=100)
    command = dict(channel_id='tribe',process_instance_id='fixture',expected_head='a'*64,phase='revoke')
    monkeypatch.setattr(owner,'status',lambda:dict(gate={'process_instance_id':'fixture','head':'a'*64},process={},server={}))
    authored = []
    class Client:
        def prepare(self, method, params):
            authored.append(True)
            return dict(method=method,params=params,request_id='one-retained-request')
    monkeypatch.setattr(owner,'_client',lambda _role:Client())
    durable = owner._durable_control
    def late(path):
        durable(path)
        clock[0]=101
    monkeypatch.setattr(owner,'_durable_control',late)
    private = root/'receiving-control'/'revoke.json'
    with pytest.raises(OnboardingError,match='deadline_expired'):
        owner.prepare_control(command,private)
    retained = private.read_bytes()
    owner.deadline_ns=200
    assert owner.prepare_control(command,private)['request_id'] == 'one-retained-request'
    assert private.read_bytes() == retained and authored == [True]


def fixture(tmp_path):
    path, original, runtime, _old_journal, _identifier = host_fixture(tmp_path)
    owners = {}
    for name in ('eko', 'oliva'):
        root = tmp_path / name
        root.mkdir(mode=0o700)
        owners[name] = FakeOwner(root, name)
    senders = freeze_senders(owners, tribe_ref='tribe:fixture')
    journal = OperationJournal(tmp_path / 'cohort-journal')
    row = plan_update(journal, manifest_digest='a'*64, target='receiving:tribe-fixture',
        expected_precondition=dict(host_config=str(path), host_configuration=original,
            host_config_sha256=digest(original), senders=senders),
        intended_transition={'host_runtime': runtime}, audit_identity={'actor': 'fixture'})
    return path, original, runtime, owners, journal, row['operation_id']


@pytest.mark.parametrize('part', ['being_ref', 'local_origin'])
def test_frozen_sender_identity_requires_the_authenticated_status_binding(tmp_path, monkeypatch, part):
    root = tmp_path / 'owner'
    root.mkdir(mode=0o700)
    owner = FakeOwner(root, 'source')
    status = owner.status()
    status['runtime_status'][part] = None if part == 'being_ref' else {'embodiment_id': 'another-body'}
    monkeypatch.setattr(owner, 'status', lambda: status)
    with pytest.raises(OnboardingError, match='owner_identity_conflict'):
        freeze_senders({'source': owner}, tribe_ref='tribe:fixture')
    assert owner.effects == 0 and owner.requests == {}


def test_incomplete_barrier_and_direct_selector_bypass_have_no_file_effect(tmp_path):
    path, original, _, owners, journal, identifier = fixture(tmp_path)
    controller = CohortController(journal, identifier, owners)
    with pytest.raises(OnboardingError, match='barrier_incomplete'):
        controller.apply_host_selection(path)
    with pytest.raises(OnboardingError, match='barrier_required'):
        apply_host_selection(journal, identifier, path)
    assert being_seed._read(path) == original
    assert journal.get(identifier)['state'] == 'planned'
    assert all(owner.effects == 0 for owner in owners.values())


def test_all_frozen_revocations_precede_actual_selector_and_exact_retry(tmp_path):
    path, original, runtime, owners, journal, identifier = fixture(tmp_path)
    controller = CohortController(journal, identifier, owners)
    barrier = controller.revoke_senders()
    assert set(barrier['sender_revocations']) == set(owners)
    assert being_seed._read(path) == original
    assert all(owner.effects == 1 for owner in owners.values())
    assert controller.apply_host_selection(path)['selected']
    assert being_seed._read(path) == {**original, **runtime}
    assert controller.revoke_senders() == barrier
    assert controller.apply_host_selection(path)['selected']
    assert all(owner.effects == 1 for owner in owners.values())
    assert set(journal.get(identifier)['runtime_observation']) == {'sender_revocations', 'host_selection'}


def test_partial_revocation_loss_resumes_without_repeating_the_first_effect(tmp_path, monkeypatch):
    path, original, _, owners, journal, identifier = fixture(tmp_path)
    controller = CohortController(journal, identifier, owners)
    apply = owners['oliva'].apply_control
    lost = True
    def lose_reply(path):
        nonlocal lost
        result = apply(path)
        if lost:
            lost = False
            raise OSError('synthetic control reply lost after effect')
        return result
    monkeypatch.setattr(owners['oliva'], 'apply_control', lose_reply)
    with pytest.raises(OSError):
        controller.revoke_senders()
    assert set(journal.get(identifier)['runtime_observation']['sender_revocations']) == {'eko'}
    assert all(owner.effects == 1 for owner in owners.values())
    assert being_seed._read(path) == original
    with pytest.raises(OnboardingError, match='barrier_incomplete'):
        controller.apply_host_selection(path)
    restored = CohortController(journal, identifier, owners)
    restored.revoke_senders()
    assert all(owner.effects == 1 for owner in owners.values())
    assert restored.apply_host_selection(path)['selected']


@pytest.mark.parametrize('changed', ['process', 'gate', 'readers'])
def test_durable_old_ack_cannot_pass_a_changed_current_sender(tmp_path, changed):
    path, original, _, owners, journal, identifier = fixture(tmp_path)
    controller = CohortController(journal, identifier, owners)
    controller.revoke_senders()
    if changed == 'process':
        owners['eko'].process['start_ticks'] += 1
    elif changed == 'gate':
        owners['eko'].gate['head'] = 'f'*64
    else:
        owners['eko'].gate['readers'] = [{'fixture': 'enabled'}]
    with pytest.raises(OnboardingError, match='barrier_changed'):
        controller.apply_host_selection(path)
    assert being_seed._read(path) == original


def test_another_owner_locator_cannot_rebind_the_frozen_sender_vector(tmp_path):
    path, original, _, owners, journal, identifier = fixture(tmp_path)
    owners['eko'].socket = Path('/other/tribe.sock')
    with pytest.raises(OnboardingError, match='vector_invalid'):
        CohortController(journal, identifier, owners).revoke_senders()
    assert being_seed._read(path) == original
    assert all(owner.effects == 0 for owner in owners.values())


@pytest.mark.parametrize('failed_directory', ['control', 'root'])
def test_failed_request_publication_is_completed_before_native_control(tmp_path, monkeypatch, failed_directory):
    """Fault actual fsync after rename; fake RPC distinguishes effect ordering."""
    from daimon_matrix.local_api import request_hash
    root = tmp_path / 'owner'
    root.mkdir(mode=0o700)
    owner = OwnerGroupClient(root, root / 'tribe.sock')
    path = root / 'receiving-control' / 'revoke.json'
    command = dict(channel_id='tribe', process_instance_id='fixture', expected_head='b'*64,
                   phase='revoke', operation_id='fixture', release_digest='a'*64, readers=[])
    gate = dict(command, head=command['expected_head'], request_sha256=None)
    calls = []
    prepared = []
    monkeypatch.setattr(owner, 'status', lambda: dict(gate=copy.deepcopy(gate), process={}, server={}))

    class FakeClient:
        def prepare(self, method, params):
            prepared.append(True)
            return dict(method=method, params=params, request_id='fixture-request')

        def send(self, request):
            calls.append(request)
            gate['request_sha256'] = request_hash(request)
            return {'ok': True}

    monkeypatch.setattr(owner, '_client', lambda role: FakeClient())
    actual_sync = os.fsync
    fault = True
    syncs = []
    target = path.parent if failed_directory == 'control' else root

    def fail_sync(descriptor):
        location = os.readlink('/proc/self/fd/' + str(descriptor))
        syncs.append(location)
        if location == str(target) and fault:
            raise OSError('synthetic directory fsync failure')
        return actual_sync(descriptor)

    monkeypatch.setattr(os, 'fsync', fail_sync)
    with pytest.raises(OSError, match='fsync failure'):
        owner.prepare_control(command, path)
    raw = path.read_bytes()  # Rename happened, but the durable boundary failed.
    with pytest.raises(OSError, match='fsync failure'):
        owner.prepare_control(command, path)
    with pytest.raises(OSError, match='fsync failure'):
        owner.apply_control(path)
    assert not calls and len(prepared) == 1 and path.read_bytes() == raw

    fault = False
    start = len(syncs)
    owner.prepare_control(command, path)
    assert syncs[start:] == [str(path), str(path.parent), str(root)]
    owner.apply_control(path)
    assert len(calls) == 1 and len(prepared) == 1 and path.read_bytes() == raw


@pytest.mark.parametrize('changed', ['none', 'counts', 'process', 'loaded', 'gate'])
def test_owner_adapter_rechecks_actual_loaded_connection_before_control(tmp_path, monkeypatch, changed):
    from clusterctl import onboarding_receiving_update as receiving
    current = dict(process={'pid': 123}, gate={'head': 'original'}, runtime_status={
        'loaded_runtime': {'base': 'actual'}, 'loaded_application': {'view': 'actual'},
        'counts': {'rows': 1}, 'receiving': {'channels': {'tribe': {'head': 'original'}}}})
    observed = dict(process=copy.deepcopy(current['process']),
        runtime_status=copy.deepcopy(current['runtime_status']), responder_association='same-connection')
    calls = []
    class FakeClient:
        def __init__(self, *_):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def status(self):
            return current
        def apply_control(self, path):
            calls.append(path)
            return {'applied': True}
    monkeypatch.setattr(receiving, 'OwnerGroupClient', FakeClient)
    if changed == 'process':
        current['process']['pid'] += 1
    elif changed == 'loaded':
        current['runtime_status']['loaded_application']['view'] = 'other'
    elif changed == 'gate':
        current['gate']['head'] = 'other'
    elif changed == 'counts':
        current['runtime_status']['counts']['rows'] += 1
    group = dict(channel_id='tribe', socket=str(tmp_path / 'tribe.sock'))
    path = tmp_path / 'revoke.json'
    if changed in {'none', 'counts'}:
        assert receiving.owner_control(tmp_path, group, observed, 'receiving-control-apply', path) == {'applied': True}
        assert calls == [path]
    else:
        with pytest.raises(OnboardingError, match='process_changed'):
            receiving.owner_control(tmp_path, group, observed, 'receiving-control-apply', path)
        assert calls == []
