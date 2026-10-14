"""Cohort state-machine faults with fake senders and real selector/journal.

These cases prove durable orchestration, not native RPC or receiving readiness.
Native owner RPC/fence qualification is a separate actual integration boundary.
"""
import copy
import os
from pathlib import Path

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.onboarding_receiving_update import CohortController, OwnerGroupClient, apply_host_selection, freeze_senders
from clusterctl.operation_journal import OperationJournal
from tests.test_receiving_host_selection import fixture as host_fixture


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
