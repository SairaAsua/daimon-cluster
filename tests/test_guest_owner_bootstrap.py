"""Actual native guest publication with explicit group/process observation seams.

Synthetic custody and real encrypted upgrades/files; these do not qualify a
live signed group, actual process exit, closed installed CLI or systemd.
"""
import copy
import inspect
import json
import os
import time
import tempfile
from pathlib import Path
import uuid

import pytest

from clusterctl import onboarding_receiving_update as receiving_update
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_receiving_update import GuestOwnerBootstrap
from tests.test_onboarding_target import receiving


def deadline():
    return time.monotonic_ns() + 10_000_000_000


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    if 'provision_receiving_controller' not in inspect.signature(upgrade.stage_capabilities).parameters:
        import importlib.metadata
        from clusterctl.onboarding_sdk import MATRIX_COMMIT
        selected = json.loads(importlib.metadata.distribution('daimon-matrix').read_text('direct_url.json'))
        assert selected['vcs_info']['commit_id'] == MATRIX_COMMIT
        pytest.skip('retained legacy SDK has no native optional controller; qualifies with the selected successor SDK')
    assert os.geteuid() == 1000
    ceremony, plan, target = receiving(tmp_path)
    with tempfile.TemporaryDirectory(prefix="dm-owner-") as short:
        from clusterctl.onboarding_target import Target
        target = Target(Path(short), plan, target.genesis)
        target.activate(ceremony.authorize_target(plan, target.prepare()))
        target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
        root = target.package / 'runtime'
        group = dict(selected=dict(channel_id='tribe', socket=str(root / 'tribe.sock')),
            hashes={'application': 'a' * 64, 'selection': 'b' * 64})
        monkeypatch.setattr(receiving_update, 'bootstrap_group', lambda *_args, **_kwargs: copy.deepcopy(group))
        exited = [True]
        monkeypatch.setattr('clusterctl.owner_process.observe_process_exit', lambda _: exited[0])
        process = dict(uid=1000, pid=123, start_ticks=5, boot_id=str(uuid.uuid4()))
        request = dict(schema='cluster-guest-owner-bootstrap/v1', operation_id=str(uuid.uuid4()),
            plan_digest=digest(plan), genesis_digest=digest(target.genesis), code_digest=target.code_digest,
            runtime_sha256=digest(target.document_bundle()), group_sha256=digest(group),
            predecessor=dict(process=process, admission_parent={**process, 'pid': 122, 'start_ticks': 4}),
            expires_at_ms=time.time_ns() // 1_000_000 + 3600000)
        yield target, request, group, exited

def files(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob('*')
            if path.is_file() and path.name != 'lock'}


def test_native_stage_and_publication_retain_identity_history_and_exact_retry(fixture):
    target, request, group, _ = fixture
    old = target.observe()
    history = files(target.credential)
    current = target.document_bundle()
    owner = GuestOwnerBootstrap(target, request)
    ready = owner.execute('stage', deadline_ns=deadline())
    assert target.document_bundle() == current and target.observe() == old
    assert owner.execute('stage', deadline_ns=deadline()) == ready
    receipt = owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256'])
    observed = target.observe()
    assert observed['receipt'] == old['receipt'] and observed['phase'] == old['phase']
    assert observed['receiving_controller']['runtime_sha256'] == receipt['runtime_sha256']
    assert receipt['counter_after'] == current['keystore']['counter'] + 1
    assert receipt['receiving_readiness'] == 'unobserved' and files(target.credential) == history
    assert receiving_update.bootstrap_group(target, target.document_bundle()) == group
    ciphertext = (owner.runtime / 'custody.json').read_bytes()
    assert owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256']) == receipt
    assert (owner.runtime / 'custody.json').read_bytes() == ciphertext


@pytest.mark.parametrize('phase', ['stage', 'publish'])
def test_native_effect_lost_reply_resumes_without_reissuing_keys(fixture, monkeypatch, phase):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    target, request, _, _ = fixture
    owner = GuestOwnerBootstrap(target, request)
    ready = None if phase == 'stage' else owner.execute('stage', deadline_ns=deadline())
    name = 'stage_capabilities' if phase == 'stage' else 'publish'
    actual, calls = getattr(upgrade, name), []
    def lost(**kwargs):
        result = actual(**kwargs)
        calls.append(result)
        if len(calls) == 1:
            raise OSError('synthetic lost native reply after effect')
        return result
    monkeypatch.setattr(upgrade, name, lost)
    options = {} if ready is None else {'ready_sha256': ready['ready_sha256']}
    with pytest.raises(OSError):
        owner.execute(phase, deadline_ns=deadline(), **options)
    ciphertext = ((owner.transaction / 'successor' / 'custody.json') if phase == 'stage'
                  else owner.runtime / 'custody.json').read_bytes()
    result = GuestOwnerBootstrap(target, request).execute(phase, deadline_ns=deadline(), **options)
    assert result['receiving_readiness'] == 'unobserved'
    assert len(calls) == (1 if phase == 'stage' else 2)
    assert ((owner.transaction / 'successor' / 'custody.json') if phase == 'stage'
            else owner.runtime / 'custody.json').read_bytes() == ciphertext


def test_actual_partial_unpublished_stage_is_archived_before_retry(fixture, monkeypatch):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    target, request, _, _ = fixture
    owner = GuestOwnerBootstrap(target, request)
    original = files(owner.runtime)
    write = upgrade._write
    def partial(path, raw):
        if path.name == 'ready.json':
            raise OSError('synthetic failed final staged write')
        return write(path, raw)
    with monkeypatch.context() as fault:
        fault.setattr(upgrade, '_write', partial)
        with pytest.raises(OSError):
            owner.execute('stage', deadline_ns=deadline())
    unfinished = upgrade.inventory_digest(owner.transaction)
    ready = owner.execute('stage', deadline_ns=deadline())
    records = owner._observations()
    archive = records['capability_archive_0_retained']
    assert archive['sha256'] == unfinished
    assert upgrade.inventory_digest(Path(archive['path'])) == unfinished
    assert files(owner.runtime) == original
    owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256'])


def test_still_live_predecessor_and_changed_request_or_group_cannot_publish(fixture):
    target, request, group, exited = fixture
    owner = GuestOwnerBootstrap(target, request)
    original = files(owner.runtime)
    exited[0] = False
    with pytest.raises(OnboardingError, match='exit_required'):
        owner.execute('stage', deadline_ns=deadline())
    assert files(owner.runtime) == original and not owner.transaction.exists()
    exited[0] = True
    group['hashes']['selection'] = 'c' * 64
    with pytest.raises(OnboardingError, match='group_changed'):
        owner.execute('stage', deadline_ns=deadline())
    assert not owner.transaction.exists()
    different = {**request, 'expires_at_ms': request['expires_at_ms'] + 1}
    with pytest.raises(OnboardingError, match='conflict'):
        GuestOwnerBootstrap(target, different).execute('stage', deadline_ns=deadline())
    assert files(owner.runtime) == original


def test_wrong_ready_digest_and_changed_native_source_refuse_without_new_rotation(fixture):
    target, request, _, _ = fixture
    owner = GuestOwnerBootstrap(target, request)
    ready = owner.execute('stage', deadline_ns=deadline())
    ciphertext = (owner.runtime / 'custody.json').read_bytes()
    with pytest.raises(OnboardingError, match='ready_required'):
        owner.execute('publish', deadline_ns=deadline(), ready_sha256='f' * 64)
    assert (owner.runtime / 'custody.json').read_bytes() == ciphertext
    marker = owner.runtime / 'unexpected-native-source'
    marker.write_bytes(b'preserve this intervening writer')
    marker.chmod(0o600)
    with pytest.raises(ValueError):
        owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256'])
    assert marker.read_bytes() == b'preserve this intervening writer'
    assert (owner.runtime / 'custody.json').read_bytes() == ciphertext


def test_late_publication_retains_evidence_for_fresh_bounded_retry(fixture, monkeypatch):
    target, request, _, _ = fixture
    owner = GuestOwnerBootstrap(target, request)
    ready = owner.execute('stage', deadline_ns=deadline())
    record = owner._record
    clock = [1_000_000_000]
    monkeypatch.setattr(time, 'monotonic_ns', lambda: clock[0])
    def late(name, value):
        result = record(name, value)
        if name == 'capability_published':
            clock[0] = 3_000_000_000
        return result
    monkeypatch.setattr(owner, '_record', late)
    with pytest.raises(OnboardingError, match='deadline_expired'):
        owner.execute('publish', deadline_ns=2_000_000_000, ready_sha256=ready['ready_sha256'])
    assert 'capability_published' in owner._observations()
    ciphertext = (owner.runtime / 'custody.json').read_bytes()
    result = GuestOwnerBootstrap(target, request).execute('publish', deadline_ns=4_000_000_000,
        ready_sha256=ready['ready_sha256'])
    assert result == owner._observations()['capability_published']
    assert (owner.runtime / 'custody.json').read_bytes() == ciphertext


@pytest.mark.parametrize('action, extra', [
    ('receiving-bootstrap-freeze', []),
    ('receiving-bootstrap-freeze', ['--bootstrap-timeout-seconds', 'nan']),
    ('receiving-bootstrap-stage', ['--bootstrap-timeout-seconds', '10']),
    ('receiving-bootstrap-publish', ['--bootstrap-timeout-seconds', '10', '--bootstrap-request-json', '{}']),
    ('observe', ['--bootstrap-timeout-seconds', '10']),
])
def test_owner_bootstrap_cli_refuses_invalid_modes_before_owner_state(monkeypatch, capsys, action, extra):
    from clusterctl import onboarding_target
    reads = []
    monkeypatch.setattr('clusterctl.being_seed._read', lambda *_args, **_kwargs: reads.append(True))
    assert onboarding_target.main([action, '--home', '/unused', '--plan', '/unused/plan.json',
        '--genesis', '/unused/genesis.json', '--code', '/unused/code', *extra]) == 1
    assert not reads
    assert json.loads(capsys.readouterr().out) == {'error': 'native_onboarding_target_refused'}


def test_owner_request_cannot_change_binding_or_run_as_root(fixture, monkeypatch):
    target, request, _, _ = fixture
    for key in ('plan_digest', 'genesis_digest', 'code_digest'):
        with pytest.raises(OnboardingError, match='request_required'):
            GuestOwnerBootstrap(target, {**request, key: '0' * 64})
    with monkeypatch.context() as root:
        root.setattr(os, 'geteuid', lambda: 0)
        with pytest.raises(OnboardingError, match='request_required'):
            GuestOwnerBootstrap(target, request)
    assert not (target.root / 'receiving-bootstrap').exists()


def test_predecessor_freeze_uses_actual_base_and_admission_without_group_status(fixture, tmp_path, monkeypatch):
    """Real admitted child/HMAC/base scope; explicit old group restriction seam."""
    from daimon_matrix import client as native_client
    from clusterctl.admission import AdmissionAuthority, AdmissionEndpoint, AdmissionTCPServer, serve_in_thread
    from clusterctl.onboarding_admission import ReceivingHolder, enrollment
    from clusterctl.onboarding_runtime import AdmittedDaemon
    from clusterctl.onboarding_receiving_update import freeze_guest_bootstrap
    from tests.test_admission import _key
    target, _, group, _ = fixture
    # The real first-body ceremony is retained by the owning test fixture.
    from clusterctl.onboarding_custody import FirstCustody
    ceremony = FirstCustody(tmp_path / 'custody', tmp_path / 'custody-grants')
    holder = ReceivingHolder(target)
    registrar = _key(tmp_path / 'host/registrar.pem', 'registrar')
    signer = _key(tmp_path / 'host/authority.pem', 'authority')
    authority = AdmissionAuthority(tmp_path / 'authority', signer=signer,
        holder_registrars={registrar.key_id: registrar.public_key})
    server = AdmissionTCPServer(('127.0.0.1', 0), authority)
    thread = serve_in_thread(server)
    endpoint = AdmissionEndpoint.network('127.0.0.1', server.server_address[1])
    owned = holder.client(endpoint, authority_key_id=signer.key_id, authority_public_key=signer.public_key)
    # Recover the same ceremony through the actual receiving test setup paths.
    # Coordinates come from its signed authority, never a fabricated body scope.
    admitted = AdmittedDaemon(target, owned)
    try:
        owned.enroll(enrollment(target.plan, holder.request(), ceremony.admission_coordinates(target.plan), registrar))
        presence = admitted.start(receive_only=True)
        actual_observe = target.observe
        old = actual_observe()
        selected = group['selected']
        group_socket = target.package / 'runtime/tribe.sock'
        group_socket.write_bytes(b'old group endpoint observation seam')
        group_socket.chmod(0o600)
        monkeypatch.setattr(target, 'observe', lambda: {**actual_observe(), 'group': selected})
        Client = native_client.LocalClient
        queried = []
        class LegacyGroupRestrictedClient:
            __dataclass_fields__ = Client.__dataclass_fields__
            def __init__(self, socket_path, config, **options):
                self.socket_path = socket_path
                self.base = Client(socket_path, config, **options)
            def runtime_status(self):
                if self.socket_path == group_socket:
                    queried.append('group')
                    raise native_client.ClientError('old group profile cannot authenticate status')
                return self.base.runtime_status()
            def scope_me(self):
                return self.base.scope_me()
        monkeypatch.setattr(native_client, 'LocalClient', LegacyGroupRestrictedClient)
        with pytest.raises(native_client.ClientError):
            target.running(admitted=True, deadline_ns=deadline())
        observed = target.running(admitted=True, deadline_ns=deadline(), bootstrap_base_only=True)
        assert observed['process']['pid'] == presence['process']['pid']
        assert observed['admission_parent']['pid'] == os.getpid()
        assert observed['responder_association'] == 'same-connection'
        assert observed['group_runtime_status'] is None and observed['receiving_readiness'] == 'unobserved'
        frozen = freeze_guest_bootstrap(target, deadline_ns=deadline())
        assert frozen['runtime_sha256'] == digest(target.document_bundle())
        assert frozen['predecessor']['process'] == observed['process'] and queried == ['group']
        status = LegacyGroupRestrictedClient.runtime_status
        for field in ('being_ref', 'local_origin'):
            def wrong_identity(self):
                identifier, response = status(self)
                response = copy.deepcopy(response)
                response['result'][field] = 'different authenticated runtime'
                return identifier, response
            with monkeypatch.context() as wrong:
                wrong.setattr(LegacyGroupRestrictedClient, 'runtime_status', wrong_identity)
                with pytest.raises(OnboardingError, match='identity_required'):
                    freeze_guest_bootstrap(target, deadline_ns=deadline())
        assert actual_observe() == old and not (target.root / 'receiving-bootstrap').exists()
    finally:
        admitted.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_bootstrap_base_only_cannot_bypass_qualified_loaded_observation(monkeypatch):
    from types import SimpleNamespace
    from clusterctl.onboarding_target import Target
    target = SimpleNamespace(observe=lambda: pytest.fail('invalid mode accessed custody'))
    for options in ({}, {'admitted': True, 'require_loaded': True}):
        with pytest.raises(OnboardingError, match='invalid_receiving_bootstrap_observation'):
            Target.running(target, bootstrap_base_only=True, **options)
