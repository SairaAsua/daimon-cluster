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

from clusterctl import being_seed
from clusterctl import onboarding_receiving_update as receiving_update
from clusterctl.onboarding import OnboardingError, digest
from daimon_matrix.client import ClientError
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


def initial_request(target, request):
    frozen = receiving_update.freeze_guest_bootstrap(target, deadline_ns=deadline(), initial=True)
    return {**request, **{key: frozen[key] for key in (
        'plan_digest', 'genesis_digest', 'code_digest', 'runtime_sha256', 'group_sha256', 'predecessor')},
        'schema': 'cluster-guest-owner-initial/v1', 'mode': frozen['mode'],
        'preservation': frozen['preservation']}


@pytest.mark.parametrize('action', ['group_relationship', 'group_publication'])
def test_group_owner_routes_take_target_lock_before_native_writer(tmp_path, monkeypatch, action):
    from contextlib import contextmanager
    from clusterctl.onboarding_target import Target
    target = object.__new__(Target)
    target.root, target.package = tmp_path, tmp_path / 'package'
    @contextmanager
    def writer():
        # A separate descriptor must observe the real root lock as held when
        # either supported group route reaches the native-writer boundary.
        with pytest.raises(being_seed.SeedError, match='seed_operation_in_progress'):
            with being_seed._locked(target.root):
                pass
        raise OnboardingError('synthetic_native_entry')
        yield
    monkeypatch.setattr(target, '_runtime_writer', writer)
    value = dict(operation_id=str(uuid.uuid4()), step='synthetic', params={})
    if action == 'group_relationship':
        value['method'] = 'tribe.invite'
    else:
        value.update(action='selection', params={'expected_selection_sha256': None})
    with pytest.raises(OnboardingError, match='synthetic_native_entry'):
        getattr(target, action)(value, authority_closure={})


def test_initial_controller_publication_uses_native_writer_without_fake_predecessor(fixture, monkeypatch):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    target, request, group, _ = fixture
    def no_predecessor(*_args, **_kwargs):
        raise AssertionError('An initial body must not invent a running/exited predecessor')
    monkeypatch.setattr(target, 'running', no_predecessor)
    monkeypatch.setattr('clusterctl.owner_process.observe_process_exit', no_predecessor)
    request = initial_request(target, request)
    assert request['predecessor'] is None and request['group_sha256'] == digest({'group': None})
    owner = GuestOwnerBootstrap(target, request)
    original = target.observe()
    history = files(target.credential)
    key = (owner.runtime / 'client.key').read_bytes()
    counter = target.document_bundle()['keystore']['counter']
    ready = owner.execute('stage', deadline_ns=deadline())
    assert owner.execute('stage', deadline_ns=deadline()) == ready
    actual, calls = upgrade.publish, []
    def lost(**kwargs):
        result = actual(**kwargs)
        calls.append(result)
        if len(calls) == 1:
            raise OSError('synthetic lost initial publication reply')
        return result
    monkeypatch.setattr(upgrade, 'publish', lost)
    with pytest.raises(OSError, match='lost initial publication'):
        owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256'])
    ciphertext = (owner.runtime / 'custody.json').read_bytes()
    result = GuestOwnerBootstrap(target, request).execute('publish', deadline_ns=deadline(),
        ready_sha256=ready['ready_sha256'])
    observed = target.observe()
    assert result['counter_after'] == counter + 1
    assert observed['receiving_controller']['runtime_sha256'] == result['runtime_sha256']
    assert observed['receipt'] == original['receipt'] and observed.get('group') is None
    assert (owner.runtime / 'custody.json').read_bytes() == ciphertext
    assert (owner.runtime / 'client.key').read_bytes() == key and files(target.credential) == history
    assert not any(name.endswith('_exited') for name in owner._observations())
    assert result['receiving_readiness'] == 'unobserved'
    with pytest.raises(OnboardingError, match='initial_required'):
        receiving_update.freeze_guest_bootstrap(target, deadline_ns=deadline(), initial_service=True)
    # Native controller/custody are genuine; the selected group/publication is
    # an explicit seam here, qualified independently by the group selector tests.
    monkeypatch.setattr('clusterctl.onboarding_peer.observed_group',
        lambda *_args, **_kwargs: copy.deepcopy(group['selected']))
    frozen = receiving_update.freeze_guest_bootstrap(target, deadline_ns=deadline(), initial_service=True)
    assert frozen['predecessor'] is None and frozen['group'] == group
    assert frozen['group_sha256'] == digest(group) and frozen['runtime_sha256'] == result['runtime_sha256']
    assert frozen['mode'] == 'preserve' and frozen['preservation']['active'] is True
    assert (owner.runtime / 'custody.json').read_bytes() == ciphertext
    with target._runtime_writer():
        with pytest.raises(BlockingIOError):
            receiving_update.freeze_guest_bootstrap(target, deadline_ns=deadline(), initial_service=True)
    with pytest.raises(OnboardingError, match='invalid_receiving_bootstrap_request'):
        receiving_update.freeze_guest_bootstrap(target, deadline_ns=deadline(), initial=True, initial_service=True)


def test_schema_phase_uses_post_controller_context_and_does_not_republish_it(fixture):
    from daimon_matrix import operator_communication_migration as migration
    target, request, _group, _ = fixture
    initial = initial_request(target, request)
    owner = GuestOwnerBootstrap(target, initial)
    identifier = str(uuid.uuid4())
    preview_request = dict(operation_id=identifier, step='context', action='context-preview', params={})
    before = target.group_publication(preview_request, authority_closure={})
    ready = owner.execute('stage', deadline_ns=deadline())
    owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256'])
    after = target.group_publication(preview_request, authority_closure={})
    assert before['owner_context_sha256'] != after['owner_context_sha256']
    request = dict(operation_id=identifier, step='communication-prepare', action='communication-prepare',
        params=dict(expected_plan_sha256=after['communication_plan']['plan_sha256'],
            expires_at_ms=initial['expires_at_ms']))
    options = dict(authority_closure={}, expected_context_sha256=after['owner_context_sha256'])
    with pytest.raises(OnboardingError, match='owner_context_conflict'):
        target.group_publication(request, **{**options, 'expected_context_sha256':before['owner_context_sha256']})
    publication = (owner.records/'capability_published.json').read_bytes()
    native = {name:(owner.runtime/name).read_bytes() for name in ('runtime.json', 'custody.json')}
    ledger = owner.runtime/target.document_bundle()['ledger']
    identity = (ledger.stat().st_dev, ledger.stat().st_ino)
    result = target.group_publication(request, **options)
    assert result['migration']['target_version'] == migration.plan(ledger)['source_version'] == 4
    assert target.group_publication(request, **options) == result
    assert (ledger.stat().st_dev, ledger.stat().st_ino) == identity
    assert (owner.records/'capability_published.json').read_bytes() == publication
    assert all((owner.runtime/name).read_bytes() == raw for name,raw in native.items())


@pytest.mark.parametrize('committed', [False, True])
def test_expired_initial_publication_allows_only_exact_committed_recovery(fixture, monkeypatch, committed):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    target, request, _, _ = fixture
    request = initial_request(target, request)
    owner = GuestOwnerBootstrap(target, request)
    ready = owner.execute('stage', deadline_ns=deadline())
    counter = target.document_bundle()['keystore']['counter']
    if committed:
        actual = upgrade.publish
        def lost(**kwargs):
            actual(**kwargs)
            raise OSError('synthetic lost committed initial publication')
        with monkeypatch.context() as effect:
            effect.setattr(upgrade, 'publish', lost)
            with pytest.raises(OSError, match='lost committed'):
                owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256'])
    ciphertext = (owner.runtime / 'custody.json').read_bytes()
    original_request = (owner.records / 'request.json').read_bytes()
    monkeypatch.setattr(time, 'time_ns', lambda: (request['expires_at_ms'] + 1) * 1_000_000)
    if committed:
        result = owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256'])
        assert result['counter_after'] == counter + 1
    else:
        with pytest.raises(upgrade.UpgradeError, match='expired|expiry'):
            owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256'])
    assert (owner.runtime / 'custody.json').read_bytes() == ciphertext
    assert (owner.records / 'request.json').read_bytes() == original_request
    assert target.document_bundle()['keystore']['counter'] == counter + int(committed)


def test_first_service_freeze_requires_a_prepared_native_controller(fixture, monkeypatch):
    target, _, group, _ = fixture
    monkeypatch.setattr('clusterctl.onboarding_peer.observed_group',
        lambda *_args, **_kwargs: copy.deepcopy(group['selected']))
    before = files(target.package / 'runtime')
    with pytest.raises(OnboardingError, match='initial_controller_required'):
        receiving_update.freeze_guest_bootstrap(target, deadline_ns=deadline(), initial_service=True)
    assert files(target.package / 'runtime') == before


def test_initial_controller_refuses_an_existing_writer_or_group(fixture, monkeypatch):
    target, request, _, _ = fixture
    request = initial_request(target, request)
    owner = GuestOwnerBootstrap(target, request)
    with target._runtime_writer():
        with pytest.raises(BlockingIOError):
            receiving_update.freeze_guest_bootstrap(target, deadline_ns=deadline(), initial=True)
        with pytest.raises(BlockingIOError):
            owner.execute('stage', deadline_ns=deadline())
    assert not owner.transaction.exists()
    # A verified selection appearing after the frozen absence must not become
    # an initial bootstrap. Its signature validation is owned by observed_group.
    monkeypatch.setattr('clusterctl.onboarding_peer.observed_group', lambda *_args, **_kwargs: {'channel_id': 'tribe'})
    with pytest.raises(OnboardingError, match='initial_required'):
        receiving_update.freeze_guest_bootstrap(target, deadline_ns=deadline(), initial=True)
    with pytest.raises(OnboardingError, match='group_changed'):
        owner.execute('stage', deadline_ns=deadline())
    assert not owner.transaction.exists()
    with pytest.raises(OnboardingError, match='request_required'):
        GuestOwnerBootstrap(target, {**request, 'group_sha256': 'f' * 64})
    with pytest.raises(OnboardingError, match='request_required'):
        GuestOwnerBootstrap(target, {**request, 'schema': 'cluster-guest-owner-bootstrap/v1'})


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
        monkeypatch.setattr(target, 'observe', lambda: pytest.fail(
            'read-only predecessor observation reopened birth/custody or archived pairs'))
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
                with pytest.raises(OnboardingError, match='^receiving_identity_admission_conflict$'):
                    freeze_guest_bootstrap(target, deadline_ns=deadline())
        scope = LegacyGroupRestrictedClient.scope_me
        for field in ('credential_ref', 'incarnation_authorization_ref'):
            def wrong_credential(self):
                identifier, response = scope(self)
                response = copy.deepcopy(response)
                response['result'][field] = 'different-current-credential'
                return identifier, response
            with monkeypatch.context() as wrong:
                wrong.setattr(LegacyGroupRestrictedClient, 'scope_me', wrong_credential)
                with pytest.raises(OnboardingError, match='^receiving_identity_public_binding_conflict$'):
                    freeze_guest_bootstrap(target, deadline_ns=deadline())
        config = target.package/'runtime/client.json'
        original = config.read_bytes()
        def replace_client(self):
            result = scope(self)
            config.write_bytes(original+b'\n')
            return result
        try:
            with monkeypatch.context() as changed:
                changed.setattr(LegacyGroupRestrictedClient, 'scope_me', replace_client)
                with pytest.raises(OnboardingError, match='^receiving_bootstrap_public_preimage_changed$'):
                    freeze_guest_bootstrap(target, deadline_ns=deadline())
        finally:
            config.write_bytes(original)
        binding = target.root/'plan.json'
        original_binding = binding.read_bytes()
        try:
            being_seed._write(binding, {**target._binding(), 'genesis_digest': '0'*64})
            with pytest.raises(OnboardingError, match='^onboarding_target_binding_conflict$'):
                target.running(admitted=True, deadline_ns=deadline(), bootstrap_base_only=True)
        finally:
            binding.write_bytes(original_binding)
        bundle = target.document_bundle()
        def different_loaded_bundle(self):
            identifier, response = status(self)
            response = copy.deepcopy(response)
            response['result']['loaded_runtime'] = dict(process_id=observed['process']['pid'],
                runtime_bundle_sha256='0'*64, runtime_id=bundle['runtime_id'],
                local_origin=bundle['local_origin'])
            return identifier, response
        with monkeypatch.context() as changed:
            changed.setattr(LegacyGroupRestrictedClient, 'runtime_status', different_loaded_bundle)
            with pytest.raises(OnboardingError, match='^onboarding_loaded_base_conflict$'):
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


@pytest.fixture
def preserved_fixture(fixture):
    target, request, group, exited = fixture
    first = GuestOwnerBootstrap(target, request)
    ready = first.execute('stage', deadline_ns=deadline())
    first.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256'])
    request = {**request, 'operation_id': str(uuid.uuid4()), 'mode': 'preserve',
        'runtime_sha256': digest(target.document_bundle()),
        'preservation': receiving_update.controller_preservation(first.runtime, target.document_bundle()),
        'expires_at_ms': time.time_ns() // 1_000_000 + 60000}
    return target, request, group, exited


@pytest.fixture
def expired_fixture(preserved_fixture):
    """An authentic old short-lived controller; original owner grants are live."""
    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix.keystore import EncryptedKeystore
    from daimon_matrix.local_api import create_capability
    from daimon_matrix.operator_capabilities import create_operator_capability_binding
    target, request, group, exited = preserved_fixture
    root = target.package / 'runtime'
    bundle = target.document_bundle()
    custody = EncryptedKeystore(root / 'custody.json').open(target._reader)
    row = next(row for row in bundle['capabilities'] if row['profile']['role'] == 'receiving-controller')
    now = time.time_ns() // 1_000_000
    previous = row['descriptor']
    capability = create_capability(custody.secrets[row['secret_slot']],
        **{key: previous[key] for key in ('client_id', 'methods', 'status')},
        not_before_ms=now - 120000, not_after_ms=now - 60000)
    row['descriptor'] = capability.descriptor
    client = root / row['profile']['client_directory'] / row['profile']['client_config_filename']
    config = json.loads(client.read_bytes())
    config['capability'] = capability.descriptor
    client.write_bytes(canonical_bytes(config))
    bundle['operator_capability_binding'] = create_operator_capability_binding(
        runtime_id=bundle['runtime_id'], runtime_label=bundle['runtime_label'],
        being_ref=bundle['manifest']['being_ref'], origin=bundle['local_origin'],
        signing_seed=custody.secrets[bundle['keystore']['signing_slot']], capability_rows=bundle['capabilities'])
    (root / 'runtime.json').write_bytes(canonical_bytes(bundle))
    request = {**request, 'operation_id': str(uuid.uuid4()), 'mode': 'renew',
        'runtime_sha256': digest(bundle), 'preservation': receiving_update.controller_preservation(root, bundle)}
    return target, request, group, exited


def test_expired_native_controller_renews_once_without_new_identity_or_history(expired_fixture, monkeypatch):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    from daimon_matrix.keystore import EncryptedKeystore
    target, request, _, _ = expired_fixture
    root = target.package / 'runtime'
    original, history = target.document_bundle(), files(target.credential)
    keys = EncryptedKeystore(root / 'custody.json').open(target._reader).secrets
    assert receiving_update.controller_bootstrap_mode(original, request['preservation']) == 'renew'
    owner = GuestOwnerBootstrap(target, request)
    ready = owner.execute('stage', deadline_ns=deadline())
    assert target.document_bundle() == original and owner.execute('stage', deadline_ns=deadline()) == ready
    actual = upgrade.publish
    def lost(**kwargs):
        actual(**kwargs)
        raise OSError('synthetic lost renewal publication reply')
    with monkeypatch.context() as fault:
        fault.setattr(upgrade, 'publish', lost)
        with pytest.raises(OSError, match='lost renewal'):
            owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256'])
    ciphertext = (root / 'custody.json').read_bytes()
    result = GuestOwnerBootstrap(target, request).execute('publish', deadline_ns=deadline(),
        ready_sha256=ready['ready_sha256'])
    current = target.document_bundle()
    assert current['keystore']['counter'] == original['keystore']['counter'] + 1
    assert current['capabilities'][:-1] == original['capabilities'][:-1]
    assert current['capabilities'][-1]['secret_slot'] == original['capabilities'][-1]['secret_slot']
    assert current['capabilities'][-1]['descriptor']['not_after_ms'] > request['expires_at_ms']
    assert EncryptedKeystore(root / 'custody.json').open(target._reader).secrets == keys
    assert files(target.credential) == history and (root / 'custody.json').read_bytes() == ciphertext
    assert target.observe()['receiving_controller']['counter'] == result['counter_after']
    assert result['receiving_readiness'] == 'unobserved'
    assert receiving_update.controller_bootstrap_mode(current,
        receiving_update.controller_preservation(root, current)) == 'preserve'
    assert owner.execute('publish', deadline_ns=deadline(), ready_sha256=ready['ready_sha256']) == result


def test_renewal_preflight_refuses_legacy_sdk_or_an_expired_owner_horizon(expired_fixture, monkeypatch):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    target, request, _, _ = expired_fixture
    bundle = target.document_bundle()
    before = files(target.package / 'runtime')
    with monkeypatch.context() as old:
        old.setattr(upgrade, 'stage_capabilities', lambda **_kwargs: None)
        with pytest.raises(OnboardingError, match='qualified_controller_renewal_sdk_required'):
            receiving_update.controller_bootstrap_mode(bundle, request['preservation'])
    original = next(row for row in bundle['capabilities'] if row['profile']['role'] != 'receiving-controller')
    original['descriptor']['not_after_ms'] = time.time_ns() // 1_000_000 - 1
    with pytest.raises(ValueError, match='legacy_authorization_expired'):
        receiving_update.controller_bootstrap_mode(bundle, request['preservation'])
    assert files(target.package / 'runtime') == before


def test_source_renewal_reuses_native_publication_and_rebinds_visibility(expired_fixture, tmp_path, monkeypatch):
    """Real owner capability publication; explicit visibility/systemd seams."""
    from types import SimpleNamespace
    from clusterctl.operation_journal import OperationJournal
    from clusterctl.onboarding_code_successor import plan_update
    from tests.test_source_bootstrap import FakeManager
    target, request, group, _ = expired_fixture
    root = target.package / 'runtime'
    visibility = tmp_path / 'visibility.json'
    being_seed._write(visibility, {'fixture': 'visibility observation seam'})
    unit = tmp_path / 'daimon-matrix-renewal.service'
    unit.write_bytes(b'[Service]\nExecStart=/original/loader\nKillMode=control-group\n')
    unit.chmod(0o600)
    manager = FakeManager(unit)
    service = manager.inspect()
    manager.live = False
    source = SimpleNamespace(root=root, settings={'fixture': 'source'}, visibility=visibility, _reader=target._reader)
    frozen = dict(mode='renew', preservation=request['preservation'], settings_sha256=digest(source.settings),
        unit=str(unit), service=service, scope={'invocation_id': manager.invocation},
        bundle_sha256=request['runtime_sha256'],
        predecessor={'process': request['predecessor']['process'], 'server': request['preservation']['origin']},
        visibility_sha256=receiving_update.hashlib.sha256(visibility.read_bytes()).hexdigest())
    candidate = dict(transaction=str(root.parent / 'source-renewal'), expires_at_ms=request['expires_at_ms'],
        argv=['/qualified/new/loader'], qualification={'group': group})
    journal = OperationJournal(tmp_path / 'source-renewal-journal')
    row = plan_update(journal, manifest_digest='a' * 64, target='source:renewal-fixture',
        expected_precondition={'source_bootstrap': frozen}, intended_transition={'source_bootstrap': candidate},
        audit_identity={'actor': 'fixture'})
    controller = receiving_update.SourceBootstrapController(journal, row['operation_id'], source, manager)
    monkeypatch.setattr(controller, '_qualify_candidate', lambda *_: {})
    monkeypatch.setattr(controller, '_writer_quiesced', lambda: None)
    controller._record('quiesced', {'exit_observed': True})
    rebound = []
    def rebind(_upgrade, _frozen, transaction):
        assert transaction == Path(candidate['transaction'])
        actual = target.document_bundle()
        assert actual['keystore']['counter'] == request['preservation']['counter'] + 1
        rebound.append(digest(actual))
        return dict(runtime_sha256=rebound[-1], installation_sha256='a' * 64)
    monkeypatch.setattr(controller, '_publish_visibility', rebind)
    history = files(target.credential)
    for path in (root / 'custody.json', root / 'host-clients/receiving-controller/client.json'):
        before = path.read_bytes()
        path.write_bytes(before + b' ')
        with pytest.raises(OnboardingError, match='preservation_changed'):
            controller.publish()
        assert not Path(candidate['transaction']).exists()
        assert 'capability_intent' not in journal.get(row['operation_id'])['runtime_observation']['source_bootstrap']
        path.write_bytes(before)
    result = controller.publish()
    assert result['published'] is True and result['loaded_readiness'] == 'unobserved'
    assert files(target.credential) == history and len(rebound) == 1
    effects = journal.get(row['operation_id'])['runtime_observation']['source_bootstrap']
    assert effects['capability_published']['publication']['counter_after'] == request['preservation']['counter'] + 1
    assert effects['visibility_published']['runtime_sha256'] == digest(target.document_bundle())


def test_existing_controller_is_preserved_without_native_publication(preserved_fixture, monkeypatch):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    target, request, _, _ = preserved_fixture
    owner = GuestOwnerBootstrap(target, request)
    before, history = files(owner.runtime), files(target.credential)
    def forbidden(**_kwargs):
        pytest.fail('software preservation must not issue or publish authority')
    monkeypatch.setattr(upgrade, 'stage_capabilities', forbidden)
    monkeypatch.setattr(upgrade, 'publish', forbidden)
    actual = owner.execute('stage', deadline_ns=deadline())
    assert actual['mode'] == 'preserve' and actual['counter_after'] == request['preservation']['counter']
    assert files(owner.runtime) == before and files(target.credential) == history
    assert owner.execute('stage', deadline_ns=deadline()) == actual
    assert 'capability_published' not in owner._observations() and not owner.transaction.exists()
    with pytest.raises(OnboardingError, match='no_publication'):
        owner.execute('publish', deadline_ns=deadline(), ready_sha256='a' * 64)


def test_admission_preserves_actual_owner_and_store_identity_across_ledger_writes(preserved_fixture):
    from clusterctl.onboarding_group_admission import check_snapshot_context
    from clusterctl.onboarding_peer import loaded
    from clusterctl.onboarding_receiving_update import preserved_admission_stores
    from daimon_matrix import operator_runtime_upgrade as upgrade
    target, request, _, _ = preserved_fixture
    root = target.package / 'runtime'
    hosted = loaded(target)
    stores = {role: json.loads(binding.observation) for role, binding in hosted.service.loaded_stores.items()}
    before = upgrade.inventory_digest(root)
    hosted.service.ledger.append_local(kind='experience.observed', subject='synthetic admission preservation',
        payload={'summary': 'authorized new ledger content'}, signer=hosted.service.signer,
        sensitivity='shareable', occurred_at_ms=time.time_ns() // 1_000_000)
    assert upgrade.inventory_digest(root) != before
    assert preserved_admission_stores(root, target.document_bundle(), request['preservation'], stores) == stores
    operation = str(uuid.uuid4())
    journal = target.root / 'snapshot-guard'
    context_directory = journal / operation / 'owner'
    context_directory.mkdir(mode=0o700, parents=True)
    context = dict(identity=dict(runtime_root=str(root), runtime_bundle_sha256=digest(target.document_bundle())))
    being_seed._write(context_directory / 'context.json', context)
    snapshot = dict(action='snapshot', operation_id=operation, params=dict(owner_context_sha256=digest(context),
        expected_stores=stores, expected_preservation=request['preservation']))
    check_snapshot_context(journal, snapshot)
    for name in ('custody.json', 'host-clients/receiving-controller/client.json'):
        path = root / name
        original = path.read_bytes()
        path.write_bytes(original + b' ')
        try:
            with pytest.raises(OnboardingError, match='preservation_changed'):
                preserved_admission_stores(root, target.document_bundle(), request['preservation'], stores)
            with pytest.raises(OnboardingError, match='preservation_changed'):
                check_snapshot_context(journal, snapshot)
        finally:
            path.write_bytes(original)
    ledger = root / target.document_bundle()['ledger']
    retained = ledger.with_name('retained-original-ledger')
    ledger.rename(retained)
    ledger.write_bytes(retained.read_bytes())
    ledger.chmod(0o600)
    try:
        with pytest.raises(OnboardingError, match='store_binding_changed'):
            preserved_admission_stores(root, target.document_bundle(), request['preservation'], stores)
        with pytest.raises(OnboardingError, match='store_binding_changed'):
            check_snapshot_context(journal, snapshot)
    finally:
        ledger.unlink()
        retained.rename(ledger)
    assert preserved_admission_stores(root, target.document_bundle(), request['preservation'], stores) == stores


def test_lost_preservation_reply_reconciles_exact_durable_record(preserved_fixture, monkeypatch):
    target, request, _, _ = preserved_fixture
    owner = GuestOwnerBootstrap(target, request)
    record = owner._record
    def lost(name, value):
        actual = record(name, value)
        if name == 'owner_preserved':
            raise OSError('synthetic reply loss after durable preservation')
        return actual
    monkeypatch.setattr(owner, '_record', lost)
    before = files(owner.runtime)
    with pytest.raises(OSError):
        owner.execute('stage', deadline_ns=deadline())
    retained = owner._observations()['owner_preserved']
    actual = GuestOwnerBootstrap(target, request).execute('stage', deadline_ns=deadline())
    assert actual == retained and files(owner.runtime) == before


def test_source_admission_child_is_prepared_locally_and_recovers_lost_plan_without_refreeze(
        preserved_fixture, tmp_path, monkeypatch):
    from clusterctl.onboarding_group_admission import preview_owner_context
    from clusterctl.onboarding_source import Source
    from clusterctl.operation_journal import JournalConflict, OperationJournal
    from tests.test_source_bootstrap import FakeManager
    from daimon_matrix.service import LoadedStoreBinding
    target, owner_request, _group, _exited = preserved_fixture
    root, bundle = target.package / 'runtime', target.document_bundle()
    settings = dict(schema='cluster-onboarding-source/v1', runtime_root=str(root),
        password_file=str(tmp_path/'unused.unlock'), native_visibility=str(tmp_path/'visibility.json'),
        outputs=str(tmp_path/'source-outputs'), applications=[])
    config = tmp_path/'source.json'
    being_seed._write(config, settings)
    source = Source(settings, code=tmp_path/'approved-code', code_uid=os.geteuid(),
        code_digest='a'*64, qualified_startup={'explicit': 'SDK-startup seam'})
    monkeypatch.setattr(source, '_reader', lambda: pytest.fail('preparation opened custody'))
    unit = tmp_path/'daimon-matrix-admission.service'
    unit.write_bytes(b'[Service]\nExecStart=/existing/loader\nKillMode=control-group\n')
    unit.chmod(0o600)
    manager = FakeManager(unit)
    stores = {}
    for role, name, metadata in (
            ('ledger', bundle['ledger'], {'ledger': 'metadata', 'communication': 'communication_meta'}),
            ('relationships', bundle['relationships']['store_filename'], {'relationships': 'metadata'})):
        stores[role] = json.loads(LoadedStoreBinding.capture(root/name, metadata=metadata).observation)
    predecessor = dict(process=owner_request['predecessor']['process'], server=bundle['local_origin'],
        runtime_status=dict(being_ref=bundle['manifest']['being_ref'], local_origin=bundle['local_origin'],
            loaded_runtime={'stores': stores}))
    frozen = dict(mode='preserve', preservation=owner_request['preservation'], settings_sha256=digest(settings),
        unit=str(unit), service=manager.inspect(), scope={'explicit': 'native-process seam'}, predecessor=predecessor,
        bundle_sha256=digest(bundle), visibility_sha256='c'*64)
    identifier = str(uuid.uuid4())
    preview = preview_owner_context(root, source.outputs/'tribe', identifier, {})
    request = dict(schema='cluster-source-admission-preparation/v1', operation_id=identifier,
        cohort_operation_id='operation:synthetic-parent', cohort_intent_sha256='b'*64, tribe_ref='tribe:fixture',
        owner=dict(being_ref=bundle['manifest']['being_ref'], embodiment_id=bundle['local_origin']['embodiment_id']),
        predecessor={key: predecessor[key] for key in ('process', 'server')}, unit=str(unit), home=str(tmp_path),
        manifest_path=str(tmp_path/'manifest.json'), manifest_uid=os.geteuid(), manifest_digest='d'*64,
        expires_at_ms=owner_request['expires_at_ms'], authority_closure={},
        owner_context_sha256=preview['owner_context_sha256'],
        steps=dict(application='application', visibility='visibility', selection='selection', snapshot='snapshot'))
    calls = []
    def freeze(selected, selected_manager, *, deadline_ns):
        assert selected is source and selected_manager.unit == unit and deadline_ns > time.monotonic_ns()
        calls.append('freeze')
        return copy.deepcopy(frozen)
    def candidate(selected, **options):
        assert selected is source and options['installed_only'] is True
        assert 0 < receiving_update.onboarding_sdk.probe_timeout(180) <= 10
        calls.append('candidate')
        return dict(transaction=str(options['transaction']), expires_at_ms=options['expires_at_ms'],
            argv=['/qualified/existing/loader'], admission_link=options['admission_link'], qualification=dict(
                code=str(source.code), code_digest=source.code_digest, code_uid=source.code_uid, config=str(config),
                group={'selected': {'tribe_ref': request['tribe_ref']}}))
    monkeypatch.setattr(receiving_update, 'freeze_source_bootstrap', freeze)
    monkeypatch.setattr(receiving_update, 'prepare_source_bootstrap', candidate)
    journal_path = tmp_path/'source-journal'
    before = files(root)
    for field, value in (('owner_context_sha256', '0'*64), ('expires_at_ms', 1),
                         ('predecessor', {**request['predecessor'], 'process': {'pid': 999}})):
        with pytest.raises(OnboardingError):
            source.prepare_receiving_admission(journal_path, {**request, field: value},
                config=config, deadline_ns=deadline())
        assert OperationJournal.existing(journal_path) is None
    from clusterctl import onboarding_code_successor
    actual = onboarding_code_successor.plan_update
    def lost(*args, **options):
        actual(*args, **options)
        raise OSError('synthetic lost durable child plan reply')
    monkeypatch.setattr(onboarding_code_successor, 'plan_update', lost)
    with pytest.raises(OSError, match='lost durable child'):
        source.prepare_receiving_admission(journal_path, request, config=config, deadline_ns=deadline())
    assert receiving_update.onboarding_sdk.probe_timeout(180) == 180
    row = OperationJournal.existing(journal_path).latest_for_target('source-admission:'+identifier)
    assert row['state'] == 'planned' and row['runtime_observation'] is None
    calls.clear()
    monkeypatch.setattr(receiving_update, 'freeze_source_bootstrap', lambda *a, **k: pytest.fail('retry refroze Source'))
    monkeypatch.setattr(time, 'time_ns', lambda: (request['expires_at_ms']+1)*1_000_000)
    result = source.prepare_receiving_admission(journal_path, request, config=config, deadline_ns=deadline())
    assert result['operation_id'] == row['operation_id'] and result['receiving_readiness'] == 'unobserved'
    link = row['intended_transition']['source_bootstrap']['admission_link']
    assert result['link_sha256'] == digest(link)
    assert link['cohort_intent_sha256'] == request['cohort_intent_sha256']
    assert source.prepare_receiving_admission(journal_path, request, config=config, deadline_ns=deadline()) == result
    with pytest.raises(JournalConflict):
        source.prepare_receiving_admission(journal_path, {**request, 'manifest_digest': 'f'*64},
            config=config, deadline_ns=deadline())
    assert calls == [] and manager.stops == 0 and manager.live
    assert OperationJournal.existing(journal_path).get(row['operation_id']) == row
    assert files(root) == before


@pytest.mark.parametrize('change', ['custody', 'client', 'bundle', 'expired', 'live'])
def test_preservation_refuses_changed_inputs_or_unusable_authorization(preserved_fixture, change):
    target, request, _, exited = preserved_fixture
    owner = GuestOwnerBootstrap(target, request)
    if change == 'custody':
        path = owner.runtime / 'custody.json'
        path.write_bytes(path.read_bytes() + b' ')
    elif change == 'client':
        path = owner.runtime / 'host-clients/receiving-controller/client.json'
        path.write_bytes(path.read_bytes() + b' ')
    elif change == 'bundle':
        path = owner.runtime / 'runtime.json'
        path.write_bytes(path.read_bytes() + b' ')
    elif change == 'expired':
        request['expires_at_ms'] = time.time_ns() // 1_000_000 - 1
        owner = GuestOwnerBootstrap(target, request)
    else:
        exited[0] = False
    before = files(owner.runtime)
    with pytest.raises((OnboardingError, ValueError)):
        owner.execute('stage', deadline_ns=deadline())
    assert files(owner.runtime) == before and 'owner_preserved' not in owner._observations()


@pytest.mark.parametrize('lost_reply', [False, True, 'selection_expiry'])
def test_source_preserves_real_native_controller_and_visibility(preserved_fixture, tmp_path, monkeypatch, lost_reply):
    from types import SimpleNamespace
    from daimon_matrix import operator_runtime_upgrade as upgrade
    from clusterctl.operation_journal import OperationJournal
    from clusterctl.onboarding_code_successor import plan_update
    from tests.test_source_bootstrap import FakeManager
    target, request, group, _ = preserved_fixture
    root = target.package / 'runtime'
    visibility = tmp_path / 'visibility.json'
    receiving_update.being_seed._write(visibility, {'fixture': 'signed visibility observation seam'})
    unit = tmp_path / 'daimon-matrix-preservation.service'
    unit.write_bytes(b'[Service]\nExecStart=/original/loader\nKillMode=control-group\n')
    unit.chmod(0o600)
    manager = FakeManager(unit)
    service = manager.inspect()
    manager.live = False
    source = SimpleNamespace(root=root, settings={'fixture': 'source'}, visibility=visibility,
        _reader=target._reader)
    frozen = dict(mode='preserve', preservation=request['preservation'],
        settings_sha256=digest(source.settings), unit=str(unit), service=service,
        scope={'invocation_id': manager.invocation},
        bundle_sha256=request['runtime_sha256'],
        predecessor={'process': request['predecessor']['process'], 'server': request['preservation']['origin']},
        visibility_sha256=receiving_update.hashlib.sha256(visibility.read_bytes()).hexdigest())
    candidate = dict(transaction=str(root.parent / 'unneeded-software-transaction'),
        expires_at_ms=request['expires_at_ms'], argv=['/qualified/new/loader'], qualification={'group': group})
    journal = OperationJournal(tmp_path / 'source-journal')
    row = plan_update(journal, manifest_digest='a' * 64, target='source:preservation-fixture',
        expected_precondition={'source_bootstrap': frozen},
        intended_transition={'source_bootstrap': candidate}, audit_identity={'actor': 'fixture'})
    controller = receiving_update.SourceBootstrapController(journal, row['operation_id'], source, manager)
    monkeypatch.setattr(controller, '_qualify_candidate', lambda *_: {'fixture': 'code qualification seam'})
    monkeypatch.setattr(receiving_update, 'source_bootstrap_group', lambda *_: copy.deepcopy(group))
    controller._record('quiesced', {'exit_observed': True})
    before, visible = files(root), visibility.read_bytes()
    def forbidden(**_kwargs):
        pytest.fail('software selection must not publish authority or visibility')
    monkeypatch.setattr(upgrade, 'stage_capabilities', forbidden)
    monkeypatch.setattr(upgrade, 'publish', forbidden)
    if lost_reply:
        record = controller._record
        def lost(name, value):
            actual = record(name, value)
            if name == 'owner_preserved' and lost_reply is True:
                raise OSError('synthetic lost Source preservation reply')
            if name == 'unit_selected' and lost_reply == 'selection_expiry':
                monkeypatch.setattr(time, 'time_ns', lambda: (request['expires_at_ms'] + 1) * 1_000_000)
                raise OSError('synthetic lost Source selection reply then expiry')
            return actual
        with monkeypatch.context() as fault:
            fault.setattr(controller, '_record', lost)
            with pytest.raises(OSError):
                controller.publish()
    result = controller.publish()
    assert result['preserved'] is True and controller.publish() == result
    effects = journal.get(row['operation_id'])['runtime_observation']['source_bootstrap']
    assert not {'capability_published', 'visibility_published'} & effects.keys()
    assert effects['owner_preserved']['counter_after'] == request['preservation']['counter']
    assert files(root) == before and visibility.read_bytes() == visible
    assert not Path(candidate['transaction']).exists()


def test_preservation_requires_actual_native_writer_ownership(preserved_fixture):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    target, request, _, _ = preserved_fixture
    owner = GuestOwnerBootstrap(target, request)
    before = files(owner.runtime)
    with upgrade._locks(owner.runtime):
        with pytest.raises(BlockingIOError):
            owner.execute('stage', deadline_ns=deadline())
    assert files(owner.runtime) == before and 'owner_preserved' not in owner._observations()


def test_preservation_cannot_reclassify_a_changed_group(preserved_fixture):
    target, request, group, _ = preserved_fixture
    owner = GuestOwnerBootstrap(target, request)
    group['hashes']['selection'] = 'd' * 64
    with pytest.raises(OnboardingError, match='group_changed'):
        owner.execute('stage', deadline_ns=deadline())
    assert 'owner_preserved' not in owner._observations()


def test_source_preservation_refuses_advanced_custody_with_older_bundle(preserved_fixture):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    from daimon_matrix.keystore import EncryptedKeystore
    target, request, _, _ = preserved_fixture
    root = target.package / 'runtime'
    bundle = target.document_bundle()
    custody = EncryptedKeystore(root / 'custody.json')
    custody.rotate(target._reader, target._reader, expected_counter=bundle['keystore']['counter'],
        control_head=bundle['control_head'])
    pins = receiving_update.controller_preservation(root, bundle)
    before = files(root)
    with upgrade._locks(root):
        with pytest.raises(OnboardingError, match='counter_conflict'):
            receiving_update.preservation_result(upgrade, root, pins, password=target._reader(),
                operation_id=request['operation_id'], request_sha256=digest(request),
                expires_at_ms=request['expires_at_ms'])
    assert files(root) == before


def test_fresh_preservation_cannot_cross_its_fixed_horizon(preserved_fixture, monkeypatch):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    target, request, _, _ = preserved_fixture
    owner = GuestOwnerBootstrap(target, request)
    actual = upgrade._validate
    clock = [time.time_ns()]
    def late(*args):
        result = actual(*args)
        clock[0] = (request['expires_at_ms'] + 1) * 1_000_000
        return result
    monkeypatch.setattr(time, 'time_ns', lambda: clock[0])
    monkeypatch.setattr(upgrade, '_validate', late)
    before = files(owner.runtime)
    with pytest.raises(OnboardingError, match='authorization_expired'):
        owner.execute('stage', deadline_ns=deadline())
    assert files(owner.runtime) == before and 'owner_preserved' not in owner._observations()


def test_exact_historical_preservation_retry_after_expiry_does_not_readmit(preserved_fixture, monkeypatch):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    target, request, _, _ = preserved_fixture
    owner = GuestOwnerBootstrap(target, request)
    first = owner.execute('stage', deadline_ns=deadline())
    before = files(owner.runtime)
    monkeypatch.setattr(time, 'time_ns', lambda: (request['expires_at_ms'] + 1) * 1_000_000)
    def forbidden(*_args):
        pytest.fail('historical preservation cannot readmit runtime with the current clock')
    monkeypatch.setattr(upgrade, '_validate', forbidden)
    assert owner.execute('stage', deadline_ns=deadline()) == first
    assert files(owner.runtime) == before


def test_preservation_requires_outer_runtime_binding_before_owner_effects(preserved_fixture):
    target, request, _, _ = preserved_fixture
    request['runtime_sha256'] = 'f' * 64
    with pytest.raises(OnboardingError, match='request_required'):
        GuestOwnerBootstrap(target, request)


@pytest.mark.parametrize('module_name', ['onboarding_target', 'onboarding_service'])
@pytest.mark.parametrize('error, code', [
    (OnboardingError('qualified_runtime_imports_required'), 'qualified_runtime_imports_required'),
    (being_seed.SeedError('seed_operation_in_progress'), 'seed_operation_in_progress'),
    (OnboardingError('SYNTHETIC_PRIVATE_PAYLOAD'), 'unclassified_refusal'),
    (ValueError('qualified_runtime_imports_required'), 'unclassified_refusal'),
    (FileNotFoundError(2, 'SYNTHETIC_PRIVATE_PAYLOAD', '/private/synthetic-path'), 'local_input_or_socket_missing'),
])
def test_cli_diagnostics_are_opt_in_bounded_and_never_echo_private_exceptions(monkeypatch, capsys, module_name, error, code):
    import importlib
    module = importlib.import_module('clusterctl.'+module_name)
    def refuse(_value):
        raise error
    monkeypatch.setattr(module, 'validate_plan', refuse)
    if module_name == 'onboarding_target':
        monkeypatch.setattr(being_seed, '_read', lambda *_args, **_kwargs:{})
        arguments = ['observe', '--home', '/unused', '--genesis', '/unused/genesis']
        expected = {'error':'native_onboarding_target_refused'}
    else:
        monkeypatch.setattr(module.onboarding_release, 'regular', lambda *_args, **_kwargs:b'{}')
        arguments = []
        expected = {'installed':False, 'error':'onboarding_service_operation_failed'}
    arguments += ['--code', '/unused/code', '--plan', '/unused/plan']
    assert module.main(arguments) == 1
    normal = capsys.readouterr()
    assert json.loads(normal.out) == expected and normal.err == ''
    assert module.main([*arguments, '--diagnostics']) == 1
    detailed = capsys.readouterr()
    assert json.loads(detailed.out) == expected
    assert json.loads(detailed.err) == dict(schema='cluster-onboarding-refusal/v1', stage='public-release', code=code)
    assert 'SYNTHETIC_PRIVATE_PAYLOAD' not in detailed.err and '/private/' not in detailed.err


def test_explicit_sdk_observe_refusal_reports_sdk_stage(monkeypatch, capsys):
    from clusterctl import onboarding_target
    monkeypatch.setattr(being_seed, '_read', lambda *_args, **_kwargs:{})
    monkeypatch.setattr(onboarding_target, 'validate_plan', lambda _value:{'release_digest':'a'*64})
    monkeypatch.setattr(onboarding_target.onboarding_code_successor, 'selection', lambda *_args, **_kwargs:Path('/unused/code'))
    monkeypatch.setattr(onboarding_target.onboarding_code_successor, 'sdk_parameters', lambda *_args:{})
    def refuse(*_args, **_kwargs):
        raise OnboardingError('installed_onboarding_sdk_changed')
    monkeypatch.setattr(onboarding_target.onboarding_sdk, 'observe', refuse)
    assert onboarding_target.main(['sdk-observe','--diagnostics','--home','/unused',
        '--code','/unused/code','--plan','/unused/plan','--genesis','/unused/genesis']) == 1
    result = capsys.readouterr()
    assert json.loads(result.err)['stage'] == 'sdk-observation'
    assert json.loads(result.err)['code'] == 'installed_onboarding_sdk_changed'


@pytest.mark.parametrize('error,code', [
    (ClientError('daemon_response_truncated'), 'daemon_response_truncated'),
    (ClientError('SYNTHETIC_PRIVATE_PAYLOAD'), 'unclassified_refusal'),
    (RuntimeError('daemon_response_truncated'), 'unclassified_refusal'),
])
def test_native_client_diagnostics_preserve_only_typed_public_codes(error, code):
    from clusterctl.onboarding import refusal_diagnostic
    assert refusal_diagnostic(error, stage='owner-action') == dict(
        schema='cluster-onboarding-refusal/v1', stage='owner-action', code=code)
