"""Managed reconciliation uses native admission and preserves uncertain effects."""
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.admission import AdmissionAuthority, AdmissionEndpoint, AdmissionTCPServer, serve_in_thread
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_admission import ReceivingHolder
from clusterctl.onboarding_managed import ManagedRuntime
from clusterctl.onboarding_runtime import AdmittedDaemon
from clusterctl.onboarding_target import Target
from tests.test_admission import _key
from tests.test_onboarding_target import receiving


def test_each_receiving_body_selects_its_verified_peer_application(monkeypatch):
    managed = object.__new__(ManagedRuntime)
    managed.backend = SimpleNamespace(config=SimpleNamespace(peer=Path('configured'), qualification=False))
    managed.settings = {'visibility_installation': '/home/agent/another-being/visibility',
                        'messaging_application': '/home/agent/another-being/application'}
    def host(backend):
        def application(plan):
            if plan['name'] == 'waiting':
                return None
            root = '/home/agent/.local/state/daimon-onboarding/' + plan['name'] + '/matrix/peer'
            return root + '/application', root + '/visibility/installation.json'
        return SimpleNamespace(application=application)
    monkeypatch.setattr('clusterctl.onboarding_peer_host.PeerHost', host)
    for name in ('eko', 'oliva'):
        app, visibility = managed._selection({'name': name})
        assert '/' + name + '/matrix/peer/' in app and '/' + name + '/matrix/peer/' in visibility
        assert managed._ready({'name': name})
    assert managed._selection({'name': 'waiting'}) == (None, None)
    assert not managed._ready({'name': 'waiting'})


def test_lost_enrollment_and_registry_ack_resume_same_holder_and_native_body(tmp_path, monkeypatch):
    ceremony, plan, blank = receiving(tmp_path)
    ceremony.prepare(plan, identity_mode='first')
    registrar = _key(tmp_path / 'host/registrar.pem', 'registrar')
    signer = _key(tmp_path / 'host/authority.pem', 'authority')
    authority = AdmissionAuthority(tmp_path / 'authority', signer=signer,
        holder_registrars={registrar.key_id: registrar.public_key})
    server = AdmissionTCPServer(('127.0.0.1', 0), authority)
    thread = serve_in_thread(server)
    endpoint = AdmissionEndpoint.network('127.0.0.1', server.server_address[1])
    for name in ('service-state', 'registry'):
        (tmp_path / name).mkdir(mode=0o700)
    settings = dict(schema='cluster-onboarding-managed-runtime/v1',
        host_port=server.server_address[1], guest_port=server.server_address[1],
        authority_key_id=signer.key_id, authority_public_key=signer.public_key,
        registrar_key_id=registrar.key_id, registrar_key=str(tmp_path / 'host/registrar.pem'),
        registry=str(tmp_path / 'registry'), state=str(tmp_path / 'service-state'), visibility_installation=None)
    being_seed._write(tmp_path / 'managed.json', settings)
    published = []
    monkeypatch.setattr('clusterctl.onboarding_mounts.prepare_matrix_public',
                        lambda _root, _plan, documents: published.append(documents))
    with tempfile.TemporaryDirectory(prefix='dm-') as home:
        target = Target(Path(home), plan, blank.genesis)
        target.activate(ceremony.authorize_target(plan, target.prepare()))
        target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
        holder = ReceivingHolder(target)
        instances = [dict(name='dm-' + plan['name'], expanded_devices={})]
        active = []
        failures = ['enroll', 'registry']
        calls = []
        def target_call(_plan, action, *, profile=None):
            calls.append(action)
            if action == 'admission-prepare':
                return holder.request()
            if action in {'admission-check', 'admission-enroll'}:
                result = dict(registered=holder.ensure_enrolled(profile, enroll=action == 'admission-enroll'))
                if action == 'admission-enroll' and 'enroll' in failures:
                    failures.remove('enroll')
                    raise OSError('lost ACK after authority registration')
                return result
            assert action == 'admitted-running'
            return target.running(admitted=True)
        def dispatch(_plan, argv):
            if argv[:3] == ['config', 'device', 'add']:
                instances[0]['expanded_devices'][argv[4]] = dict(type=argv[5],
                    **dict(item.split('=', 1) for item in argv[6:]))
                return ''
            if 'systemctl' in argv:
                return 'ActiveState=active\nMainPID=1\n' if active else 'ActiveState=inactive\nMainPID=0\n'
            assert 'python3' in argv
            if not active:
                client = holder.client(endpoint, authority_key_id=signer.key_id, authority_public_key=signer.public_key)
                daemon = AdmittedDaemon(target, client)
                daemon.start(receive_only=True)
                active.append(daemon)
            return json.dumps(dict(installed=True))
        backend = SimpleNamespace(config=SimpleNamespace(admission=tmp_path / 'managed.json', qualification=True,
            custody=ceremony.root, custody_grants=ceremony.grants, views=tmp_path / 'views'),
            instance=lambda _plan: instances[0]['name'], _inventory=lambda: (instances, []),
            _dispatch=dispatch, _target_call=target_call,
            _guest_paths=lambda _plan: (None, Path('/opt/qualified-code'), {}),
            _runtime_paths=lambda _plan, code: (code, [], {}))
        backend._ceremony = lambda _plan: ceremony
        managed = ManagedRuntime(backend)
        # Receive-only is a disposable qualification mode, never a live fallback.
        assert managed.observe({**plan, 'name': 'eko'}).state == 'waiting'
        original_adopt = managed.registry.adopt_running
        def adopt(**origin):
            result = original_adopt(**origin)
            if 'registry' in failures:
                failures.remove('registry')
                raise OSError('lost ACK after registry publication')
            return result
        managed.registry.adopt_running = adopt
        try:
            assert managed.observe(plan).state == 'absent'
            with pytest.raises(OSError, match='authority registration'):
                managed.prepare_admission(plan)
            preserved_key = holder.key.read_bytes()
            proposal = being_seed._read(tmp_path / 'service-state' / digest(plan) / 'candidate.json')
            # A shared-group owner context must be frozen after native profile
            # preparation, while no application/service has been selected yet.
            # The real authority has already accepted the lost enrollment ACK.
            ready = managed._ready
            managed._ready = lambda _plan: False
            with pytest.raises(OnboardingError, match='visibility_selection_required'):
                managed.execute(plan)
            assert managed.prepare_admission(plan) == proposal
            assert managed.prepare_admission(plan) == proposal
            assert active == []
            assert not managed._registered(managed._expected(plan))
            managed._ready = ready
            with pytest.raises(OSError, match='registry publication'):
                managed.execute(plan)
            pid = active[0].process.pid
            before = managed.registry.path.read_bytes()
            observed = managed.observe(plan)
            observed.validate()
            assert observed.state == 'complete' and observed.facts['identity_verified'] is True
            managed.execute(plan)
            assert managed.registry.path.read_bytes() == before
            assert len(active) == 1 and active[0].process.pid == pid
            assert holder.key.read_bytes() == preserved_key
            assert calls.count('admission-prepare') == calls.count('admission-enroll') == 1
            assert all(documents['admission.json'] == proposal for documents in published)
            active[0].close()
            active.clear()
            assert managed.observe(plan).state == 'absent'
            # Registry is continuity history; its row alone never proves presence.
            assert managed.registry.path.read_bytes() == before
        finally:
            for daemon in active:
                daemon.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
