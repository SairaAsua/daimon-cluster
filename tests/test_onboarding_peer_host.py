"""Host orchestration retries native effects, preserves Source and isolates jobs."""
import hashlib
import json
import os
import threading
from types import SimpleNamespace

import pytest

from clusterctl import being_seed, onboarding_peer
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_peer_host import PeerHost
from tests.test_onboarding_source import prepare

pytest_plugins = ['tests.test_onboarding_peer']


def test_host_retry_reuses_signed_response_and_retains_native_source(journey, tmp_path, monkeypatch):
    source, target, _, _, original = prepare(journey, tmp_path)
    # prepare() qualified the native peer; use the same immutable proposal under
    # its original Source fingerprint so no second ceremony is invented.
    plan = journey[1][0][1].plan
    fingerprint = digest(plan)
    source_config = source.outputs / 'source.json'
    being_seed._write(source_config, source.settings)
    unit = source.outputs / 'daimon-matrix-native.service'
    original_unit = b'[Service]\nLoadCredential=matrix-password:existing\nExecStart=existing\nRestart=on-failure\n'
    unit.write_bytes(original_unit)
    unit.chmod(0o600)
    root = tmp_path / 'host-peer'
    root.mkdir(mode=0o700)
    source_being = journey[2][0]['document']['authority']['manifest']['being_ref']
    settings = dict(schema='cluster-onboarding-peer-host/v1', source_config=str(source_config),
        source_uid=os.geteuid(), source_gid=os.getegid(),
        source_settings_digest=digest({k: v for k, v in source.settings.items() if k != 'applications'}),
        source_being_ref=source_being, source_unit=str(unit), source_unit_sha256=hashlib.sha256(original_unit).hexdigest(),
        source_python=str(target.code / 'python'), state=str(root),
        port_base=int(journey[4]['plan']['endpoints'][0].rsplit(':', 1)[1]))
    path = tmp_path / 'peer-host.json'
    being_seed._write(path, settings)
    expected = dict(being_ref=target.document_bundle()['manifest']['being_ref'], **target.document_bundle()['local_origin'])
    actual_native = onboarding_peer.native
    monkeypatch.setattr(onboarding_peer, 'native', lambda code, uid=0: actual_native(code, uid=os.geteuid()))
    # Exercise the typed host publication boundary with the actual encrypted
    # offer; a path/Root argument cannot be supplied independently by intake.
    from clusterctl.onboarding_host import HostBackend
    from daimon_matrix.canonical import canonical_bytes
    views = tmp_path / 'views'
    views.mkdir(mode=0o700)
    monkeypatch.setattr('clusterctl.onboarding_mounts.GUEST_UID', os.geteuid())
    monkeypatch.setattr('clusterctl.onboarding_mounts.GUEST_GID', os.getegid())
    typed = object.__new__(HostBackend)
    typed.config = SimpleNamespace(peer=path, custody=tmp_path / 'custody', custody_grants=tmp_path / 'grants', views=views)
    typed._ceremony = lambda p: SimpleNamespace(authorize=lambda p: True)
    typed._guest_paths = lambda p: (None, target.code, {})
    typed._runtime_paths = lambda p, code: (code, [], {})
    commands = []
    typed._dispatch = lambda p, argv: commands.append(argv) or '{}'
    packet = source.tool.read_public(source.directory(fingerprint) / 'offer.json')
    typed._target_call(plan, 'peer-accept', peer_packet=packet, peer_being_ref=source_being)
    command = commands[-1]
    assert command[command.index('--peer-packet-sha256') + 1] == hashlib.sha256(canonical_bytes(packet)).hexdigest()
    assert (views / fingerprint / 'matrix-public/peer-offer.json').read_bytes() == canonical_bytes(packet)
    with pytest.raises(OnboardingError, match='approved_onboarding_peer_required'):
        typed._target_call(plan, 'peer-accept', peer_packet=packet, peer_being_ref='another Root')
    assert len(commands) == 1
    accepted = []
    def target_call(p, action, **arguments):
        if action == 'peer-identity':
            return journey[2][1]
        assert action == 'peer-accept' and arguments['peer_being_ref'] == source_being
        accepted.append(action)
        return onboarding_peer.accept(target, arguments['peer_packet'], expected_being=source_being)
    backend = SimpleNamespace(config=SimpleNamespace(peer=path, custody=None, custody_grants=None,
        consent_state=None, progress=None), _target_call=target_call,
        _matrix_command=lambda p, a: target.observe(), authorize=lambda p, d: True)
    backend._ceremony = lambda p: SimpleNamespace(admission_coordinates=lambda p: expected)
    host = PeerHost(backend)
    monkeypatch.setattr(host, '_proxies', lambda p, **k: True)
    monkeypatch.setattr(host, '_ports', lambda p: tuple(int(x.rsplit(':', 1)[1]) for x in journey[4]['plan']['endpoints']))
    calls = []
    state = []
    def service(action):
        calls.append(action)
        if action == 'stop' and state:
            stop, thread = state.pop()
            stop.set()
            thread.join(timeout=8)
            assert not thread.is_alive()
        if action == 'start':
            stop = threading.Event()
            reader, writer = os.pipe()
            thread = threading.Thread(target=lambda: source.serve(stop, ready_descriptor=writer))
            thread.start()
            import select
            assert select.select([reader], [], [], 8)[0] and os.read(reader, 16) == b'READY\n'
            os.close(reader)
            state.append((stop, thread))
    monkeypatch.setattr(host, '_service', service)
    failed = []
    def call(action, value):
        if action == 'observe':
            return dict(running=bool(state), applications=source.settings['applications'])
        if action == 'offer':
            return source.offer(value['plan_digest'], value['peer'], value['endpoints'])
        if action == 'finish':
            ready = source.finish(value['plan_digest'], value['response'])
            if not failed:
                failed.append(True)
                raise OSError('lost source finish acknowledgement')
            return ready
        assert action == 'register'
        source.register(source_config, unit, value['unit_sha256'], target.code / 'python', value['plan_digest'])
        return {'registered': True}
    monkeypatch.setattr(host, '_source', call)
    try:
        with pytest.raises(OSError, match='lost source finish'):
            host.repair_directed(plan)
        assert state and source._load(signed=True).egress is not None
        host.repair_directed(plan)
        assert host.directed_application(plan) == (str('/home/agent/.local/state/daimon-onboarding/' + plan['name'] + '/matrix/peer/application'),
            '/home/agent/.local/state/daimon-onboarding/' + plan['name'] + '/matrix/peer/visibility/installation.json')
        before = json.loads((root / fingerprint / 'response.json').read_bytes())
        with pytest.raises(OnboardingError, match='onboarding_group_enrollment_required'):
            host.execute(plan)
        assert accepted == ['peer-accept']
        assert json.loads((root / fingerprint / 'response.json').read_bytes()) == before
        assert calls.count('stop') == calls.count('start') == 2
        assert source.tool.read_public(source.visibility)['document']['secrets'] == original['document']['secrets']
    finally:
        service('stop')


def test_loopback_proxies_preserve_foreign_devices_and_retain_port_leases(tmp_path):
    host = object.__new__(PeerHost)
    host.settings = {'port_base': 23000}
    host.state = tmp_path
    tmp_path.chmod(0o700)
    from tests.test_onboarding import plan
    first = plan()
    second = {**first, 'name': 'oliva', 'owner': 'ani'}
    assert host._ports(first) == (23000, 23001)
    assert host._ports(second) == (23002, 23003)
    assert host._ports(first) == (23000, 23001)
    rows = [dict(name='dm-eko', expanded_devices={'onboarding-peer-source': dict(type='proxy', listen='foreign')})]
    host.backend = SimpleNamespace(_inventory=lambda: (rows, []), instance=lambda p: 'dm-' + p['name'])
    with pytest.raises(OnboardingError, match='foreign_onboarding_peer_proxy_preserved'):
        host._proxies(first, install=True)
    rows[0]['expanded_devices'] = {}
    rows.append(dict(name='foreign', expanded_devices={'proxy': dict(type='proxy', bind='host', listen='tcp:127.0.0.1:23001')}))
    with pytest.raises(OnboardingError, match='onboarding_runtime_listener_collision'):
        host._proxies(first)


def test_revocation_between_peer_effects_restores_source_without_finishing(tmp_path, monkeypatch):
    from tests.test_onboarding import plan
    host = object.__new__(PeerHost)
    host.state = tmp_path
    tmp_path.chmod(0o700)
    host.settings = {'source_being_ref': 'approved-source'}
    approved = [True]
    def receive(*a, **k):
        approved[0] = False
        return {'signed': 'response'}
    host.backend = SimpleNamespace(authorize=lambda *a: approved[0], _target_call=receive)
    host.application = lambda p: None
    host._identity = lambda p: {}
    host._proxies = lambda p, **k: True
    host._ports = lambda p: (24000, 24001)
    services, effects = [], []
    host._service = services.append
    def source(action, value):
        if action == 'observe':
            return {'running': True, 'applications': []}
        effects.append(action)
        assert action == 'offer'
        return {'sender_identity': {}}
    host._source = source
    monkeypatch.setattr(onboarding_peer, 'native', lambda *a: SimpleNamespace(
        verify_identity=lambda v: SimpleNamespace(state=SimpleNamespace(being_ref='approved-source'))))
    with pytest.raises(OnboardingError, match='host_authorization_required'):
        host.repair_directed(plan())
    assert effects == ['offer'] and services == ['stop', 'start']


def test_owner_service_resolves_runuser_in_the_closed_execution_environment(monkeypatch):
    import subprocess
    host = object.__new__(PeerHost)
    host.settings = {'source_uid': os.geteuid(), 'source_unit': '/owner/daimon-matrix-native.service'}
    captured = []
    host._run = lambda argv: captured.append(argv)
    host._service('stop')
    command = captured[0]
    assert command[0] == '/usr/sbin/runuser'
    result = subprocess.run([command[0], '--version'], env={'PATH': os.defpath}, capture_output=True, check=False)
    assert result.returncode == 0
    assert command[-3:] == ['--user', 'stop', 'daimon-matrix-native.service']


def test_selected_application_matches_native_receiving_target_layout(tmp_path, monkeypatch):
    from pathlib import Path
    from clusterctl.onboarding_target import Target
    from tests.test_onboarding import plan as make_plan
    plan = make_plan()
    home = tmp_path / 'receiving-home'
    home.mkdir(mode=0o700)
    target = Target(home, plan, {})
    native_peer = onboarding_peer.root(target)
    (native_peer / 'application').mkdir(mode=0o700, parents=True)
    (native_peer / 'application/publication.json').write_text('{}')
    host = object.__new__(PeerHost)
    host.settings = {'source_being_ref': 'verified-source'}
    host.state = tmp_path / 'host'
    host.state.mkdir(mode=0o700)
    marker = host.state / digest(plan)
    marker.mkdir(mode=0o700)
    being_seed._write(marker / 'complete.json', dict(schema='cluster-onboarding-peer-complete/v1',
        plan_digest=digest(plan), source_being_ref='verified-source'))
    host.backend = SimpleNamespace(_matrix_command=lambda p, a: dict(phase='v8',
        receipt={'peer_being_ref': 'verified-source'}))
    monkeypatch.setattr(host, '_identity', lambda p: {})
    monkeypatch.setattr(host, '_proxies', lambda p: True)
    monkeypatch.setattr(host, '_source', lambda action, args: dict(running=True, applications=[digest(plan)]))
    assert host.application(plan) is None
    application, visibility = host.directed_application(plan)
    selected_relative = Path(application).relative_to('/home/agent')
    assert (home / selected_relative / 'publication.json').is_file()
    assert Path(visibility).relative_to('/home/agent') == native_peer.relative_to(home) / 'visibility/installation.json'
