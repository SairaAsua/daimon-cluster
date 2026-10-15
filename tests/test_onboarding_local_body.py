"""Local requests reuse owner access, preserve evidence and never enroll a body."""
import dataclasses
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

import pytest

from clusterctl import being_seed, onboarding_local_body as local, onboarding_peer
from daimon_matrix.daemon import acquire_lock
from tests.test_being_seed import KEY, http_server
from tests.test_onboarding_target import receiving
from tools.export_local_matrix_identity import export

pytest_plugins = ['tests.test_onboarding_peer']


def test_public_identity_export_pin_matches_the_distributed_native_asset():
    from tools.export_local_matrix_identity import PEER_SHA256
    asset = Path(__file__).resolve().parents[1] / 'clusterctl/onboarding_peer_native.py'
    assert hashlib.sha256(asset.read_bytes()).hexdigest() == PEER_SHA256


def request(name='eko', owner='sai', expected=None):
    return dict(schema=local.SCHEMA, name=name, owner=owner, request_id=str(uuid.uuid4()),
        expected_being_ref=expected, updated_ms=int(time.time() * 1000))


def report(task, identity=None):
    return dict(schema=local.REPORT, request_id=task['request_id'], checked_at_ms=int(time.time() * 1000),
        checks={key: 'passed' for key in local.CHECKS},
        matrix_state='signed-identity' if identity is not None else 'not-found', matrix_identity=identity)


def test_host_guidance_is_owner_scoped_request_bound_and_read_only(tmp_path):
    state, progress = tmp_path / 'state', tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    task = request('oliva', 'ani')
    local.Requests(progress, worker_uid=os.geteuid()).publish(task)
    guidance = dict(schema='cluster-onboarding-local-guidance/v1', name='oliva', owner='ani',
        request_id=task['request_id'], updated_ms=task['updated_ms'],
        steps=['Use the existing private VPN; preserve the signed source runtime.'])
    publisher = local.Guidance(progress, worker_uid=os.geteuid())
    publisher.publish(guidance)
    with http_server(state) as (server, http):
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(progress), onboarding_worker_uid=os.geteuid())
        path = '/v1/onboarding/local-body/oliva'
        assert http(path, owner='ani')[2]['host_guidance'] == guidance
        assert http('/v1/onboarding/local-body', owner='ani')[2]['items'][0]['host_guidance'] == guidance
        assert http(path, owner='sai')[0] == 404
        assert http('/v1/onboarding/local-body', owner='sai')[2]['items'] == []
        # This remains a report endpoint, never a participant guidance writer.
        assert http(path, 'POST', guidance, owner='ani')[0] == 400
        assert publisher.read('oliva', owner='ani') == guidance
        local.Requests(progress, worker_uid=os.geteuid()).publish({**task, 'request_id': str(uuid.uuid4())})
        assert http(path, owner='ani')[2]['host_guidance'] is None
        (progress / ('oliva' + publisher.suffix)).chmod(0o666)
        assert http(path, owner='ani')[0] == 409
        code, headers, source = http('/v1/onboarding/local-body/tools/expose_native_peer.py', owner='ani')
        assert code == 200 and headers['X-Content-SHA256'] == hashlib.sha256(source.encode()).hexdigest()


def test_foreground_native_carrier_preserves_wire_and_refuses_other_requests(monkeypatch):
    import http.client
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from tools import expose_native_peer as carrier

    observed = []
    class Native(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            observed.append((self.path, self.headers['Content-Type'],
                self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(200)
            self.send_header('Content-Type', carrier.CONTENT_TYPE)
            self.send_header('Content-Length', '7')
            self.end_headers()
            self.wfile.write(b'receipt')

    with ThreadingHTTPServer(('127.0.0.1', 0), Native) as native:
        monkeypatch.setattr(carrier, 'NATIVE_PORT', native.server_port)
        with ThreadingHTTPServer(('127.0.0.1', 0), carrier.Carrier) as proxy:
            proxy.allowed_host = '127.0.0.1'
            threads = [threading.Thread(target=s.serve_forever) for s in (native, proxy)]
            for thread in threads:
                thread.start()
            def send(path='/dm-peer/v1', kind=carrier.CONTENT_TYPE):
                connection = http.client.HTTPConnection('127.0.0.1', proxy.server_port, timeout=5)
                try:
                    connection.request('POST', path, b'opaque native fixture', {'Content-Type': kind})
                    response = connection.getresponse()
                    return response.status, response.read(), response.getheader('Content-Type')
                finally:
                    connection.close()
            try:
                assert send() == (200, b'receipt', carrier.CONTENT_TYPE)
                assert send('/dm-messaging/v1/message')[0] == 403
                assert send(kind='application/json')[0] == 403
                proxy.allowed_host = '10.6.6.6'
                assert send()[0] == 403
                assert observed == [('/dm-peer/v1', carrier.CONTENT_TYPE, b'opaque native fixture')]
            finally:
                for server in (native, proxy):
                    server.shutdown()
                for thread in threads:
                    thread.join()
    assert carrier.addresses('10.6.6.7', '10.6.6.6') == ('10.6.6.7', '10.6.6.6')
    for address in ('0.0.0.0', '127.0.0.1', '8.8.8.8', '224.0.0.1', '169.254.1.1', '10.6.6.6'):
        with pytest.raises(ValueError):
            carrier.addresses(address, '10.6.6.6')


def test_private_requests_before_intake_reuse_supplied_inputs_and_preserve_reports(tmp_path):
    state, progress = tmp_path / 'state', tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    publisher = local.Requests(progress, worker_uid=os.geteuid())
    task, other = request(), request('oliva', 'ani')
    publisher.publish(task)
    publisher.publish(other)
    with http_server(state) as (server, http):
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(progress), onboarding_worker_uid=os.geteuid())
        endpoint = '/v1/onboarding/local-body'
        code, headers, value = http(endpoint, owner='sai')
        assert code == 200 and headers['Cache-Control'] == 'no-store'
        assert [row['name'] for row in value['items']] == ['eko']
        assert http(endpoint + '/eko', owner='ani')[0] == 404
        assert http(endpoint, owner='reader')[0] == 403
        assert http(endpoint, extra={'Authorization': ''})[0] == 401
        assert len(http(endpoint, owner='operator')[2]['items']) == 2
        being_seed.create(state, dict(name='eko', label='Eko', mode='import'), owner='sai', key=KEY)
        being_seed.connections(state, 'eko', dict(telegram_bot_token='123456789:' + 'a' * 40,
            telegram_chat_id=123, ssh_public_key='ssh-ed25519 ' + 'a' * 44), owner='sai')
        received = http(endpoint + '/eko', owner='sai')[2]['received']
        assert received['ssh_key_received'] and received['telegram_data_received']
        record = state / 'being-seeds/eko/record.json'
        being_seed._write(record, {**being_seed._read(record), 'preparation_queued': True})
        waiting = http(endpoint + '/eko', owner='sai')[2]
        assert 'receiving_selection_and_preparation' not in waiting['pending_inputs']
        assert waiting['host_tasks'] == ['context_preparation']
        data = report(task)
        code, _, value = http(endpoint + '/eko', 'POST', data, owner='sai')
        assert code == 200 and value['report']['identity_verified'] is False
        assert value['report']['hosted_acceptance'] is False
        assert http(endpoint + '/eko', 'POST', data, owner='sai')[2] == value
        changed = {**data, 'checked_at_ms': data['checked_at_ms'] + 1,
                   'checks': {**data['checks'], 'memory': 'failed'}}
        assert http(endpoint + '/eko', 'POST', changed, owner='sai')[0] == 200
        assert http(endpoint + '/eko', 'POST', data, owner='sai')[2]['report']['checks']['memory'] == 'failed'
        preserved = state / 'local-body-reports/eko'
        assert len([path for path in preserved.glob('*.json') if path.name != 'latest.json']) == 2
        assert http(endpoint + '/eko', 'POST', {**data, 'password': 'must not be accepted'}, owner='sai')[0] == 400
        assert http(endpoint + '/eko', 'POST', {**data, 'checked_at_ms': True}, owner='sai')[0] == 400
        assert not (state / 'being-seeds/oliva').exists()
        assert not list(state.rglob('custody.json'))
        publisher.publish({**task, 'request_id': str(uuid.uuid4())})
        assert http(endpoint + '/eko', 'POST', data, owner='sai')[0] == 400
        assert http(endpoint + '/eko', owner='sai')[2]['report'] is None
        for tool in ('export_local_matrix_identity.py', 'onboarding_peer_native.py'):
            code, headers, source = http(endpoint + '/tools/' + tool, owner='sai')
            assert code == 200
            assert headers['X-Content-SHA256'] == hashlib.sha256(source.encode()).hexdigest()
        assert http(endpoint + '/tools/custody.json', owner='sai')[0] == 404
        assert 'local-body-section' in http('/v1/onboarding')[2]
        assert 'local_body_report' in http('/v1/onboarding?format=json')[2]['requests']


def test_real_existing_identity_export_and_signature_verification_no_new_custody(tmp_path, monkeypatch):
    ceremony, plan, target = receiving(tmp_path)
    proposal = target.prepare()
    target.activate(ceremony.authorize_target(plan, proposal))
    target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
    root = target.package / 'runtime'
    before = {name: (root / name).read_bytes() for name in ('runtime.json', 'custody.json')}
    password = target.root / 'body.unlock'
    output = target.root / 'public-local.json'
    asset = Path(__file__).resolve().parents[1] / 'clusterctl/onboarding_peer_native.py'
    lock = acquire_lock(root)
    try:
        with pytest.raises(BlockingIOError):
            export(root, password, output, peer_file=asset)
        assert not output.exists()
    finally:
        os.close(lock)
    export(root, password, output, peer_file=asset)
    assert output.stat().st_mode & 0o077 == 0
    identity = json.loads(output.read_bytes())
    assert before == {name: (root / name).read_bytes() for name in before}
    task = request(expected=identity['document']['authority']['manifest']['being_ref'])
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    accepted = local.submit(state, task, report(task, identity), code_uid=os.geteuid())
    assert accepted['report']['identity_verified']
    assert accepted['report']['hosted_acceptance'] is False
    assert 'matrix_identity' not in accepted['report']
    forged = json.loads(json.dumps(identity))
    forged['document']['runtime_label'] = 'Another identity'
    with pytest.raises(being_seed.SeedError, match='signed_identity_required'):
        local.submit(state, task, report(task, forged), code_uid=os.geteuid())
    wrong = {**task, 'expected_being_ref': 'dm:being:v1:' + 'a' * 43}
    with pytest.raises(being_seed.SeedError, match='signed_identity_required'):
        local.submit(state, wrong, report(wrong, identity), code_uid=os.geteuid())
    with pytest.raises(being_seed.SeedError, match='existing_local_body_identity_preserved'):
        local.submit(state, task, report(task), code_uid=os.geteuid())
    with pytest.raises(FileExistsError):
        export(root, password, output, peer_file=asset)
    actual = onboarding_peer.native
    monkeypatch.setattr(onboarding_peer, 'native', lambda code, uid=0: actual(code, uid=os.geteuid()))
    assert local.worker_identity(state, task, intake_uid=os.geteuid()) == identity
    with pytest.raises(Exception, match='private_local_body_report_required'):
        local.worker_identity(state, task, intake_uid=os.geteuid() + 1)
    progress = tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    local.Requests(progress, worker_uid=os.geteuid()).publish(task)
    with http_server(state) as (server, http):
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(progress), onboarding_worker_uid=os.geteuid())
        assert http('/v1/onboarding/local-body/eko', 'POST', report(task, identity), owner='sai')[0] == 200
    assert before == {name: (root / name).read_bytes() for name in before}


def test_export_reuses_signed_owner_application_and_refuses_other_visibility(journey, tmp_path):
    from daimon_matrix.native_egress import NativeEgressError
    from daimon_matrix.messaging_config import MessagingConfigError

    _, sources, public, packet, _ = journey
    target = sources[1][1]
    onboarding_peer.accept(target, packet, expected_being=public[0]['document']['authority']['manifest']['being_ref'])
    root = target.package / 'runtime'
    app = onboarding_peer.root(target) / 'application'
    visibility = onboarding_peer.root(target) / 'visibility/installation.json'
    password = target.root / 'body.unlock'
    asset = Path(__file__).resolve().parents[1] / 'clusterctl/onboarding_peer_native.py'
    before = {path: path.read_bytes() for path in (root / 'runtime.json', root / 'custody.json',
        visibility, app / 'application.json', app / 'binding.json', app / 'publication.json')}
    # Reproduce the reported mismatch: the bare daemon binds its runtime bundle,
    # while this actual owner-signed installation binds the messaging app.
    with pytest.raises(NativeEgressError, match='egress_installation_invalid'):
        export(root, password, tmp_path / 'bare.json', visibility_installation=visibility, peer_file=asset)
    output = tmp_path / 'owner-public.json'
    lock = acquire_lock(root)
    try:
        with pytest.raises(BlockingIOError):
            export(root, password, output, visibility_installation=visibility,
                   messaging_application=app, peer_file=asset)
    finally:
        os.close(lock)
    export(root, password, output, visibility_installation=visibility, messaging_application=app, peer_file=asset)
    identity = json.loads(output.read_bytes())
    authority = onboarding_peer.native(target.code, uid=target.code_uid).verify_identity(identity)
    assert authority.manifest.being_ref == public[1]['document']['authority']['manifest']['being_ref']
    assert output.stat().st_mode & 0o077 == 0
    assert before == {path: path.read_bytes() for path in before}
    with pytest.raises(ValueError, match='existing_owner_visibility_required'):
        export(root, password, tmp_path / 'missing.json', messaging_application=app, peer_file=asset)
    # SDK profiles may reject an absent path before parsing its application.
    # Both forms must refuse it without publishing or changing existing state.
    with pytest.raises((MessagingConfigError, FileNotFoundError)):
        export(root, password, tmp_path / 'other.json', visibility_installation=visibility,
               messaging_application=tmp_path / 'missing-app', peer_file=asset)
    assert not any((tmp_path / name).exists() for name in ('bare.json', 'missing.json', 'other.json'))
    assert before == {path: path.read_bytes() for path in before}


def test_blocker_diagnostics_before_archive_are_private_preserved_and_do_not_replace_identity_checks(tmp_path):
    state, progress = tmp_path / 'state', tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    task = request()
    publisher = local.Requests(progress, worker_uid=os.geteuid())
    publisher.publish(task)
    publisher.publish(request('oliva', 'ani'))
    with http_server(state) as (server, http):
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(progress), onboarding_worker_uid=os.geteuid())
        endpoint = '/v1/onboarding/local-body/eko'
        data = dict(schema=local.DIAGNOSTIC, request_id=task['request_id'],
            reported_at_ms=task['updated_ms'], component='context-exporter', no_credentials=True,
            report={'error': 'embedded_credential_requires_separate_handoff',
                    'harmless_cases': ['code without credentials', 'empty JPEG'], 'originals_intact': True})
        assert http(endpoint + '/diagnostic', 'POST', data, owner='ani')[0] == 404
        assert http(endpoint + '/diagnostic', 'POST', data, owner='reader')[0] == 403
        assert http(endpoint + '/diagnostic', 'POST', data, extra={'Authorization': ''})[0] == 401
        code, headers, first = http(endpoint + '/diagnostic', 'POST', data, owner='sai')
        assert code == 200 and headers['Cache-Control'] == 'no-store'
        assert first['report'] is None and not first['received']['archive_received']
        assert first['diagnostic']['received'] and first['diagnostic']['resolution'] == 'host-review-pending'
        assert 'report' not in first['diagnostic']
        assert http(endpoint + '/diagnostic', 'POST', data, owner='sai')[2] == first
        checks = report(task)
        assert http(endpoint, 'POST', checks, owner='sai')[0] == 200
        later = {**data, 'reported_at_ms': data['reported_at_ms'] + 1,
                 'report': {'reproduction': 'additional harmless evidence'}}
        assert http(endpoint + '/diagnostic', 'POST', later, owner='sai')[0] == 200
        value = http(endpoint + '/diagnostic', 'POST', data, owner='sai')[2]
        assert value['diagnostic']['reported_at_ms'] == later['reported_at_ms']
        assert value['report']['checks'] == checks['checks']
        saved = state / 'local-body-reports/eko/diagnostics'
        assert saved.stat().st_mode & 0o077 == 0
        evidence = [path for path in saved.glob('*.json') if path.name != 'latest.json']
        assert len(evidence) == 2 and all(path.stat().st_mode & 0o077 == 0 for path in evidence)
        assert any(json.loads(path.read_bytes()) == data for path in evidence)
        for bad in ({**data, 'no_credentials': False}, {**data, 'request_id': str(uuid.uuid4())},
                    {**data, 'reported_at_ms': True}, {**data, 'report': {'large': 'x' * 60000}},
                    {**data, 'report': {'token': 'ghp_' + 'a' * 40}}):
            assert http(endpoint + '/diagnostic', 'POST', bad, owner='sai')[0] == 400
        assert len([path for path in saved.glob('*.json') if path.name != 'latest.json']) == 2
        assert not (state / 'being-seeds').exists()
        assert 'local-body-send-diagnostic' in http('/v1/onboarding')[2]
        assert 'local_body_diagnostic' in http('/v1/onboarding?format=json')[2]['requests']
        publisher.publish({**task, 'request_id': str(uuid.uuid4())})
        assert http(endpoint, owner='sai')[2]['diagnostic'] is None
