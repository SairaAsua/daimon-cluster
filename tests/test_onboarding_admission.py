"""Native Matrix authority, separate receiving custody and real shared leases."""
import copy
import subprocess
import sys

import pytest

from clusterctl.admission import AdmissionAuthority, AdmissionConflict, AdmissionEndpoint, AdmissionTCPServer, AdmissionUnavailable, serve_in_thread
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_admission import ReceivingHolder, coordinates, enrollment
from tests.test_admission import _key
from tests.test_onboarding_target import receiving


def active(tmp_path):
    ceremony, plan, target = receiving(tmp_path)
    target.activate(ceremony.authorize_target(plan, target.prepare()))
    target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
    return ceremony, plan, target


def test_receiving_holder_native_enrollment_shared_exclusion_and_restart(tmp_path):
    ceremony, plan, target = active(tmp_path)
    holder = ReceivingHolder(target)
    public = holder.prepare()
    private = holder.key.read_bytes()
    assert holder.prepare() == public and holder.key.read_bytes() == private
    assert public['coordinates'] == coordinates(target) == ceremony.admission_coordinates(plan)
    assert public['coordinates']['body_ref'] == 'codex:daimon-cluster:' + plan['name']
    registrar = _key(tmp_path / 'host/registrar.pem', 'registrar')
    signer = _key(tmp_path / 'host/authority.pem', 'authority')
    authority = AdmissionAuthority(tmp_path / 'authority', signer=signer,
        holder_registrars={registrar.key_id: registrar.public_key})
    server = AdmissionTCPServer(('127.0.0.1', 0), authority)
    thread = serve_in_thread(server)
    endpoint = AdmissionEndpoint.network('127.0.0.1', server.server_address[1])
    def client():
        return holder.client(endpoint, authority_key_id=signer.key_id, authority_public_key=signer.public_key)
    first, competing = client(), client()
    try:
        admitted = enrollment(plan, holder.request(), ceremony.admission_coordinates(plan), registrar)
        assert first.enroll(admitted)['admitted'] is True
        assert first.enroll(admitted)['admitted'] is True
        for _ in range(2):
            owner = client()
            child = []
            def spawn():
                process = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'])
                child.append(process)
                return process
            supervisor = holder.launch(owner, spawn)
            try:
                assert supervisor.verify_current(minimum_remaining_s=1) is not None
                competing_spawn = []
                with pytest.raises(AdmissionConflict):
                    holder.launch(competing, lambda: competing_spawn.append(True))
                assert competing_spawn == [] and child[0].poll() is None
                assert public['coordinates'] == coordinates(target)
                assert holder.key.read_bytes() == private
            finally:
                supervisor.request_shutdown()
                child[0].wait(timeout=5)
                supervisor.thread.join(timeout=5)
                assert not supervisor.thread.is_alive()
            assert owner.current() is None
        failed = client()
        def cannot_spawn():
            raise RuntimeError('controlled process creation failed')
        with pytest.raises(RuntimeError, match='controlled process creation failed'):
            holder.launch(failed, cannot_spawn)
        assert failed.current() is None
        uncertain = client()
        actual_call = uncertain._call
        def lose_ack(action, **values):
            result = actual_call(action, **values)
            if action == 'acquire':
                raise AdmissionUnavailable('response lost after durable acquisition')
            return result
        uncertain._call = lose_ack
        spawned = []
        with pytest.raises(AdmissionUnavailable, match='response lost'):
            holder.launch(uncertain, lambda: spawned.append(True))
        assert spawned == []
        assert uncertain.current()['session_id'] == uncertain.session_id
        with pytest.raises(AdmissionConflict):
            holder.launch(client(), lambda: spawned.append(True))
        assert spawned == []
        uncertain.release()
        assert not list(target.home.rglob('authority.pem'))
        assert not list(target.home.rglob('registrar.pem'))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_foreign_or_expired_receiving_holder_proof_refuses_before_registrar_signing(tmp_path):
    ceremony, plan, target = active(tmp_path)
    holder = ReceivingHolder(target)
    request = holder.request()
    expected = coordinates(target)
    class Registrar:
        calls = []
        def sign(self, *args):
            self.calls.append(args)
            raise AssertionError('invalid proof reached registrar custody')
    registrar = Registrar()
    alterations = [('holder', 'plan_digest', 'f' * 64),
                   ('proof', 'signature', 'ED25519:invalid'),
                   ('proof', 'expires_at_ms', 0),
                   ('proof', 'body_ref', 'foreign-body'),
                   ('proof', 'expected_current', 0)]
    for section, key, value in alterations:
        invalid = copy.deepcopy(request)
        invalid[section][key] = value
        with pytest.raises(OnboardingError, match='onboarding_admission_request_rejected'):
            enrollment(plan, invalid, expected, registrar)
    foreign = copy.deepcopy(request)
    foreign['holder']['coordinates']['being_ref'] = 'foreign-being'
    with pytest.raises(OnboardingError, match='onboarding_admission_request_rejected'):
        enrollment(plan, foreign, expected, registrar)
    assert registrar.calls == []
    key = holder.key.read_bytes()
    holder.key.unlink()
    with pytest.raises(OnboardingError, match='existing_onboarding_admission_preserved'):
        holder.prepare()
    assert not holder.key.exists() and key


def test_expired_holder_probe_cannot_fall_through_to_enrollment(monkeypatch):
    from types import SimpleNamespace
    from clusterctl import onboarding_admission as receiver
    from clusterctl.admission import AdmissionError
    clock, calls = [1], []
    monkeypatch.setattr(receiver, 'time', SimpleNamespace(monotonic_ns=lambda: clock[0]))
    def current():
        calls.append('current')
        clock[0] = 11
        raise AdmissionError('synthetic holder not registered')
    holder = object.__new__(ReceivingHolder)
    def client(configuration, *, deadline_ns):
        assert deadline_ns == 10
        return SimpleNamespace(current=current, enroll=lambda _: calls.append('enroll'))
    holder.configured_client = client
    with pytest.raises(OnboardingError, match='deadline_expired'):
        holder.ensure_enrolled({'enrollment': {}}, enroll=True, deadline_ns=10)
    assert calls == ['current']
