"""Actual signed native Source survives an additive peer ceremony and restart."""
import hashlib
import os
import threading

import pytest

from clusterctl import onboarding_peer
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_source import Source
pytest_plugins = ['tests.test_onboarding_peer']


def test_source_group_construction_does_not_invoke_unrelated_pair_ceremony(tmp_path, monkeypatch):
    root = tmp_path / 'runtime'
    root.mkdir(mode=0o700)
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(True)
        raise OnboardingError('qualified_native_peer_sdk_required')
    monkeypatch.setattr(onboarding_peer, 'native', unavailable)
    source = Source(dict(schema='cluster-onboarding-source/v1', runtime_root=str(root),
        password_file=str(tmp_path / 'unused.unlock'), native_visibility=str(tmp_path / 'unused.json'),
        outputs=str(tmp_path / 'outputs'), applications=[]))
    assert calls == []
    with pytest.raises(OnboardingError, match='qualified_native_peer_sdk_required'):
        source.tool
    assert calls == [True]  # Explicit ceremony still has the exact existing guard.


def signed_visibility(target, directory):
    from daimon_matrix import canonical, daemon, native_egress, runtime
    from daimon_matrix.messaging_config import config_digest, create_binding
    tool = onboarding_peer.native(target.code, uid=target.code_uid)
    body = onboarding_peer.loaded(target)
    being = target.document_bundle()['manifest']['being_ref']
    scope = dict(mode='all-inter-daimon-communications', channels=[dict(
        channel_id='runtime-control-only', direction='outgoing', local_being_ref=being,
        peer_being_ref=being, bootstrap_policy={}, relationship_disclosure={})],
        projected_content='complete-plaintext-content-and-metadata')
    destination = dict(bot_id=123, chat_id=-100123, topic_id=None, representation='plain-json/v2')
    disclosure = dict(schema='dm.messaging.visibility-disclosure/v1', issued_at_ms=tool.now(),
        destination=destination, scope=scope, scope_sha256=config_digest(scope), participants=[being],
        risk='all-inter-daimon-communication-will-be-posted-as-plaintext-to-the-fixed-telegram-destination')
    acceptance = dict(schema='dm.messaging.visibility-acceptance-set/v1', disclosure_sha256=config_digest(disclosure),
        bindings=[create_binding(body, disclosure)])
    token = b'123:disposable-source-test-only'
    proof = os.urandom(32)
    directory.mkdir(mode=0o700)
    for name, raw in (('telegram.token', token), ('proof.key', proof)):
        (directory / name).write_bytes(raw)
        (directory / name).chmod(0o600)
    document = dict(schema='dm.messaging.visibility-installation/v1', generation=1,
        runtime_id=target.document_bundle()['runtime_id'], application_sha256=config_digest(target.document_bundle()),
        disclosure=disclosure, acceptance_set=acceptance,
        policy=dict(schema='daimon-visibility-policy/v2', generation=1, origin='owner-signed-installation',
            **destination, acceptance_digest=config_digest(acceptance), proof_key_id='sha256:' + hashlib.sha256(proof).hexdigest()),
        secrets=dict(telegram_token_file='telegram.token', telegram_token_sha256=hashlib.sha256(token).hexdigest(),
            proof_key_file='proof.key'),
        telegram_qualification=dict(schema='dm.messaging.telegram-qualification/v1', qualified_at_ms=tool.now(),
            token_sha256=hashlib.sha256(token).hexdigest(), get_me_bot_id=123, probe_chat_id=-100123,
            probe_topic_id=None, probe_message_id=1, probe_text_sha256='b' * 64))
    path = directory / 'installation.json'
    path.write_bytes(canonical.canonical_bytes(dict(document=document, binding=create_binding(body, document))))
    path.chmod(0o600)
    adopted = runtime.load_runtime(target.package / 'runtime', 'runtime.json', target._reader, clock=tool.now,
        egress_factory=daemon._visibility_factory(path, clock=tool.now, catalog_mode='migrate'))
    adopted.egress.adopt_closed_visibility_catalogs(version=native_egress.VISIBILITY_SCHEMA_VERSION)
    return path


def prepare(journey, tmp_path, *, semantic_receipts=False):
    tool, sources, public, _, payload = journey
    target = sources[0][1]
    visibility = signed_visibility(target, tmp_path / 'native-visibility')
    source = Source(dict(schema='cluster-onboarding-source/v1', runtime_root=str(target.package / 'runtime'),
        password_file=str(target.root / 'body.unlock'), native_visibility=str(visibility),
        outputs=str(target.home / 'source-output'), applications=[]), code=target.code, code_uid=target.code_uid)
    if semantic_receipts:
        source._load(signed=True).service.communication.upgrade_receipts_v2()
    original = tool.read_public(visibility)
    fingerprint = digest(target.plan)
    packet = source.offer(fingerprint, public[1], payload['plan']['endpoints'])
    response = onboarding_peer.accept(sources[1][1], packet,
        expected_being=public[0]['document']['authority']['manifest']['being_ref'])
    return source, sources[1][1], fingerprint, response, original


def assert_original(source, original):
    current = source.tool.read_public(source.visibility)
    for field in ('disclosure', 'secrets', 'telegram_qualification'):
        assert current['document'][field] == original['document'][field]
    source._load(signed=True).egress.validate_registered_catalogs()


@pytest.mark.parametrize('semantic_receipts', [False, True])
def test_signed_source_retains_native_client_and_peer_under_one_lock(journey, tmp_path, semantic_receipts):
    from daimon_matrix.client import ClientConfig, LocalClient
    source, target, fingerprint, response, original = prepare(journey, tmp_path, semantic_receipts=semantic_receipts)
    custody = (source.root / 'custody.json').read_bytes()
    ready = source.finish(fingerprint, response)
    assert source.finish(fingerprint, response) == ready
    packet = source.tool.read_public(source.directory(fingerprint) / 'offer.json')
    assert source.offer(fingerprint, journey[2][1], journey[4]['plan']['endpoints']) == packet
    assert (source.root / 'custody.json').read_bytes() == custody
    assert_original(source, original)
    assert source._load(signed=True).service.communication.receipts_v2 is semantic_receipts
    from clusterctl import being_seed
    config = source.outputs / 'config.json'
    being_seed._write(config, source.settings)
    unit = source.outputs / 'daimon-matrix-native.service'
    original_unit = b'[Service]\nWorkingDirectory=existing\nLoadCredential=matrix-password:existing\nExecStart=existing\nRestart=on-failure\n'
    unit.write_bytes(original_unit)
    unit.chmod(0o600)
    unit_digest = hashlib.sha256(original_unit).hexdigest()
    import sys
    from pathlib import Path
    import shutil
    # The actual host entry point includes Source, unlike receiving-only code.
    checkout = Path(__file__).resolve().parents[1]
    source.code = tmp_path / 'qualified-host-previous'
    (source.code / 'clusterctl').mkdir(parents=True)
    for filename in ('onboarding_peer.py', 'onboarding_peer_native.py', 'onboarding_source.py'):
        captured = source.code / 'clusterctl' / filename
        shutil.copyfile(checkout / 'clusterctl' / filename, captured)
        captured.chmod(0o644)
    old_tool = source.code / 'clusterctl/onboarding_peer_native.py'
    old_tool.write_bytes(old_tool.read_bytes() + b'\n# Retained previous host generation.\n')
    old_adapter = source.code / 'clusterctl/onboarding_peer.py'
    old_adapter.write_text(old_adapter.read_text().replace(onboarding_peer.TOOL_SHA256,
        hashlib.sha256(old_tool.read_bytes()).hexdigest()))
    source.register(config, unit, unit_digest, target.code / sys.executable, fingerprint)
    source.register(config, unit, unit_digest, target.code / sys.executable, fingerprint)
    successor = tmp_path / 'qualified-host-successor'
    (successor / 'clusterctl').mkdir(parents=True)
    for filename in ('onboarding_peer.py', 'onboarding_peer_native.py', 'onboarding_source.py'):
        shutil.copyfile(checkout / 'clusterctl' / filename, successor / 'clusterctl' / filename)
        (successor / 'clusterctl' / filename).chmod(0o644)
    source.code = successor
    source.register(config, unit, unit_digest, target.code / sys.executable, fingerprint)
    source.register(config, unit, unit_digest, target.code / sys.executable, fingerprint)
    selected_unit = unit.read_bytes()
    assert str(successor).encode() in selected_unit
    foreign = selected_unit.replace(b'WorkingDirectory=existing', b'WorkingDirectory=foreign')
    unit.write_bytes(foreign)
    from clusterctl.onboarding import OnboardingError
    with pytest.raises(OnboardingError, match='existing_onboarding_source_service_preserved'):
        source.register(config, unit, unit_digest, target.code / sys.executable, fingerprint)
    assert unit.read_bytes() == foreign
    unit.write_bytes(selected_unit)
    assert source.settings['applications'] == [fingerprint]
    assert (source.outputs / ('native-unit-' + unit_digest)).read_bytes() == original_unit
    assert b'LoadCredential=matrix-password:existing\n' in unit.read_bytes()
    native = ClientConfig.load(source.root / 'client.json', bytearray((source.root / 'client.key').read_bytes()))
    application = source.directory(fingerprint) / 'application'
    peer = ClientConfig.load(application / 'client.json', bytearray((application / 'client.key').read_bytes()))
    # Restart proves both authenticated surfaces retain their original identity;
    # no inbox, Telegram API or external transport is exercised by this check.
    for _ in range(2):
        stop = threading.Event()
        reader, writer = os.pipe()
        errors = []
        def run():
            try:
                source.serve(stop, ready_descriptor=writer)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            import select
            assert select.select([reader], [], [], 8)[0]
            assert os.read(reader, 16) == b'READY\n'
            assert LocalClient(source.root / 'matrix.sock', native).runtime_status()[1]['ok']
            # Capability authentication is checked by the local hello itself.
            client = LocalClient(source.outputs / ('peer-' + fingerprint[:12] + '.sock'), peer)
            # An invalid send reaches the authenticated peer dispatcher but
            # cannot create or deliver a message.
            assert client.invoke('messaging.send', {})[1]['error']['code'] == 'invalid_params'
        finally:
            stop.set()
            thread.join(timeout=10)
            os.close(reader)
        assert not thread.is_alive() and errors == []
    assert_original(source, original)


def test_lost_source_ack_after_publication_keeps_native_daemon_restartable(journey, tmp_path):
    source, _, fingerprint, response, original = prepare(journey, tmp_path)
    replace = source.tool.replace_document
    failures = []
    def interrupted(path, value):
        replace(path, value)
        if not failures:
            failures.append(True)
            raise OSError('lost source publication ACK')
    source.tool.replace_document = interrupted
    with pytest.raises(OSError, match='lost source publication ACK'):
        source.finish(fingerprint, response)
    assert_original(source, original)
    source.tool.replace_document = replace
    source.finish(fingerprint, response)
    assert_original(source, original)
