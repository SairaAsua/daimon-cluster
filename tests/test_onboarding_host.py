"""Typed substrate commands preserve foreign bodies and reconcile partial creation."""
import copy
import json
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import JobStore, OnboardingError, digest
from clusterctl.onboarding_host import HostBackend, HostConfig
from tests.test_onboarding import plan


def test_only_typed_context_install_has_the_large_archive_deadline(monkeypatch):
    from clusterctl import onboarding_host
    calls = []

    def run(argv, **kwargs):
        calls.append(kwargs['timeout'])
        return SimpleNamespace(returncode=0, stdout='{}')

    monkeypatch.setattr(onboarding_host.subprocess, 'run', run)
    HostBackend._run(['exec', 'dm-fixture', '--', 'python3', 'execute', 'context', '--home', '/home/agent'])
    HostBackend._run(['exec', 'dm-fixture', '--', 'python3', 'execute', 'memory', '--home', '/home/agent'])
    HostBackend._run(['list', '--format=json'])
    assert calls == [7200, 1800, 1800]


class IncusFixture:
    def __init__(self):
        self.instances = []
        self.volumes = []
        self.calls = []
        self.fail_after = None

    def __call__(self, argv):
        if argv[0] == "list":
            return json.dumps(self.instances)
        if argv[:3] == ["storage", "volume", "list"]:
            return json.dumps(self.volumes)
        if argv[0] == "query":
            return json.dumps(next(v for v in self.volumes if argv[1].endswith("/" + v["name"])))
        self.calls.append(argv)
        if argv[0] == "init":
            self.instances.append(dict(name=argv[2], status="Stopped", config={
                "volatile.base_image": argv[1], "user.dm.onboarding-plan": argv[-1].split("=", 1)[1]},
                expanded_devices={"root": dict(type="disk", path="/", pool=argv[6], size="8GiB")}))
        elif argv[:3] == ["storage", "volume", "create"]:
            self.volumes.append(dict(name=argv[4], type="custom", config={
                "size": "22GiB", "user.dm.onboarding-plan": argv[6].split("=", 1)[1]}))
        elif argv[:3] == ["config", "device", "add"]:
            if not 1 <= len(argv[4]) <= 63:
                raise OnboardingError("incus_device_name_limit")
            row = next(row for row in self.instances if row["name"] == argv[3])
            row["expanded_devices"][argv[4]] = dict(type="disk", **dict(item.split("=", 1) for item in argv[6:]))
        elif argv[0] == "start":
            next(row for row in self.instances if row["name"] == argv[1])["status"] = "Running"
        else:
            raise AssertionError("unexpected command")
        if len(self.calls) == self.fail_after:
            raise RuntimeError("transport disconnected after effect")
        return ""


def configured(tmp_path):
    for name in ("jobs", "grants"):
        (tmp_path / name).mkdir(mode=0o700)
    config = HostConfig(tmp_path / "jobs", tmp_path / "grants", "3" * 64, "4" * 64,
                        "2" * 64, "daimon-cluster", "daimon-agent", 2)
    value = plan()
    being_seed._write(config.grants / "eko.json", dict(schema="cluster-onboarding-host-grant/v1",
                                                      plan=value, revoked=False))
    run = IncusFixture()
    return config, value, run, HostBackend(config, run=run)


@pytest.mark.parametrize('optional', [{}, {'group': {}}, {'receiving_controller': {}},
                                     {'group': {}, 'receiving_controller': {}}])
def test_matrix_observation_wrapper_retains_supported_selection_metadata(tmp_path, optional):
    """Wrapper seam; Target tests authenticate these receiving observations."""
    _,value,_,backend=configured(tmp_path)
    observed=dict(phase='v8',request={},receipt={},**optional)
    backend._target_call=lambda *_args,**_kwargs:observed
    assert backend._matrix_command(value,'observe') is observed


@pytest.mark.parametrize('change', ['unknown-field','missing-receipt','invalid-phase'])
def test_matrix_observation_wrapper_still_rejects_unrecognized_contract(tmp_path, change):
    _,value,_,backend=configured(tmp_path)
    observed=dict(phase='v8',request={},receipt={})
    if change=='unknown-field':
        observed['unexpected']={}
    elif change=='missing-receipt':
        del observed['receipt']
    else:
        observed['phase']='controller-ready'
    backend._target_call=lambda *_args,**_kwargs:observed
    with pytest.raises(OnboardingError,match='invalid_onboarding_observation'):
        backend._matrix_command(value,'observe')


def test_exact_receiving_mount_can_keep_its_existing_operational_alias(tmp_path):
    _, value, run, backend = configured(tmp_path)
    desired = {"type": "disk", "source": "/qualified/source", "path": "/opt/qualified-code",
               "readonly": "true", "shift": "true"}
    run.instances.append({"name": "dm-eko", "expanded_devices": {"existing-alias": desired.copy()}})
    expected = {"generated-name": desired}
    assert backend._mounted(value, expected)
    for field in desired:
        run.instances[0]["expanded_devices"]["existing-alias"][field] = "different"
        assert not backend._mounted(value, expected)
        run.instances[0]["expanded_devices"]["existing-alias"][field] = desired[field]
    # An occupied canonical name with different contents is still a conflict.
    run.instances[0]["expanded_devices"]["generated-name"] = {**desired, "source": "/foreign"}
    with pytest.raises(OnboardingError, match="foreign_receiving_mount_preserved"):
        backend._mounted(value, expected)
    assert not run.calls


@pytest.mark.parametrize("failed_command", [1, 2, 3, 4])
def test_each_partial_effect_reconciles_without_recreating(tmp_path, failed_command):
    config, value, run, backend = configured(tmp_path)
    store = JobStore(config.jobs)
    store.submit(value, backend)
    run.fail_after = failed_command
    assert store.tick("eko", backend)["active"] is False
    run.fail_after = None
    assert store.tick("eko", backend)["completed_steps"] == ["environment"]
    assert len(run.calls) == 4
    assert backend.observe(value, "environment", "unused").facts == {
        "verified": True, "root_gib": 8, "home_gib": 22}


@pytest.mark.parametrize("foreign", ["body", "volume", "device"])
def test_foreign_state_is_not_mutated(tmp_path, foreign):
    config, value, run, backend = configured(tmp_path)
    if foreign == "body":
        run.instances.append(dict(name="dm-eko", config={}, expanded_devices={}))
    elif foreign == "volume":
        run.volumes.append(dict(name="dm-eko-home", type="custom", config={"size": "22GiB"}))
    else:
        backend.execute(value, "environment", "unused")
        run.instances[0]["expanded_devices"]["home"]["source"] = "other-being-home"
        run.calls.clear()
    before = copy.deepcopy((run.instances, run.volumes))
    assert backend.observe(value, "environment", "unused").state == "conflict"
    with pytest.raises(OnboardingError):
        backend.execute(value, "environment", "unused")
    assert (run.instances, run.volumes) == before and run.calls == []


def test_intake_label_and_revoked_or_different_grant_cannot_authorize(tmp_path):
    config, value, run, backend = configured(tmp_path)
    assert backend.authorize(value, digest(value))
    assert not backend.authorize(plan(owner="ani"), digest(plan(owner="ani")))
    assert not backend.authorize(value, "5" * 64)
    grant = config.grants / "eko.json"
    being_seed._write(grant, dict(schema="cluster-onboarding-host-grant/v1", plan=value, revoked=True))
    assert not backend.authorize(value, digest(value))
    with pytest.raises(OnboardingError, match="host_authorization_required"):
        backend.execute(value, "environment", "unused")
    assert not run.calls


def test_revocation_during_creation_stops_before_the_next_resource_effect(tmp_path):
    config, value, run, backend = configured(tmp_path)
    original = backend.run
    def revoke_after_init(argv):
        result = original(argv)
        if argv[0] == "init":
            being_seed._write(config.grants / "eko.json", dict(schema="cluster-onboarding-host-grant/v1",
                                                              plan=value, revoked=True))
        return result
    backend.run = revoke_after_init
    with pytest.raises(OnboardingError, match="host_authorization_required"):
        backend.execute(value, "environment", "unused")
    assert len(run.calls) == 1
    assert len(run.instances) == 1 and not run.volumes


def test_verified_v8_lifecycle_retry_never_reenters_credential_writer(tmp_path, monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace

    config, value, run, _ = configured(tmp_path)
    (tmp_path / 'views').mkdir(mode=0o700)
    config = replace(config, views=tmp_path / 'views')
    backend = HostBackend(config, run=run)
    backend.execute(value, 'environment', 'unused')
    run.instances[0]['expanded_devices']['onboarding-matrix-public'] = backend._matrix_mount(value)
    run.calls.clear()
    root = tmp_path / 'custody'
    (root / digest(value)).mkdir(mode=0o700, parents=True)
    being_seed._write(root / digest(value) / 'genesis.json', {})
    published, actions = [], []
    monkeypatch.setattr('clusterctl.onboarding_mounts.prepare_matrix_public',
                        lambda _views, _plan, documents: published.append(documents))
    def current(_plan, action):
        actions.append(action)
        assert action == 'observe'
        return dict(phase='v8')
    backend._matrix_command = current
    backend._matrix_execute(value, SimpleNamespace(root=root))
    assert actions == ['observe'] and published == [{'genesis.json': {}}]
    assert run.calls == []


def test_access_installs_only_dedicated_ssh_and_does_not_claim_provider(tmp_path, monkeypatch):
    from dataclasses import replace
    config, value, run, _ = configured(tmp_path)
    backend = HostBackend(replace(config, code=tmp_path, consent_state=tmp_path), run=run)
    monkeypatch.setattr(backend, '_ssh_key', lambda _plan: 'public fixture key')
    calls = []
    def ssh(_plan, action, key):
        calls.append(action)
        return dict(installed='install' in calls)
    monkeypatch.setattr(backend, '_ssh_command', ssh)
    assert backend.observe(value, 'access', 'unused').state == 'absent'
    backend.execute(value, 'access', 'unused')
    result = backend.observe(value, 'access', 'unused')
    assert result.state == 'waiting' and result.facts == {}
    assert calls == ['observe', 'install', 'observe']


def test_private_connections_are_owner_scoped_and_never_return_bot_token(tmp_path, monkeypatch):
    import os
    from dataclasses import replace
    config, value, run, _ = configured(tmp_path)
    backend = HostBackend(replace(config, consent_state=tmp_path, consent_uid=os.geteuid()), run=run)
    monkeypatch.setattr(backend, '_decision', lambda _plan: {'approved': True})
    directory = tmp_path / 'being-seeds/eko'
    directory.mkdir(mode=0o700, parents=True)
    record = dict(schema=being_seed.SCHEMA, name='eko', created_by=value['owner'])
    being_seed._write(directory / 'record.json', record)
    key = 'ssh-ed25519 ' + 'A' * 43
    being_seed._write(directory / 'connections.json', dict(ssh_public_key=key, telegram_bot_token='fixture secret'))
    assert backend._ssh_key(value) == key
    (directory / 'connections.json').chmod(0o644)
    with pytest.raises(OnboardingError, match='private_onboarding_connections_required'):
        backend._ssh_key(value)
    (directory / 'connections.json').chmod(0o600)
    being_seed._write(directory / 'record.json', {**record, 'created_by': 'other'})
    with pytest.raises(OnboardingError, match='account_authorization_required'):
        backend._ssh_key(value)
