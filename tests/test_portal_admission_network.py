"""Synthetic setup ownership/recovery; no actual firewall or Incus mutations."""
import copy
import json
import uuid
from types import SimpleNamespace

import pytest

from tests.integration import portal_admission_network as network


@pytest.fixture
def selected():
    value = dict(schema='cluster-synthetic-admission-network/v1', bridge=network.BRIDGE, subnet=network.SUBNET, owners={
        'q232-mixed-source': dict(address='10.99.227.1', port=46129),
        'q232-mixed': dict(address='10.99.227.2', port=52659),
        network.NAME: dict(address='10.99.227.3', port=42831)})
    for name in ('q232-mixed', network.NAME):
        value['owners'][name].update(instance='dm-'+name, instance_uuid=str(uuid.uuid5(uuid.NAMESPACE_DNS, name)),
            plan_digest=network.digest(dict(name=name)))
    return value


@pytest.fixture
def legacy(monkeypatch):
    owner = dict(plan=dict(name='q232-mixed'),
        root='/home/agent/.local/state/daimon-onboarding/q232-mixed/matrix/package/runtime')
    runtime = dict(state_root_identity=dict(device=91, inode=45561),
        local_origin=dict(body_ref='codex:daimon-cluster:q232-mixed'), runtime_bundle_sha256='a'*64)
    loaded = dict(schema='cluster-guest-bootstrap-loaded/v1', loaded_runtime=runtime,
        process=dict(boot_id='original-container-boot'))
    record = dict(actual_admitted_parent=True, actual_host_backend=True, production_effects=0, loaded=loaded)
    baseline = dict(observed=dict(plan_digest=network.digest(owner['plan']),
        origin=runtime['local_origin'], process=loaded['process']))
    monkeypatch.setattr(network.being_seed, '_read', lambda path:
        record if path.name == 'guest-compatible-rollback-loaded.json' else baseline)
    actual = dict(state_root_identity=runtime['state_root_identity'], uid=1000,
        boot_id=loaded['process']['boot_id'], runtime_bundle_sha256=runtime['runtime_bundle_sha256'])
    def inspect(*args):
        assert args[:7] == ('exec', 'dm-q232-mixed', '--user', '1000', '--group', '1000', '--')
        assert args[7:12] == ('/usr/bin/python3', '-I', '-S', '-B', '-c')
        assert args[-1] == owner['root']
        return json.dumps(actual)
    monkeypatch.setattr(network, 'incus', inspect)
    return owner, record, baseline, actual


def test_legacy_guest_uses_its_real_retained_plan_runtime_and_boot(legacy):
    owner, _record, _baseline, _actual = legacy
    assert network.legacy_guest_owned(owner)


@pytest.mark.parametrize('field', ['state_root_identity', 'uid', 'boot_id', 'runtime_bundle_sha256'])
def test_replaced_legacy_guest_refused(legacy, field):
    owner, _record, _baseline, actual = legacy
    actual[field] = {'device': 92, 'inode': 45561} if field == 'state_root_identity' else 'replaced'
    assert not network.legacy_guest_owned(owner)


@pytest.mark.parametrize('boundary', ['plan', 'origin', 'boot', 'record'])
def test_legacy_evidence_must_bind_the_original_authorized_owner(legacy, boundary):
    owner, record, baseline, _actual = legacy
    if boundary == 'plan':
        baseline['observed']['plan_digest'] = 'b'*64
    elif boundary == 'origin':
        baseline['observed']['origin'] = dict(body_ref='foreign')
    elif boundary == 'boot':
        baseline['observed']['process'] = dict(boot_id='different-boot')
    else:
        record['actual_admitted_parent'] = False
    assert not network.legacy_guest_owned(owner)


def test_unrelated_guest_cannot_use_the_legacy_exception(legacy, monkeypatch):
    owner, _record, _baseline, _actual = legacy
    owner['plan'] = dict(name=network.NAME)
    monkeypatch.setattr(network, 'incus', lambda *args: pytest.fail('unrelated guest queried'))
    assert not network.legacy_guest_owned(owner)


@pytest.mark.parametrize('marker,legacy_owned,accepted,calls', [
    ('correct', True, True, 0), (None, True, True, 1),
    ('foreign', True, False, 0), (None, False, False, 1)])
def test_instance_marker_conflicts_never_fall_back_to_legacy_proof(
        monkeypatch, tmp_path, marker, legacy_owned, accepted, calls):
    owners = {name: dict(profile='guest', plan=dict(name=name))
        for name in (network.NAME, 'q232-mixed')}
    group = dict(owners=owners)
    backend = SimpleNamespace(config=SimpleNamespace(qualification=True), authorize=lambda *args: True)
    monkeypatch.setattr(network.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(network.HostConfig, 'load', lambda path: None)
    monkeypatch.setattr(network, 'HostBackend', lambda config: backend)
    monkeypatch.setattr(network.being_seed, '_read', lambda path:
        dict(synthetic=True, name=network.NAME) if path.name == 'scope.json' else group)
    instances = [dict(name='dm-'+name, config={'user.dm.onboarding-plan': network.digest(owner['plan']),
            'volatile.uuid': str(uuid.uuid5(uuid.NAMESPACE_DNS, name))})
        for name, owner in owners.items()]
    legacy_instance = next(row for row in instances if row['name'] == 'dm-q232-mixed')
    if marker != 'correct':
        legacy_instance['config'].pop('user.dm.onboarding-plan')
        if marker is not None:
            legacy_instance['config']['user.dm.onboarding-plan'] = marker
    monkeypatch.setattr(network, 'incus', lambda *args: json.dumps([row for row in instances if len(args) < 3 or row['name'] == args[1]]))
    queried = []
    def inspect(owner):
        queried.append(owner)
        return legacy_owned
    monkeypatch.setattr(network, 'legacy_guest_owned', inspect)
    if accepted:
        actual_backend, actual_group, pins = network.scope(tmp_path)
        assert (actual_backend, actual_group) == (backend, group)
        assert set(pins) == set(owners)
    else:
        with pytest.raises(ValueError, match='original synthetic instance'):
            network.scope(tmp_path)
    assert len(queried) == calls


@pytest.fixture
def retained_scope(selected, monkeypatch, tmp_path):
    owners = {name: dict(profile='source' if name == 'q232-mixed-source' else 'guest',
        plan=dict(name=name)) for name in selected['owners']}
    group = dict(owners=owners)
    backend = SimpleNamespace(config=SimpleNamespace(qualification=True), authorize=lambda *args: True)
    monkeypatch.setattr(network.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(network.HostConfig, 'load', lambda path: None)
    monkeypatch.setattr(network, 'HostBackend', lambda config: backend)
    monkeypatch.setattr(network.being_seed, '_read', lambda path:
        dict(synthetic=True, name=network.NAME) if path.name == 'scope.json'
        else selected if path.name == 'network-scope.json' else group)
    instances = [dict(name=row['instance'], config={'volatile.uuid': row['instance_uuid'],
        **({'user.dm.onboarding-plan': row['plan_digest']} if name != 'q232-mixed' else {})})
        for name, row in selected['owners'].items() if name != 'q232-mixed-source']
    monkeypatch.setattr(network, 'incus', lambda *args: json.dumps(instances))
    (tmp_path/'network-scope.json').touch()
    return tmp_path, selected, instances


def test_retained_physical_ownership_survives_legitimate_runtime_republication(retained_scope, monkeypatch):
    root, _selected, _instances = retained_scope
    monkeypatch.setattr(network, 'legacy_guest_owned', lambda *args: pytest.fail('mutable runtime rechecked'))
    assert set(network.scope(root)[2]) == {network.NAME, 'q232-mixed'}


@pytest.mark.parametrize('boundary', ['uuid', 'plan', 'marker', 'missing-pin', 'missing-owner', 'extra-pin'])
def test_retained_scope_never_backfills_or_accepts_replacements(retained_scope, monkeypatch, boundary):
    root, selected, instances = retained_scope
    row = selected['owners']['q232-mixed']
    if boundary == 'uuid':
        instances[0]['config']['volatile.uuid'] = str(uuid.uuid4())
    elif boundary == 'plan':
        row['plan_digest'] = 'b'*64
    elif boundary == 'marker':
        instances[0]['config']['user.dm.onboarding-plan'] = 'b'*64
    elif boundary == 'missing-pin':
        row.pop('instance_uuid')
    elif boundary == 'missing-owner':
        selected['owners'].pop(network.NAME)
    else:
        row['new'] = 'foreign'
    monkeypatch.setattr(network, 'legacy_guest_owned', lambda *args: pytest.fail('retained scope backfilled'))
    with pytest.raises(ValueError):
        network.scope(root)


def test_initial_legacy_proof_is_bracketed_by_the_same_instance(retained_scope, monkeypatch):
    root, _selected, instances = retained_scope
    (root/'network-scope.json').unlink()
    monkeypatch.setattr(network, 'legacy_guest_owned', lambda *args: True)
    def inspect(*args):
        rows = copy.deepcopy(instances)
        if args[1] != '--format=json':
            rows = [row for row in rows if row['name'] == args[1]]
            rows[0]['config']['volatile.uuid'] = str(uuid.uuid4())
        return json.dumps(rows)
    monkeypatch.setattr(network, 'incus', inspect)
    with pytest.raises(ValueError, match='original synthetic instance'):
        network.scope(root)


def test_firewall_recovers_exact_or_cleanup_subset_but_rejects_changed_rules(selected):
    expected = network.desired_firewall(selected)
    # Handles/order are kernel observations, not new ownership. No post-effect receipt needed.
    actual = [{kind: dict(row, handle=index+1)} for index, item in enumerate(expected)
        for kind, row in item.items()]
    assert network.validate_firewall(list(reversed(actual)), expected, subset=False)
    assert network.validate_firewall([], expected, subset=False) == []
    assert network.validate_firewall(actual[1:], expected, subset=True)
    with pytest.raises(ValueError):
        network.validate_firewall(actual[1:], expected, subset=False)
    changed = copy.deepcopy(actual)
    changed[-1]['rule']['expr'][-1] = {'drop': None}
    with pytest.raises(ValueError):
        network.validate_firewall(changed, expected, subset=True)
    with pytest.raises(ValueError):
        network.validate_firewall([*actual, actual[-1]], expected, subset=True)


def test_return_rule_requires_established_guest_service_source_port(selected):
    rows = network.desired_firewall(selected)
    early = [item['rule'] for item in rows if item.get('rule', {}).get('table') == network.TABLE
        and item['rule']['chain'] == 'input']
    assert len(early) == 3
    returned = early[1]['expr']
    assert {'match': {'op': 'in', 'left': {'ct': {'key': 'state'}}, 'right': 'established'}} in returned
    assert {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'sport'}},
        'right': {'set': [42831, 52659]}}} in returned
    assert early[-1]['expr'] == [
        {'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': network.BRIDGE}}, {'drop': None}]


@pytest.mark.parametrize('collision', ['bridge', 'device', 'inherited', 'interface'])
def test_foreign_resources_refused_before_prepare_or_remove_effects(selected, monkeypatch, tmp_path, collision):
    group = {'owners': {name: {'profile': 'source' if name == 'q232-mixed-source' else 'guest', 'plan': {'name': name}}
        for name in selected['owners']}}
    backend = SimpleNamespace(_dispatch=lambda *args: pytest.fail('mutation before ownership checks'))
    monkeypatch.setattr(network, 'scope', lambda root: (backend, group, {}))
    monkeypatch.setattr(network.being_seed, '_read', lambda path: selected)
    monkeypatch.setattr(network, 'retain', lambda *args: None)
    monkeypatch.setattr(network, 'firewall', lambda: pytest.fail('firewall reached before ownership refusal'))
    for filename in ('network-scope.json', 'network-firewall-expected.json'):
        (tmp_path/filename).touch()
    def host(argv, **kwargs):
        assert argv[:3] == ['ip', '-j', 'link'] or argv[:4] == ['ip', '-j', '-4', 'route']
        return '[]'
    monkeypatch.setattr(network, 'command', host)
    def incus(*args):
        if args[:2] == ('network', 'list'):
            if collision == 'bridge':
                return json.dumps([dict(name=network.BRIDGE, type='bridge', managed=True, config={}, used_by=[])])
            return '[]'
        if args[0] == 'list':
            devices = {network.DEVICE: {'type': 'nic', 'network': 'foreign'}} if collision == 'device' else {}
            expanded = {network.DEVICE: network.NIC} if collision == 'inherited' else devices
            name = args[1][3:]
            return json.dumps([dict(name=args[1], config={'volatile.uuid': selected['owners'][name]['instance_uuid'],
                'user.dm.onboarding-plan': selected['owners'][name]['plan_digest']},
                devices=devices, expanded_devices=expanded)])
        if args[0] == 'exec':
            return json.dumps([dict(ifname=network.INTERFACE)] if collision == 'interface' else [])
        pytest.fail('unexpected operation: '+str(args))
    monkeypatch.setattr(network, 'incus', incus)
    for action in (network.prepare, network.remove):
        with pytest.raises(ValueError, match='preserve'):
            action(tmp_path)


def test_cleanup_removes_firewall_in_one_transaction_and_retries_absent(selected, monkeypatch, tmp_path):
    owners = {name: dict(profile='source') for name in selected['owners']}
    monkeypatch.setattr(network, 'scope', lambda root: (None, dict(owners=owners), {}))
    monkeypatch.setattr(network, 'validate_resources', lambda *args: (False, {}))
    expected = network.desired_firewall(selected)
    contract = dict(selection_sha256=network.digest(selected), nftables=expected)
    monkeypatch.setattr(network.being_seed, '_read', lambda path:
        selected if path.name == 'network-scope.json' else contract)
    rows = [{kind: dict(row, handle=index+1)} for index, item in enumerate(expected)
        for kind, row in item.items()]
    state = [rows]
    monkeypatch.setattr(network, 'firewall', lambda: state[0])
    batches = []
    def dispatch(argv, *, text):
        assert argv == ['nft', '-j', '-f', '-']
        batches.append(json.loads(text)['nftables'])
        state[0] = []
        raise OSError('lost successful transaction reply')
    monkeypatch.setattr(network, 'command', dispatch)
    with pytest.raises(OSError):
        network.remove(tmp_path)
    assert len(batches) == 1 and len(batches[0]) == 4
    assert network.remove(tmp_path)['removed']
    assert len(batches) == 1


def test_prepare_and_remove_share_one_nonblocking_fixture_lock(tmp_path):
    with network.being_seed._locked(tmp_path):
        for action in (network.prepare, network.remove):
            with pytest.raises(network.being_seed.SeedError, match='seed_operation_in_progress'):
                action(tmp_path)
