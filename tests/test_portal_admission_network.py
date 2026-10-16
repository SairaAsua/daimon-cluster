"""Synthetic setup ownership/recovery; no actual firewall or Incus mutations."""
import copy
import json
from types import SimpleNamespace

import pytest

from tests.integration import portal_admission_network as network


@pytest.fixture
def selected():
    return dict(bridge=network.BRIDGE, subnet=network.SUBNET, owners={
        'q232-mixed-source': dict(address='10.99.227.1', port=46129),
        'q232-mixed': dict(address='10.99.227.2', port=52659),
        network.NAME: dict(address='10.99.227.3', port=42831)})


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
    monkeypatch.setattr(network, 'scope', lambda root: (backend, group))
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
            return json.dumps([dict(devices=devices, expanded_devices=expanded)])
        if args[0] == 'exec':
            return json.dumps([dict(ifname=network.INTERFACE)] if collision == 'interface' else [])
        pytest.fail('unexpected operation: '+str(args))
    monkeypatch.setattr(network, 'incus', incus)
    for action in (network.prepare, network.remove):
        with pytest.raises(ValueError, match='preserve'):
            action(tmp_path)


def test_cleanup_removes_firewall_in_one_transaction_and_retries_absent(selected, monkeypatch, tmp_path):
    owners = {name: dict(profile='source') for name in selected['owners']}
    monkeypatch.setattr(network, 'scope', lambda root: (None, dict(owners=owners)))
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
