"""Owned private L2 network for the retained synthetic admission journey.

One NIC per guest, unchanged native HTTP and signed membership. No NAT, DHCP,
default route, pairwise proxy or change to an existing administrative rule.
All ownership checks precede mutation; retained desired rules recover lost ACKs.
"""
from __future__ import annotations

import argparse
from collections import Counter
from functools import wraps
import ipaddress
import json
import os
import socket
import subprocess
from pathlib import Path

from clusterctl import being_seed
from clusterctl.onboarding import digest
from clusterctl.onboarding_host import HostBackend, HostConfig
from tests.integration.portal_admission_fixture import NAME, incus, retain

BRIDGE = 'q227br'
TABLE = 'q227_qualification'
SUBNET = '10.99.227.0/29'
DEVICE = 'qualification-network'
INTERFACE = 'qnet0'
COMMENT = 'q227-synthetic-data'
NIC = dict(type='nic', network=BRIDGE, name=INTERFACE)


def command(argv: list[str], *, text: str | None = None) -> str:
    return subprocess.run(argv, input=text, text=True, capture_output=True,
        check=True, timeout=60).stdout


def firewall() -> list[dict]:
    return json.loads(command(['nft', '-j', 'list', 'ruleset']))['nftables']


def owned_firewall(rows: list[dict]) -> list[dict]:
    result = []
    for item in rows:
        for kind, row in item.items():
            if (isinstance(row, dict) and (row.get('table') == TABLE
                    or kind == 'table' and row.get('name') == TABLE
                    or kind == 'rule' and row.get('comment') == COMMENT)):
                result.append({kind: {key: value for key, value in row.items() if key != 'handle'}})
    return result


def scope(root: Path) -> tuple[HostBackend, dict]:
    if os.geteuid() != 0:
        raise ValueError('the synthetic host controller is required')
    value = being_seed._read(root/'scope.json')
    backend = HostBackend(HostConfig.load(root/'host.json'))
    if not value['synthetic'] or value['name'] != NAME or not backend.config.qualification:
        raise ValueError('only the retained synthetic fixture is supported')
    group = being_seed._read(root/'group.json')
    guests = {name: row for name, row in group['owners'].items() if row['profile'] == 'guest'}
    if set(guests) != {NAME, 'q232-mixed'}:
        raise ValueError('preserve the original synthetic owner set')
    instances = {row['name']: row for row in json.loads(incus('list', '--format=json'))}
    for name, row in guests.items():
        if (not backend.authorize(row['plan'], digest(row['plan']))
                or instances['dm-'+name]['config'].get('user.dm.onboarding-plan') != digest(row['plan'])):
            raise ValueError('the exact original synthetic instance is required')
    return backend, group


def settings(selected: dict) -> dict:
    return {'ipv4.address': '10.99.227.1/29', 'ipv4.nat': 'false', 'ipv4.dhcp': 'false',
        'ipv4.routing': 'false', 'ipv4.firewall': 'false', 'ipv6.address': 'none',
        'ipv6.firewall': 'false', 'dns.mode': 'none', 'user.dm.synthetic-admission': digest(selected)}


def validate_resources(selected: dict, group: dict) -> tuple[bool, dict[str, bool]]:
    """Reject foreign bridge, inherited device and interface collisions first."""
    if ((selected['bridge'], selected['subnet']) != (BRIDGE, SUBNET)
            or set(selected['owners']) != set(group['owners'])
            or [selected['owners'][name]['address'] for name in
                ('q232-mixed-source', 'q232-mixed', NAME)] !=
                ['10.99.227.1', '10.99.227.2', '10.99.227.3']):
        raise ValueError('preserve the recorded network')
    networks = {row['name']: row for row in json.loads(incus('network', 'list', '--format=json'))}
    exists = BRIDGE in networks
    if exists:
        network = networks[BRIDGE]
        if (network['type'] != 'bridge' or not network['managed']
                or any(network['config'].get(key) != value for key, value in settings(selected).items())
                or any(url.rsplit('/', 1)[-1] not in {'dm-'+NAME, 'dm-q232-mixed'}
                    for url in network.get('used_by', []))):
            raise ValueError('preserve the existing bridge configuration and users')
    links = json.loads(command(['ip', '-j', 'link', 'show']))
    if not exists and any(row['ifname'] == BRIDGE for row in links):
        raise ValueError('preserve the existing host interface')
    subnet = ipaddress.ip_network(SUBNET)
    for row in json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])):
        if row.get('dst') not in {None, 'default'}:
            if ipaddress.ip_network(row['dst'], strict=False).overlaps(subnet):
                if not exists or row.get('dev') != BRIDGE:
                    raise ValueError('preserve the existing overlapping network')
    devices_present = {}
    for name, owner in group['owners'].items():
        if owner['profile'] != 'guest':
            continue
        instance = 'dm-'+name
        config = json.loads(incus('list', instance, '--format=json'))[0]
        devices = config['devices']
        expanded = config.get('expanded_devices', devices)
        if DEVICE in expanded and (devices.get(DEVICE) != NIC or expanded[DEVICE] != NIC):
            raise ValueError('preserve the existing or inherited instance device')
        if any(key != DEVICE and (row.get('name') == INTERFACE or row.get('network') == BRIDGE)
                for key, row in expanded.items()):
            raise ValueError('preserve the existing network device binding')
        guest_links = json.loads(incus('exec', instance, '--', 'ip', '-j', 'link', 'show'))
        if DEVICE not in devices and any(row['ifname'] == INTERFACE for row in guest_links):
            raise ValueError('preserve the existing guest interface')
        devices_present[name] = DEVICE in devices
    return exists, devices_present


def desired_firewall(selected: dict) -> list[dict]:
    """Kernel JSON expressions are the pre-effect ownership contract."""
    ports = sorted({row['port'] for row in selected['owners'].values()})
    if len(ports) != 3 or any(type(port) is not int or not 1024 <= port <= 65535 for port in ports):
        raise ValueError('distinct non-administrative test ports are required')
    source_port = selected['owners']['q232-mixed-source']['port']
    guest_ports = sorted(row['port'] for name, row in selected['owners'].items()
        if name != 'q232-mixed-source')

    def match(left: dict, right: object, op: str = '==') -> dict:
        return dict(match=dict(op=op, left=left, right=right))

    def meta(key: str, value: str, op: str = '==') -> dict:
        return match(dict(meta=dict(key=key)), value, op)

    def payload(protocol: str, field: str, value: object) -> dict:
        return match(dict(payload=dict(protocol=protocol, field=field)), value)

    def rule(table: str, chain: str, expressions: list[dict], verdict: str = 'accept') -> dict:
        row = dict(family='inet', table=table, chain=chain, expr=[*expressions, {verdict: None}])
        if table == 'daimon-fw':
            row['comment'] = COMMENT
        return dict(rule=row)

    ingress = [meta('iifname', BRIDGE),
        payload('ip', 'saddr', {'set': ['10.99.227.2', '10.99.227.3']}),
        payload('ip', 'daddr', '10.99.227.1')]
    forward = [meta('iifname', BRIDGE), meta('oifname', BRIDGE),
        payload('ip', 'saddr', {'prefix': dict(addr='10.99.227.0', len=29)}),
        payload('ip', 'daddr', {'prefix': dict(addr='10.99.227.0', len=29)})]
    established = match({'ct': {'key': 'state'}}, 'established', 'in')
    return [
        dict(table=dict(family='inet', name=TABLE)),
        dict(chain=dict(family='inet', table=TABLE, name='input', type='filter', hook='input',
            prio=-20, policy='accept')),
        rule(TABLE, 'input', [*ingress, payload('tcp', 'dport', source_port)]),
        rule(TABLE, 'input', [*ingress, established, payload('tcp', 'sport', {'set': guest_ports})]),
        rule(TABLE, 'input', [meta('iifname', BRIDGE)], 'drop'),
        dict(chain=dict(family='inet', table=TABLE, name='forward', type='filter', hook='forward',
            prio=-20, policy='accept')),
        rule(TABLE, 'forward', [meta('iifname', BRIDGE), meta('oifname', BRIDGE, '!=')], 'drop'),
        rule(TABLE, 'forward', [meta('oifname', BRIDGE), meta('iifname', BRIDGE, '!=')], 'drop'),
        rule('daimon-fw', 'input', [*ingress, payload('tcp', 'dport', source_port)]),
        rule('daimon-fw', 'forward', [*forward, payload('tcp', 'dport', {'set': ports})]),
        rule('daimon-fw', 'forward', [*forward, established, payload('tcp', 'sport', {'set': ports})]),
    ]


def validate_firewall(rows: list[dict], expected: list[dict], *, subset: bool) -> list[dict]:
    actual = owned_firewall(rows)
    counts = Counter(json.dumps(row, sort_keys=True) for row in actual)
    desired = Counter(json.dumps(row, sort_keys=True) for row in expected)
    if (counts - desired) or (not subset and counts and counts != desired):
        raise ValueError('preserve foreign or modified firewall objects')
    return actual


def serialized(function):
    @wraps(function)
    def call(root: Path) -> dict:
        with being_seed._locked(root):
            return function(root)
    return call


@serialized
def prepare(root: Path) -> dict:
    backend, group = scope(root)
    path = root/'network-scope.json'
    if not path.exists():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        retain(path, dict(schema='cluster-synthetic-admission-network/v1', bridge=BRIDGE,
            subnet=SUBNET, owners={
                'q232-mixed-source': dict(address='10.99.227.1', port=46129),
                'q232-mixed': dict(address='10.99.227.2', port=52659),
                NAME: dict(address='10.99.227.3', port=port)}))
    selected = being_seed._read(path)
    exists, devices = validate_resources(selected, group)
    expected = desired_firewall(selected)
    # Durable before dispatch: an absent post-effect receipt never loses ownership.
    contract = dict(selection_sha256=digest(selected), nftables=expected)
    retain(root/'network-firewall-expected.json', contract)
    # Complete a previous lost file/directory-fsync acknowledgment on retry.
    being_seed._write(root/'network-scope.json', selected)
    being_seed._write(root/'network-firewall-expected.json', contract)
    rules = firewall()
    actual = validate_firewall(rules, expected, subset=False)
    if not actual:
        retain(root/'network-firewall-before.json', dict(nftables=rules))
        command(['nft', '-j', '-f', '-'], text=json.dumps(dict(nftables=[{'add': row} for row in expected])))
    if not validate_firewall(firewall(), expected, subset=False):
        raise ValueError('the expected firewall transaction is not installed')
    if not exists:
        incus('network', 'create', BRIDGE, *[key+'='+value for key, value in settings(selected).items()])
    for name, owner in group['owners'].items():
        if owner['profile'] != 'guest':
            continue
        plan = owner['plan']
        instance = backend.instance(plan)
        if not devices[name]:
            backend._dispatch(plan, ['config', 'device', 'add', instance, DEVICE, 'nic',
                'network='+BRIDGE, 'name='+INTERFACE])
        address = selected['owners'][name]['address']+'/29'
        backend._dispatch(plan, ['exec', instance, '--', 'ip', 'address', 'replace', address, 'dev', INTERFACE])
        backend._dispatch(plan, ['exec', instance, '--', 'ip', 'link', 'set', INTERFACE, 'up'])
    result = dict(schema='cluster-synthetic-admission-network-installed/v1',
        selection_sha256=digest(selected), production_effects=0,
        existing_admin_rules_changed=False, pairwise_proxies=0)
    being_seed._write(root/'network-installed.json', result)
    return result


@serialized
def remove(root: Path) -> dict:
    backend, group = scope(root)
    selected = being_seed._read(root/'network-scope.json')
    exists, devices = validate_resources(selected, group)
    retained = being_seed._read(root/'network-firewall-expected.json')
    if retained != dict(selection_sha256=digest(selected), nftables=desired_firewall(selected)):
        raise ValueError('preserve the existing firewall ownership contract')
    being_seed._write(root/'network-firewall-expected.json', retained)
    rules = firewall()
    actual = validate_firewall(rules, retained['nftables'], subset=True)
    for name, row in group['owners'].items():
        if row['profile'] == 'guest' and devices[name]:
            backend._dispatch(row['plan'], ['config', 'device', 'remove', 'dm-'+name, DEVICE])
    deletions = []
    for item in rules:
        row = item.get('rule', {})
        if row.get('family') == 'inet' and row.get('table') == 'daimon-fw' and row.get('comment') == COMMENT:
            deletions.append({'delete': {'rule': {key: row[key] for key in ('family', 'table', 'chain', 'handle')}}})
    if any(row.get('table', {}).get('name') == TABLE for row in actual):
        deletions.append({'delete': {'table': dict(family='inet', name=TABLE)}})
    if deletions:
        # One transaction: lost reply leaves all or none, both safely resumable.
        command(['nft', '-j', '-f', '-'], text=json.dumps(dict(nftables=deletions)))
    if exists:
        incus('network', 'delete', BRIDGE)
    return dict(removed=True, production_effects=0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'remove'))
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps((prepare if args.action == 'prepare' else remove)(args.root), sort_keys=True))


if __name__ == '__main__':
    main()
