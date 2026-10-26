"""Receiving operator boundaries that previously prevented a staged app starting."""
import getpass
import grp
import json
from pathlib import Path
import os

import pytest

from tools.agenda_units import units


@pytest.fixture
def receiving(tmp_path):
    release = tmp_path/'release'
    for name in ('clusterctl/homes/agenda_remote.py', 'engine/vikunja'):
        p = release/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch()
    state = tmp_path/'state'
    state.mkdir(mode=0o700)
    for name in ('application', 'engine'):
        (state/name).mkdir(mode=0o700)
    token = tmp_path/'token'
    token.write_text('fixture-not-a-real-transport-token')
    token.chmod(0o600)
    config = tmp_path/'application.json'
    config.write_text(json.dumps({'state': str(state/'application'), 'port': 18091,
                                 'backend': 'http://127.0.0.1:18090', 'token_file': str(token)}))
    config.chmod(0o600)
    engine = tmp_path/'engine.yml'
    engine.write_text(f'service:\n  rootpath: {state}/engine\n  interface: 127.0.0.1:18090\n')
    engine.chmod(0o600)
    return dict(release=release, python=Path('/usr/bin/python3'), config=config,
                engine_config=engine, user=getpass.getuser(), group=grp.getgrgid(os.getgid()).gr_name)


def test_private_receiving_units_keep_engine_local_and_state_bounded(receiving):
    result = units(**receiving, slice_name='eko.slice', private_bind='10.6.6.8')
    assert len(result) == 4
    assert 'ReadWritePaths='+str(receiving['config'].parent/'state') in result['daimon-agenda-application.service']
    assert 'ListenStream=10.6.6.8:18091' in result['daimon-agenda-private.socket']
    assert '127.0.0.1:18091' in result['daimon-agenda-private.service']
    assert 'fixture-not-a-real-transport-token' not in ''.join(result.values())


def test_staging_refuses_the_transferred_public_state_directory(receiving):
    state = Path(json.loads(receiving['config'].read_text())['state'])
    state.chmod(0o755)
    with pytest.raises(ValueError, match='owner-private'):
        units(**receiving)


@pytest.mark.parametrize('address', ['0.0.0.0', '8.8.8.8', '127.0.0.1', '224.0.0.1'])
def test_private_transport_does_not_become_a_public_or_wildcard_listener(receiving, address):
    with pytest.raises(ValueError, match='private VPN address'):
        units(**receiving, private_bind=address)


def test_service_identity_cannot_inject_unit_directives(receiving):
    receiving['user'] = 'agent\nExecStart=/bin/true'
    with pytest.raises(ValueError, match='service user/group'):
        units(**receiving)
