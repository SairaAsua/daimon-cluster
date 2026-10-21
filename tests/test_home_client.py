"""Independent frontend contracts reuse current subject, grants and browser origin."""
import json
from pathlib import Path
import subprocess
import urllib.request
import urllib.error

import pytest

from clusterctl.homes.service import handler
from tests.test_home_gateway import serving
from tests.test_home_passkeys import system, approved


def test_native_browser_client_behavior():
    subprocess.run(['node', '--test', 'tests/js/home-access-client.cjs'],
                   cwd=Path(__file__).resolve().parents[1], check=True)


def test_visitor_projection_and_opt_in_client_use_current_identity(system):
    app, _ = system
    token, _ = approved(app)
    with serving(handler(app)) as root:
        def get(path, **headers):
            return urllib.request.urlopen(urllib.request.Request(root+path,
                headers={'Host':'one.example.test', **headers}))
        with get('/access/status') as response:
            anonymous = json.load(response)
        assert anonymous == {'contract':'dm.home-browser/v1','home':{'name':'one'},
            'signed_in':False,'visitor':None,'dedicated_vpn':False,'passkeys':True}
        with get('/access/status', Cookie='__Host-home='+token) as response:
            assert json.load(response)['visitor'] == {'name':'Human','kind':'human'}
        with get('/access-client.js') as response:
            assert response.headers['Content-Type'].startswith('text/javascript')
            assert b'createClient' in response.read()
        with pytest.raises(urllib.error.HTTPError) as denied:
            get('/examples/home-client/')
        assert denied.value.code == 404
        denied.value.close()
        app.client_example = True
        with get('/examples/home-client/') as response:
            body = response.read()
            assert b'/access-client.js' in body and b'/home-client-example.js' in body
            assert b'passkey-action' not in body and b'/home.css' not in body
            assert "script-src 'self'" in response.headers['Content-Security-Policy']
        with get('/home-client-example.js') as response:
            assert b'client.catalog()' in response.read()
        app.sessions.revoke(home="one", token=token)
        with get('/access/status', Cookie='__Host-home='+token) as response:
            assert json.load(response)['visitor'] is None
        for origin in ('null','https://artifacts.example.test','https://two.example.test'):
            with pytest.raises(urllib.error.HTTPError) as denied:
                get('/access/status', Origin=origin)
            assert denied.value.code == 404
            denied.value.close()


def test_application_identity_reuses_current_browser_and_revocation(system):
    app, _ = system
    token, _ = approved(app)
    with serving(handler(app)) as root:
        def get(**headers):
            return urllib.request.urlopen(urllib.request.Request(root+'/access/identity',
                headers={'Host':'one.example.test', **headers}))
        for headers in ({}, {'Authorization':'Bearer '+token}):
            with pytest.raises(urllib.error.HTTPError) as denied:
                get(**headers)
            assert denied.value.code == 401
            denied.value.close()
        with get(Cookie='__Host-home='+token) as response:
            value=json.load(response)
        assert value['contract']=='dm.home-session/v1'
        assert value['origin']=='https://one.example.test'
        assert value['actor']['ref']=='human'
        assert token not in json.dumps(value)
        app.sessions.revoke(home='one', token=token)
        with pytest.raises(urllib.error.HTTPError) as denied:
            get(Cookie='__Host-home='+token)
        assert denied.value.code==401
        denied.value.close()
