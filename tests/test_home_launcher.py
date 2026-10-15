"""Shared app discovery reuses publication, current grants and canonical styling."""
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from clusterctl.homes.launcher import app_url, catalog
from clusterctl.homes.registry import version_digest
from clusterctl.homes.service import handler
from tests.test_home_gateway import selected, serving
from tests.test_home_passkeys import system, approved


@pytest.mark.parametrize('url', [
    'https://t.me/example_bot?startapp',
    'https://t.me/example_bot/sessions?mode=compact',
    'https://t.me/example_bot/matrix?startapp=my_app',
])
def test_supported_native_app_links(url):
    assert app_url(url)


@pytest.mark.parametrize('url', [
    'javascript:alert(1)', 'https://example.org/app', 'https://t.me.evil.test/a/b',
    'https://t.me@evil.test/a/b', 'https://evil.test@t.me/a/b',
    'https://t.me/example_bot', 'https://t.me/example_bot?start=hello',
    'https://t.me/example_bot?startapp=one&startapp=two',
    'https://t.me/example_bot/sessions?token=secret',
    'https://t.me/example_bot/a/b', 'https://t.me/example_bot/a%2fb',
    'https://t.me/example_bot?startapp=x%0A', 'https://t.me/example_bot#secret',
])
def test_unrelated_or_ambiguous_links_are_not_promoted_to_apps(url):
    assert not app_url(url)


def populated(app):
    app.homes['one']['ring'] = [{'name':'two','url':app.homes['two']['public_url']}]
    app.homes['two']['ring'] = []
    def entry(ref, audience, title):
        e=selected(ref * 32, audience, title=title, kind='link',
                   url='https://t.me/example_bot/'+title.lower())
        e['version_ref']=version_digest(e)
        return e
    states={'one':{'schema':1,'entries':[entry('a','human','PrivateOwn')]},
            'two':{'schema':1,'entries':[entry('b','human','PrivateOther'),entry('c','public','PublicApp')]}}
    class Backend:
        def __init__(self, name):self.name=name
        def state(self, *, timeout=15):
            assert timeout in (2,15)
            return states[self.name]
    app.backends={name:Backend(name) for name in app.homes}
    for name in app.homes:
        app.registry.register(home=name,owner='owner',state=states[name],expected_revision=0,
                              known_actor=app.authority.actor,known_tribe=lambda _:False)
    return states


def test_cross_home_public_discovery_cannot_reuse_local_private_entitlement(system):
    app,_=system;states=populated(app)
    result=catalog(app,'one',app.authority.actor('human'),False)
    assert {e['title'] for e in result['apps']}=={'PrivateOwn','PublicApp'}
    assert not result['partial']
    assert {e['title'] for e in catalog(app,'one',None,False)['apps']}=={'PublicApp'}
    states['two']['entries'][1]['visibility']='human'
    assert not catalog(app,'one',None,False)['apps']


def test_source_failure_keeps_usable_apps_and_reports_partial_without_private_error(system):
    app,_=system;populated(app)
    class Offline:
        def state(self,**_):raise OSError('private error must not reach clients')
    app.backends['two']=Offline()
    result=catalog(app,'one',app.authority.actor('human'),False)
    assert result['partial'] and result['unavailable_sources']==1
    assert [e['title'] for e in result['apps']]==['PrivateOwn']
    assert 'private error' not in json.dumps(result)


def test_actual_http_routes_preserve_origin_and_current_reader_boundaries(system):
    app,_=system;populated(app);token,_=approved(app)
    with serving(handler(app)) as base:
        def get(path,**headers):return urlopen(Request(base+path,headers={'Host':'one.example.test',**headers}))
        with get('/apps/') as response:
            body=response.read();assert b'data-style-policy="inherit"' in body
            assert b'/home-style.js' in body and b'data-style-surface="apps"' in body
            assert b'/apps/launcher.css' in body
            assert 'https://telegram.org/js/telegram-web-app.js' in response.headers['Content-Security-Policy']
        with get('/apps/catalog.json') as response:
            assert [e['title'] for e in json.load(response)['apps']]==['PublicApp']
        with get('/apps/catalog.json',Cookie='__Host-home='+token) as response:
            assert {e['title'] for e in json.load(response)['apps']}=={'PrivateOwn','PublicApp'}
        app.sessions.revoke(home='one',token=token)
        with get('/apps/catalog.json',Cookie='__Host-home='+token) as response:
            assert [e['title'] for e in json.load(response)['apps']]==['PublicApp']
        for path in ('/apps/catalog.json','/apps/launcher.js'):
            with pytest.raises(HTTPError) as denied:get(path,Origin='https://other.example.test')
            assert denied.value.code==404
            denied.value.close()
        for path in ('/apps/private.json','/apps/../registry.py','/apps/%2e%2e/registry.py'):
            with pytest.raises(HTTPError) as denied:get(path)
            assert denied.value.code==404
            denied.value.close()


def test_launcher_appearance_has_its_own_canonical_surface_without_new_store(system):
    from clusterctl.homes.homemaker import Homemaker
    from clusterctl.homes.styles import StyleConsumer
    app,_=system
    calls=[]
    class Provider:
        def resolve(self, subject, **context):
            calls.append((subject,context))
            return {'contract':'homemaker.resolved/v1','appearance':None}
    app.styles=StyleConsumer(Provider(),app.authority,app.homes)
    with serving(handler(app)) as base:
        with urlopen(Request(base+'/style.json?surface=apps',headers={'Host':'one.example.test'})) as response:
            assert json.load(response)['contract']=='homemaker.resolved/v1'
    assert calls==[(None,{'author':{'kind':'being','ref':'owner'},'surface':'apps','viewer_scope':None})]
    # Existing authorized owner selection can target this built-in surface;
    # no launcher-specific preference database or selection write is added.
    assert Homemaker.surface(None,'one','apps')=='apps'
