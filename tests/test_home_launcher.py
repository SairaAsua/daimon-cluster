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
        # The real link publisher has a canonical version_ref, not the file
        # revision field carried by artifact fixtures.
        e.pop('revision')
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
    assert all(len(e['version_ref'])==64 for e in result['apps'])
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


def publish_owner_link(app, states, url):
    entry = selected('d' * 32, 'public', title='Home Maker', kind='link', url=url)
    entry.pop('revision')
    entry['version_ref'] = version_digest(entry)
    states['one']['entries'].append(entry)
    app.registry.register(home='one', owner='owner', state=states['one'], expected_revision=1,
                          known_actor=app.authority.actor, known_tribe=lambda _:False)
    return entry


def test_owner_web_app_requires_both_configured_application_and_current_publication(system):
    from types import SimpleNamespace
    app, _ = system
    states = populated(app)
    url = app.homes['two']['public_url'] + '/homemaker/miniapp.html'
    entry = publish_owner_link(app, states, url)
    assert 'Home Maker' not in {e['title'] for e in catalog(app, 'one', None, False)['apps']}
    app.homemaker_home = 'two'
    app.designs = SimpleNamespace(owner_application=None)
    assert 'Home Maker' not in {e['title'] for e in catalog(app, 'one', None, False)['apps']}
    app.designs.owner_application = object()
    for home in ('one', 'two'):
        if home == 'two':
            app.homes[home]['ring'] = [{'name':'one', 'url':app.homes['one']['public_url']}]
        result = catalog(app, home, None, False)
        web = next(e for e in result['apps'] if e['title'] == 'Home Maker')
        assert web['url'] == url and web['launch'] == 'web'
        assert web['version_ref'] == entry['version_ref']
        assert all(e['launch'] == 'telegram' for e in result['apps'] if e != web)
    # The app link is withdrawn under the same existing publication/grant rules.
    entry['visibility'] = 'human'
    assert 'Home Maker' not in {e['title'] for e in catalog(app, 'two', None, False)['apps']}


@pytest.mark.parametrize('suffix', [
    '/homemaker/', '/homemaker/miniapp.html?target=other',
    '/homemaker/miniapp.html#identity', '/view/' + 'd' * 32,
    '/homemaker/miniapp.html/extra',
])
def test_owner_entry_does_not_promote_preview_or_identity_parameter_links(system, suffix):
    from types import SimpleNamespace
    app, _ = system
    states = populated(app)
    app.homemaker_home = 'two'
    app.designs = SimpleNamespace(owner_application=object())
    publish_owner_link(app, states, app.homes['two']['public_url'] + suffix)
    assert 'Home Maker' not in {e['title'] for e in catalog(app, 'one', None, False)['apps']}


def test_retired_local_workshop_link_is_not_a_canonical_web_app(system):
    from types import SimpleNamespace
    app, _ = system
    states = populated(app)
    app.homemaker_home = 'two'
    app.designs = SimpleNamespace(owner_application=object())
    publish_owner_link(app, states, app.homes['one']['public_url'] + '/homemaker/miniapp.html')
    assert 'Home Maker' not in {e['title'] for e in catalog(app, 'one', None, False)['apps']}


def test_first_response_contains_local_cards_style_and_versioned_public_assets(system):
    from clusterctl.homes.styles import StyleConsumer
    from urllib.parse import urlsplit
    import re
    app,_=system;populated(app);token,_=approved(app)
    class PublicStyle:
        def resolve(self,*args,**kwargs):
            return {'contract':'homemaker.resolved/v1','appearance':{
                'background':'#eeeedd','surface':'#ffffff','text':'#243624','accent':'#456745',
                'bodyFont':'Georgia, serif','headingFont':'Georgia, serif','gap':'24px','radius':'12px','scheme':'light'}}
    app.styles=StyleConsumer(PublicStyle(),app.authority,app.homes)
    with serving(handler(app)) as base:
        headers={'Host':'one.example.test','Cookie':'__Host-home='+token}
        with urlopen(Request(base+'/apps/',headers=headers)) as response:
            body=response.read().decode()
            assert response.headers['Cache-Control']=='no-store'
        assert '--dm-background:#eeeedd' in body and '>PrivateOwn</span>' in body
        assert 'initial-apps' in body and 'PublicApp' not in body  # Foreign discovery is incremental.
        asset=re.search(r'(/apps/launcher.js\?v=[a-f0-9]{16})',body).group(1)
        with urlopen(Request(base+asset,headers=headers)) as response:
            assert 'immutable' in response.headers['Cache-Control'];etag=response.headers['ETag']
        try:
            urlopen(Request(base+asset,headers={**headers,'If-None-Match':etag}))
        except HTTPError as response:
            assert response.code==304;response.close()
        else:
            raise AssertionError('public unchanged code was retransmitted')
        with urlopen(Request(base+'/apps/launcher.js?v=stale',headers=headers)) as response:
            assert 'immutable' not in response.headers['Cache-Control']
        app.sessions.revoke(home='one',token=token)
        with urlopen(Request(base+'/apps/',headers=headers)) as response:
            assert b'PrivateOwn' not in response.read()


def test_operator_launch_routes_are_bounded_same_origin_paths(system):
    import subprocess
    from pathlib import Path
    from clusterctl.homes.launcher import validate_launch_routes, page
    valid={'schema':'dm.miniapp-routes/v1','origins':{'https://apps.example':[
        {'prefix':'nexus-','path':'/nexus/'}]}}
    assert validate_launch_routes(valid)==valid
    for origins in ({'http://apps.example':valid['origins']['https://apps.example']},
                    {'https://apps.example/path':valid['origins']['https://apps.example']},
                    {'https://apps.example':[{'prefix':'nexus-','path':'//foreign/'}]},
                    {'https://apps.example':[{'prefix':'nexus-','path':'/apps/'}]},
                    {'https://apps.example':[{'prefix':'nexus-','path':'/nexus/'},{'prefix':'nexus-else','path':'/other/'}]}):
        with pytest.raises(ValueError):validate_launch_routes({**valid,'origins':origins})
    app,_=system;app.miniapp_routes=valid;populated(app)
    html=page(app,'one',None,False).decode()
    assert 'id="miniapp-routes"' in html and '/apps/launch.js?v=' in html
    subprocess.run(['node','--test','tests/js/miniapp-launch.cjs'],cwd=Path(__file__).resolve().parents[1],check=True)
