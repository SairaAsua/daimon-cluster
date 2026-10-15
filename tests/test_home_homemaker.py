"""Receiving identity/permission and public-source boundaries for Homemaker."""
from dataclasses import replace
from http.client import HTTPConnection
from urllib.parse import urlsplit
import pytest

from clusterctl.homes.homemaker import Homemaker
from clusterctl.homes.service import Application, handler
from tests.test_home_gateway import serving
from tests.test_home_passkeys import system, approved
from clusterctl.homes.policy import Actor


def receiving(app):
    provider=Homemaker.__new__(Homemaker)
    provider.app=app
    provider.templates={'world':'Existing source world'}
    return provider


def test_current_pair_permission_is_separate_from_visiting_another_home(system):
    app, _=system;provider=receiving(app)
    token,_=approved(app,home='two',actor='human')
    visitor=app.identity(token,'two',app.homes['two']['public_url'])
    assert visitor.ref=='human'
    with pytest.raises(ValueError,match='denied'):provider.scope('two',visitor,'pair')
    assert provider.scope('two',visitor,'personal')[0]=={'kind':'human','ref':'human'}
    assert provider.scope('one',visitor,'pair')[0]=={'kind':'being','ref':'owner'}
    app.authority.people['human']=replace(visitor,revision='changed')
    with pytest.raises(ValueError,match='denied'):provider.scope('one',visitor,'pair')


def test_central_editor_resolves_each_current_pair_without_replacing_personal_scope(system):
    app,_=system;provider=receiving(app);app.homemaker_home='two'
    app.authority.people['owner-two']=Actor('owner-two','being','v1','Second owner')
    app.homes['two']['owner_being_ref']='owner-two'
    for actor, owner in (('human','owner'),('other','owner-two')):
        subject=app.authority.actor(actor)
        assert provider.scope('two',subject,'pair')[0]=={'kind':'being','ref':owner}
        assert provider.scope('two',subject,'personal')[0]=={'kind':'human','ref':actor}
    # This does not silently enable every visited home as a central editor.
    with pytest.raises(ValueError,match='denied'):
        provider.scope('one',app.authority.actor('other'),'pair')
    app.authority.people['visitor']=Actor('visitor','human','v1','Visitor')
    with pytest.raises(ValueError,match='context_unavailable'):
        provider.scope('two',app.authority.actor('visitor'),'pair')
    stale=app.authority.actor('human')
    app.authority.people['human']=replace(stale,revision='new')
    with pytest.raises(ValueError,match='denied'):provider.scope('two',stale,'pair')


def test_central_pair_ambiguity_is_not_resolved_by_first_match_or_hostname(system):
    app,_=system;provider=receiving(app);app.homemaker_home='two'
    app.homes['three']={**app.homes['one'],'owner_being_ref':'third-owner'}
    original=app.authority.paired_human
    app.authority.paired_human=lambda home:'human' if home=='three' else original(home)
    with pytest.raises(ValueError,match='context_unavailable'):
        provider.scope('two',app.authority.actor('human'),'pair')


def test_retired_editor_redirects_only_entry_and_never_forwards_reader_credentials(system):
    from urllib.parse import parse_qs
    app,_=system;app.designs=receiving(app);app.homemaker_home='two'
    token,_=approved(app)
    with serving(handler(app)) as base:
        conn=HTTPConnection(urlsplit(base).netloc)
        for entry in ('/homemaker/', '/homemaker/miniapp.html'):
            conn.request('GET',entry,headers={'Host':'one.example.test','Cookie':'__Host-home='+token})
            response=conn.getresponse();response.read();assert response.status==307
            destination=urlsplit(response.getheader('Location'))
            assert destination.netloc=='two.example.test' and destination.path==entry
            assert parse_qs(destination.query)=={'target':['one'],'scope':['pair'],'return_to':['https://one.example.test/']}
            assert token not in response.getheader('Location')
        for method,path in (('GET','/homemaker/bootstrap.js'),('POST','/homemaker/api/default')):
            conn.request(method,path,body='{}' if method=='POST' else None,headers={
                'Host':'one.example.test','Cookie':'__Host-home='+token,'Origin':'https://one.example.test'})
            response=conn.getresponse();response.read();assert response.status==410
        conn.close()


def test_configured_consumer_returns_require_an_exact_registered_public_origin(system):
    app,_=system
    for destination in ('http://one.example.test/', 'https://foreign.example/',
                        'https://one.example.test@foreign.example/', 'https://private-one.example.test/',
                        'https://one.example.test/\nprivate', 'https://one.example.test/\\foreign'):
        with pytest.raises(ValueError,match='invalid_homemaker_return'):
            Application(app.config,app.authority,app.sessions,backends=app.backends,homemaker_returns=[destination])


def test_central_browser_baseline_and_save_use_verified_pair_under_the_same_origin(system):
    import json
    app,_=system;provider=receiving(app);app.designs=provider;app.homemaker_home='two'
    app.authority.people['owner-two']=Actor('owner-two','being','v1','Second owner')
    app.homes['two']['owner_being_ref']='owner-two'
    calls=[]
    class Canonical:
        def editor_default(self,actor,**fields):
            calls.append((actor,fields));return {'design_revision':0,'selection_revision':0}
        def save_default(self,actor,**fields):
            calls.append((actor,fields));return {'status':'saved'}
    provider.authority=Canonical()
    payload={'variant':'template-world','recipe':{'config':{'templateId':'world'}},
             'expected_design_revision':0,'expected_selection_revision':0,'operation_id':'same-intent'}
    with serving(handler(app)) as base:
        conn=HTTPConnection(urlsplit(base).netloc)
        for actor, owner in (('human','owner'),('other','owner-two')):
            token,_=approved(app,home='two',actor=actor)
            headers={'Host':'two.example.test','Cookie':'__Host-home='+token,
                     'Origin':'https://two.example.test'}
            conn.request('GET','/homemaker/api/default?variant=template-world',headers=headers)
            response=conn.getresponse();response.read();assert response.status==200
            assert calls[-1][0]==actor and calls[-1][1]['owner']=={'kind':'being','ref':owner}
            conn.request('POST','/homemaker/api/default',body=json.dumps(payload),headers=headers)
            response=conn.getresponse();response.read();assert response.status==200
            assert calls[-1][0]==actor and calls[-1][1]['owner']=={'kind':'being','ref':owner}
            for extra in ({'Origin':'null'},{'Authorization':'Bearer '+token}):
                before=len(calls)
                conn.request('POST','/homemaker/api/default',body=json.dumps(payload),headers={**headers,**extra})
                response=conn.getresponse();response.read();assert response.status==403
                assert len(calls)==before
        conn.close()


def test_reading_identity_does_not_authorize_another_persons_design_scope(system):
    app,_=system;provider=receiving(app)
    assert provider.authorize('human','design.select',{'kind':'human','ref':'human'})
    assert not provider.authorize('human','design.update',{'kind':'human','ref':'other'})
    assert not provider.authorize('unknown','design.update',{'kind':'being','ref':'owner'})
    assert not provider.authorize('human','unrecognized.action',{'kind':'being','ref':'owner'})
    assert provider.authorize('owner','design.read',{'kind':'being','ref':'owner'})
    assert provider.authorize('owner','design.update',{'kind':'being','ref':'owner'})
    assert not provider.authorize('owner','design.update',{'kind':'human','ref':'human'})
    with pytest.raises(ValueError,match='denied'):provider.scope('one',app.authority.actor('owner'),'pair')


def test_request_cannot_replace_author_or_private_public_decision(system):
    app,_=system;provider=receiving(app);person=app.authority.actor('human')
    payload={'variant':'template-world','recipe':{},'expected_design_revision':0,
             'expected_selection_revision':0,'operation_id':'one'}
    for key in ('actor','owner','audience'):
        with pytest.raises(ValueError,match='invalid_design_save'):
            provider.save('one',person,'pair',{**payload,key:'chosen-by-request'})
    with pytest.raises(ValueError,match='mismatch'):provider.save('one',person,'pair',payload)
    with pytest.raises(ValueError,match='invalid_design_variant'):provider.variant('../private')


def test_canonical_source_asset_route_cannot_reach_backend_state_or_symlinks(tmp_path):
    provider=Homemaker.__new__(Homemaker);provider.public=tmp_path/'dist';provider.public.mkdir()
    (provider.public/'app.js').write_text('public source')
    private=tmp_path/'state';private.write_text('not public')
    (provider.public/'shortcut.js').symlink_to(private)
    assert provider.asset('app.js').read_text()=='public source'
    for name in ('../state','shortcut.js','/app.js','./app.js','.private','a/../app.js'):
        with pytest.raises(ValueError):provider.asset(name)


@pytest.mark.parametrize('entry', ['/homemaker/', '/homemaker/miniapp.html'])
def test_anonymous_editor_offers_shared_login_without_loading_identity_or_design(system, entry):
    app,_=system;app.designs=receiving(app)
    with serving(handler(app)) as base:
        conn=HTTPConnection(urlsplit(base).netloc)
        conn.request('GET',entry,headers={'Host':'one.example.test'})
        response=conn.getresponse();body=response.read()
        assert response.status==200 and b'Sign in' in body and b'Tu taller' in body
        assert b'bootstrap.js' not in body and b'owner' not in body
        miniapp=entry.endswith('miniapp.html')
        assert (b'home-miniapp-login.js' in body)==miniapp
        assert ('https://telegram.org/js/telegram-web-app.js' in response.getheader('Content-Security-Policy'))==miniapp
        conn.request('GET','/homemaker/api/context',headers={'Host':'one.example.test'})
        response=conn.getresponse();response.read();assert response.status==404
        conn.close()


def test_design_post_requires_current_browser_and_origin_not_null_or_bearer(system):
    app,_=system;app.designs=receiving(app);token,_=approved(app)
    with serving(handler(app)) as base:
        conn=HTTPConnection(urlsplit(base).netloc)
        for extras in ({'Origin':'null'},{'Origin':'https://two.example.test'},
                       {'Origin':'https://one.example.test','Authorization':'Bearer '+token}):
            conn.request('POST','/homemaker/api/default',body='{}',headers={
                'Host':'one.example.test','Cookie':'__Host-home='+token,**extras})
            response=conn.getresponse();response.read();assert response.status==403
        conn.close()


def test_native_style_operation_requires_publisher_credential_and_fixed_namespace(system, tmp_path):
    app,_=system;provider=receiving(app);app.designs=provider
    credential=tmp_path/'publisher';credential.write_text('publisher-secret');credential.chmod(0o600)
    app.homes['one']['owner_token_file']=str(credential)
    app.sessions.register_owner(home='one',actor='owner',revision='v1',token='publisher-secret')
    calls=[]
    class Canonical:
        def editor_default(self,subject,**fields):
            calls.append((subject,fields));return {'revision':0}
        def save_default(self,subject,**fields):
            calls.append((subject,fields));return {'status':'saved'}
        def read_selection(self,subject,**fields):
            calls.append((subject,fields));return {'mode':'default','revision':0}
        def select(self,subject,**fields):
            calls.append((subject,fields));return {'mode':'default','revision':1}
        def read_recipe(self,subject,ref,revision):
            calls.append((subject,{'ref':ref,'revision':revision}));return None
    provider.authority=Canonical()
    reader,_=approved(app,actor='owner')
    for operation in ('style-baseline','style-default','style-selection','style-select','style-recipe'):
        with pytest.raises(ValueError,match='home_owner_denied'):
            app.owner('one',reader,operation,{'variant':'template-world'})
    assert app.owner('one','publisher-secret','style-baseline',{'variant':'template-world'})=={'revision':0}
    payload={'variant':'template-world','recipe':{'config':{'templateId':'world'}},
             'expected_design_revision':0,'expected_selection_revision':0,'operation_id':'native',
             'audience':'public'}
    assert app.owner('one','publisher-secret','style-default',payload)=={'status':'saved'}
    assert calls[-1][0]=='owner' and calls[-1][1]['owner']=={'kind':'being','ref':'owner'}
    assert calls[-1][1]['audience']=='public'
    assert app.owner('one','publisher-secret','style-selection',{'surface':'home'})=={'mode':'default','revision':0}
    assert calls[-1][1]['scope']=={'kind':'being','ref':'owner'}
    selection={'surface':'homemaker','selection':{'mode':'default'},'expected_revision':0,'operation_id':'select'}
    assert app.owner('one','publisher-secret','style-select',selection)['revision']==1
    for extra in ({'scope':{'kind':'human','ref':'human'}},{'actor':'other'}):
        with pytest.raises(ValueError,match='invalid_design_selection'):
            app.owner('one','publisher-secret','style-select',{**selection,**extra})
    with pytest.raises(ValueError,match='unregistered_design_surface'):
        app.owner('one','publisher-secret','style-selection',{'surface':'another-home'})
    with pytest.raises(ValueError,match='design_recipe_unavailable'):
        app.owner('one','publisher-secret','style-recipe',{'design_ref':'private-other'})
    for extra in ({'owner':{'kind':'human','ref':'human'}},{'actor':'other'}):
        with pytest.raises(ValueError,match='invalid_design_save'):
            app.owner('one','publisher-secret','style-default',{**payload,**extra})
    with pytest.raises(ValueError,match='explicit_design_audience_required'):
        app.owner('one','publisher-secret','style-default',{k:v for k,v in payload.items() if k!='audience'})
    app.authority.people['owner']=replace(app.authority.actor('owner'),revision='changed')
    with pytest.raises(ValueError,match='home_owner_binding_unavailable'):
        app.owner('one','publisher-secret','style-default',payload)
