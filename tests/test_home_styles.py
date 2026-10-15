"""Gateway consumer never becomes a second design store or cross-pair editor."""
import subprocess
from pathlib import Path

from clusterctl.homes.styles import StyleConsumer
from clusterctl.homes.policy import Actor
from tests.test_home_gateway import Authority


def test_stable_being_scope_and_explicit_viewer_context_do_not_repaint_another_pairs_home():
    calls=[]
    class Provider:
        def resolve(self,subject,**fields):
            calls.append((subject,fields));return {'contract':'homemaker.resolved/v1','appearance':None}
    authority=Authority()
    consumer=StyleConsumer(Provider(),authority,{'one':{'owner_being_ref':'owner-one'}})
    consumer.resolved('one','home',authority.actor('human-one'))
    assert calls[-1]==('human-one',{'author':{'kind':'being','ref':'owner-one'},'surface':'home','viewer_scope':{'kind':'human','ref':'human-one'}})
    consumer.resolved('one','home',authority.actor('human-two'))
    assert calls[-1][1]['viewer_scope'] is None
    consumer.resolved('one','resource-ref')
    assert calls[-1][0] is None and calls[-1][1]['surface']=='resource-ref'
    old=authority.actor('human-one');authority.people['human-one']=Actor('human-one','human','v2','changed')
    consumer.resolved('one','home',old)
    assert calls[-1][0] is None
    assert not hasattr(consumer,'select') and not hasattr(consumer,'import_recipe')


def test_sandbox_style_consumer_rejects_forged_or_unsafe_payloads():
    subprocess.run(['node','--test','tests/js/home-style-client.cjs'],cwd=Path(__file__).resolve().parents[1],check=True)


def test_public_stylesheet_cannot_use_cookie_bearer_or_private_viewer(system):
    import json
    import pytest
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError
    from clusterctl.homes.service import handler
    from tests.test_home_gateway import serving
    from tests.test_home_passkeys import approved
    app,_=system;calls=[]
    appearance={'background':'#eeeedd','surface':'#ffffff','text':'#243624','accent':'#456745',
                'bodyFont':'Georgia, serif','headingFont':'Georgia, serif','gap':'24px','radius':'12px','scheme':'light'}
    class Provider:
        def resolve(self,subject,**fields):
            calls.append((subject,fields));return {'contract':'homemaker.resolved/v1',
                'appearance':appearance,'design_ref':'not-css-metadata','actor':'never-render'}
    app.styles=StyleConsumer(Provider(),app.authority,app.homes)
    token,_=approved(app)
    with serving(handler(app)) as base:
        for credentials in ({},{'Cookie':'__Host-home='+token},
                            {'Authorization':'Bearer '+token,'Origin':'https://independent.example'}):
            with urlopen(Request(base+'/style.css?surface=sessions',headers={'Host':'one.example.test',**credentials})) as response:
                body=response.read().decode();assert '--dm-background:#eeeedd' in body
                assert 'not-css-metadata' not in body and 'never-render' not in body
                assert response.headers['Cache-Control']=='no-store'
            assert calls[-1][0] is None and calls[-1][1]['viewer_scope'] is None
        for query in ('surface=sessions&viewer=personal','surface=private-resource','surface=sessions&surface=nexus'):
            with pytest.raises(HTTPError) as error:
                urlopen(Request(base+'/style.css?'+query,headers={'Host':'one.example.test'}))
            assert error.value.code==404;error.value.close()
    from clusterctl.homes.styles import appearance_css
    assert not appearance_css({'contract':'homemaker.resolved/v1','appearance':{**appearance,'bodyFont':'</style><script>alert(1)</script>'}})


# Reuse the actual receiving fixture; no separate authority or persistent state.
from tests.test_home_passkeys import system


def test_public_stylesheet_failure_is_not_an_intentional_reset(system):
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError
    from clusterctl.homes.service import handler
    from tests.test_home_gateway import serving
    import pytest
    app,_=system
    class Provider:
        value={}
        def resolve(self,*args,**kwargs):return self.value
    provider=Provider();app.styles=StyleConsumer(provider,app.authority,app.homes)
    with serving(handler(app)) as base:
        request=Request(base+'/style.css?surface=sessions',headers={'Host':'one.example.test'})
        for value in ({},{'contract':'homemaker.resolved/v1','mode':'unavailable','appearance':None},
                      {'contract':'homemaker.resolved/v1','mode':'explicit','appearance':{}},
                      {'contract':'homemaker.resolved/v1','mode':'default'}):
            provider.value=value
            with pytest.raises(HTTPError) as error:urlopen(request)
            assert error.value.code==503;error.value.close()
        provider.value={'contract':'homemaker.resolved/v1','mode':'default','appearance':None}
        with urlopen(request) as response:assert response.status==200 and response.read()==b''
