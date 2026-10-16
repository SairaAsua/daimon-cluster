"""Actual Vikunja-backed journeys and native audience boundaries.

Set DAIMON_AGENDA_VIKUNJA to a disposable, registration-enabled loopback engine
to run the provider journeys. Default CI uses a contract fixture for those calls;
the optional qualification run proves the pinned upstream's actual behavior.
"""
from contextlib import contextmanager
from copy import deepcopy
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import urllib.error
import urllib.request

import pytest

from clusterctl.homes.agenda import Agenda, AgendaError, Vikunja
from clusterctl.homes.policy import Actor
from clusterctl.homes.service import Application, handler
from clusterctl.homes.sessions import Sessions


class Authority:
    def __init__(self):
        self.people = {name: Actor(name, kind, 'v1', name) for name, kind in (
            ('being-one','being'), ('being-two','being'), ('human-one','human'), ('human-two','human'))}
        self.pairs = {'one': 'human-one', 'two': 'human-two'}

    def actor(self, ref): return self.people.get(ref)
    def actors(self): return self.people
    def paired_human(self, home): return self.pairs.get(home)
    def tribe_member(self, *_): return False
    def tribes(self): return {}


class Engine:
    """Separate backend principals and provider-owned records; no Matrix policy."""
    def __init__(self):
        self.users = {}; self.projects = {}; self.tasks = {}; self.comments = {}
        self.next_id = 1; self.drop_ack = False

    def login(self, account):
        user = self.users.get(account['username'])
        if not user or user['password'] != account['password']:
            raise AgendaError('agenda_provider_denied', 502)
        return account['username']

    def pages(self, path, token):
        if path == '/projects':
            return deepcopy([p for p in self.projects.values() if p['owner']['id'] == token])
        if path == '/tasks':
            return deepcopy([t for t in self.tasks.values() if self.projects[t['project_id']]['owner']['id'] == token])
        return deepcopy(self.comments.get((token, path), []))

    def request(self, method, path, payload=None, *, token=None):
        if path == '/register':
            self.users[payload['username']] = payload
            return {'id': payload['username']}
        if path == '/user': return {'id': token}
        self.next_id += 1
        if path == '/projects' and method == 'PUT':
            result = {**payload, 'id': self.next_id, 'owner': {'id': token}, 'is_archived': False}
            self.projects[result['id']] = result
        elif path.startswith('/projects/') and path.endswith('/tasks'):
            project = self.projects[int(path.split('/')[2])]
            if project['owner']['id'] != token: raise AgendaError('agenda_provider_denied', 502)
            result = {**payload, 'id': self.next_id, 'done': False, 'created': '2026-10-16T12:00:00Z', 'updated': str(self.next_id)}
            self.tasks[result['id']] = result
            if self.drop_ack:
                self.drop_ack = False
                raise AgendaError('agenda_provider_unavailable', 503)
        elif path.startswith('/projects/'):
            result = self.projects[int(path.split('/')[2])]
            if result['owner']['id'] != token: raise AgendaError('agenda_provider_denied', 502)
        elif path.startswith('/tasks/') and path.endswith('/comments'):
            result = {'id': self.next_id, 'comment': payload['comment'], 'created': '2026-10-16T12:00:00Z'}
            self.comments.setdefault((token, path), []).append(result)
        elif path.startswith('/tasks/'):
            result = self.tasks[int(path.split('/')[2])]
            if self.projects[result['project_id']]['owner']['id'] != token: raise AgendaError('agenda_provider_denied', 502)
            if method == 'POST':
                result = {**payload, 'updated': str(self.next_id)}
                self.tasks[result['id']] = result
        else: raise AssertionError((method, path))
        return deepcopy(result)


@pytest.fixture
def app(tmp_path):
    authority = Authority()
    config = {'homes': {name: {'name': name, 'owner_being_ref': 'being-'+number,
        'owner_revision': 'v1', 'public_url': 'https://'+name+'.example',
        'vpn_url': 'https://private-'+name+'.example', 'ring': []}
        for name,number in [('one','one'),('two','two')]},
        'content_public_url':'https://content.example','content_vpn_url':'https://private-content.example'}
    app = Application(config, authority, Sessions(tmp_path/'sessions'), backends={'one':None,'two':None})
    app.agenda = Agenda(app, tmp_path/'agenda', 'http://127.0.0.1:18456', provider=Engine())
    return app


def call(app, action, payload=None, *, home='one', actor='human-one', operation='operation-one', native=False):
    args = payload or {}
    if action not in ('state','observations'): args = {**args,'operation_id':operation}
    return app.agenda.dispatch(home,app.authority.actor(actor),action,args,native=native)


def test_private_pair_and_native_scope_rechecked_before_every_effect(app):
    with pytest.raises(AgendaError, match='access_denied'):
        call(app,'init',actor='human-two')
    assert not app.agenda.account('being-one')
    call(app,'init')
    with pytest.raises(AgendaError, match='access_denied'):
        call(app,'state',actor='being-one')  # reader bearer is not a native writer
    assert call(app,'state',actor='being-one',native=True)['initialized']
    app.authority.pairs['one']='human-two'
    with pytest.raises(AgendaError, match='access_denied'):
        call(app,'state')
    assert call(app,'state',actor='human-two')['initialized']
    app.authority.people['being-one']=Actor('being-one','being','v2','being-one')
    with pytest.raises(AgendaError, match='access_denied'):
        call(app,'state',actor='human-two')


def test_two_agendas_share_one_engine_without_sharing_tasks(app):
    first=call(app,'init')
    other=call(app,'init',home='two',actor='human-two')
    project=first['projects'][0]['id']
    task=call(app,'task-create',{'title':'Call engineer','project_id':project,'date':'2026-11-01'},operation='create-first')['task']
    assert task['due_date']=='2026-11-01T00:00:00Z' and task['start_date'].startswith('0001-')
    assert call(app,'state',home='two',actor='human-two')['tasks']==[]
    with pytest.raises(AgendaError):
        call(app,'observation-add',{'task_id':task['id'],'text':'Forbidden'},home='two',actor='human-two',operation='foreign-note')
    assert project != other['projects'][0]['id']


def test_two_homes_of_one_being_reuse_the_same_agenda(app):
    first=call(app,'init')
    app.homes['alias']={**app.homes['one'],'name':'Another body home'}
    app.authority.pairs['alias']='human-one'
    assert call(app,'state',home='alias')['projects']==first['projects']
    assert app.agenda.account('being-one')['registered']


def test_same_operation_survives_retry_and_uncertain_ack_never_replays(app):
    project=call(app,'init')['projects'][0]['id']
    params={'title':'One task','project_id':project}
    created=call(app,'task-create',params,operation='create-once')
    assert call(app,'task-create',params,operation='create-once')==created
    with pytest.raises(AgendaError,match='operation_conflict'):
        call(app,'task-create',{**params,'title':'Changed'},operation='create-once')
    app.agenda.provider.drop_ack=True
    with pytest.raises(AgendaError,match='provider_unavailable'):
        call(app,'task-create',params,operation='lost-ack')
    with pytest.raises(AgendaError,match='operation_uncertain'):
        call(app,'task-create',params,operation='lost-ack')
    assert len(call(app,'state')['tasks'])==2


def test_observations_and_completion_reopen_from_provider(app):
    project=call(app,'init')['projects'][0]['id']
    task=call(app,'task-create',{'title':'A task','project_id':project},operation='task-create')['task']
    call(app,'observation-add',{'task_id':task['id'],'text':'The new plan is ready.'},operation='add-note')
    rows=call(app,'observations',{'task_id':task['id']})['observations']
    assert 'human-one' in rows[0]['text'] and 'new plan' in rows[0]['text']
    changed=call(app,'task-update',{'task_id':task['id'],'revision':task['revision'],'done':True},operation='finish-task')['task']
    assert changed['done']
    with pytest.raises(AgendaError,match='task_changed'):
        call(app,'task-update',{'task_id':task['id'],'revision':task['revision'],'done':False},operation='stale-update')
    restored=Agenda(app,app.agenda.path.parent,'http://127.0.0.1:18456',provider=app.agenda.provider)
    app.agenda=restored
    assert call(app,'state')['tasks'][0]['done']


def test_timezone_conversion_and_nonexistent_local_time():
    task=Agenda.task_input({'title':'Meeting','project_id':1,'date':'2026-11-01','time':'10:00','timezone':'America/Costa_Rica','duration':30})
    assert task['start_date']=='2026-11-01T16:00:00Z'
    assert task['end_date']=='2026-11-01T16:30:00Z'
    with pytest.raises(AgendaError,match='timezone_or_time'):
        Agenda.task_input({'title':'Gap','project_id':1,'date':'2026-03-08','time':'02:30','timezone':'America/New_York'})
    with pytest.raises(AgendaError,match='invalid_date'):
        Agenda.task_input({'title':'Bad','project_id':1,'date':'2026-02-30'})


@contextmanager
def serving(app):
    server=ThreadingHTTPServer(('127.0.0.1',0),handler(app))
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try: yield 'http://127.0.0.1:'+str(server.server_port)
    finally: server.shutdown();server.server_close();thread.join(timeout=2)


def test_browser_cookie_origin_and_untrusted_scope_http(app):
    session=app.sessions.issue(home='one',origin='https://one.example',subject=app.authority.actor('human-one'))
    with serving(app) as base:
        def get(path,headers=None,data=None):
            request=urllib.request.Request(base+path,headers={'Host':'one.example',**(headers or {})},data=data)
            try:
                with urllib.request.urlopen(request,timeout=5) as response:return response.status,response.read(),dict(response.headers)
            except urllib.error.HTTPError as e:
                with e:return e.code,e.read(),dict(e.headers)
        assert get('/agenda/')[0]==200
        assert get('/agenda/api/state')[0]==403
        cookie={'Cookie':'__Host-home='+session,'Content-Type':'application/json'}
        payload=json.dumps({'action':'init','payload':{'operation_id':'browser-init'}}).encode()
        assert get('/agenda/api/command',cookie,payload)[0]==403
        assert get('/agenda/api/command',{**cookie,'Origin':'https://evil.example'},payload)[0]==400
        status,body,headers=get('/agenda/api/command',{**cookie,'Origin':'https://one.example'},payload)
        assert status==200 and json.loads(body)['initialized'] and headers['Cache-Control']=='no-store'
        assert get('/agenda/api/state',{'Authorization':'Bearer '+session})[0]==403


@pytest.mark.skipif(not os.environ.get('DAIMON_AGENDA_VIKUNJA'), reason='disposable pinned engine not selected')
def test_official_vikunja_end_to_end(app):
    app.agenda.provider=Vikunja(os.environ['DAIMON_AGENDA_VIKUNJA'])
    first=call(app,'init')
    project=call(app,'project-create',{'title':'Qualification project'},operation='actual-project')['project']
    task=call(app,'task-create',{'title':'Call engineer','description':'Continue the procedures.',
        'project_id':project['id'],'date':'2026-11-01'},operation='actual-task')['task']
    assert task['due_date'].startswith('2026-11-01')
    call(app,'observation-add',{'task_id':task['id'],'text':'First verified observation.'},operation='actual-note')
    assert 'First verified observation.' in call(app,'observations',{'task_id':task['id']})['observations'][0]['text']
    assert call(app,'task-create',{'title':'Call engineer','description':'Continue the procedures.',
        'project_id':project['id'],'date':'2026-11-01'},operation='actual-task')['task']['id']==task['id']
    call(app,'init',home='two',actor='human-two')
    assert not call(app,'state',home='two',actor='human-two')['tasks']
    call(app,'task-update',{'task_id':task['id'],'revision':task['revision'],'done':True},operation='actual-complete')
    rows=call(app,'state')['tasks']
    assert len(rows)==1 and rows[0]['done']
