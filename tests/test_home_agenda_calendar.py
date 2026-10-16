"""Calendar provider consent is scoped to the current native pair, not email."""
from contextlib import closing
import hashlib

import pytest

from clusterctl.homes.agenda import AgendaError
from clusterctl.homes.agenda_calendar import GoogleCalendar
from tests.test_home_agenda import app, call  # noqa: F401 -- shared app fixture


class Google:
    def __init__(self):
        self.events = {}
        self.email = 'one@example.invalid'
        self.fail = False

    def authorization(self, state, nonce, verifier, callback, email):
        self.flow = (state, nonce, verifier, callback, email)
        return 'https://accounts.google.com/o/oauth2/v2/auth?state='+state

    def exchange(self, code, verifier, nonce, callback):
        assert (nonce, verifier, callback) == self.flow[1:4]
        return {'sub':'provider-subject','email':self.email}, {
            'access_token':'fixture-access','refresh_token':'fixture-refresh','expires_in':3600}

    def event(self, token, event_id, body):
        if self.fail:
            raise AgendaError('agenda_google_request_failed', 502)
        self.events[event_id] = body
        return {'id':event_id,'htmlLink':'https://www.google.com/calendar/event?eid=fixture'}

    def remove(self, token, event_id):
        self.events.pop(event_id, None)


def connect(app, *, email='one@example.invalid'):
    call(app,'init')
    call(app,'calendar-account',{'email':email},operation='calendar-account')
    provider = Google()
    app.agenda.calendar.provider = provider
    actor = app.authority.actor('human-one')
    app.agenda.calendar.begin('one',actor,'browser-parent','https://one.example')
    app.agenda.calendar.finish('one',actor,'browser-parent',provider.flow[0],'fixture-code')
    return provider


def test_onboarding_asks_per_being_and_valid_connection_is_retained(app):
    result=call(app,'init')
    assert not result['calendar']['setup_complete']
    call(app,'calendar-skip',operation='later-on-one')
    assert call(app,'state')['calendar']['setup_complete']
    assert not call(app,'init',home='two',actor='human-two')['calendar']['setup_complete']
    provider = connect(app)
    assert call(app,'state')['calendar']['connected']
    assert call(app,'state')['calendar']['email']=='one@example.invalid'
    assert not call(app,'state',home='two',actor='human-two')['calendar']['connected']
    assert provider.events=={}


def test_google_flow_binds_session_account_and_current_pair(app):
    call(app,'init')
    call(app,'calendar-account',{'email':'expected@example.invalid'},operation='choose-account')
    provider=Google();app.agenda.calendar.provider=provider
    actor=app.authority.actor('human-one')
    app.agenda.calendar.begin('one',actor,'parent','https://one.example')
    state=provider.flow[0]
    with pytest.raises(AgendaError,match='flow_unavailable'):
        app.agenda.calendar.finish('one',actor,'different-browser',state,'fixture-code')
    with pytest.raises(AgendaError,match='wrong_account'):
        app.agenda.calendar.finish('one',actor,'parent',state,'fixture-code')
    with pytest.raises(AgendaError,match='flow_unavailable'):
        app.agenda.calendar.finish('one',actor,'parent',state,'fixture-code')
    assert not call(app,'state')['calendar']['connected']


def test_provider_chooser_can_supply_account_without_an_email_hint(app):
    provider=connect(app,email='')
    assert provider.flow[4]==''
    assert call(app,'state')['calendar']['email']==provider.email


def test_calendar_create_and_update_keep_one_provider_event(app):
    provider=connect(app)
    project=call(app,'state')['projects'][0]['id']
    params={'title':'A date','project_id':project,'date':'2026-11-01'}
    first=call(app,'task-create',params,operation='dated-task')
    assert first['calendar']['status']=='synced'
    task=first['task']
    expected=hashlib.sha256(('dm.agenda/v1\0being-one\0'+str(task['id'])).encode()).hexdigest()
    assert provider.events[expected]['start']=={'date':'2026-11-01'}
    assert provider.events[expected]['end']=={'date':'2026-11-02'}
    edited=call(app,'task-edit',{**params,'title':'A changed date','date':'2026-11-03',
        'task_id':task['id'],'revision':task['revision']},operation='edit-dated-task')
    assert edited['calendar']['status']=='synced'
    call(app,'calendar-sync',{'task_id':task['id']},operation='sync-same-task')
    assert len(provider.events)==1 and provider.events[expected]['summary']=='A changed date'
    cleared=call(app,'task-edit',{'title':'Undated now','project_id':project,
        'task_id':task['id'],'revision':edited['task']['revision']},operation='clear-task-date')
    assert cleared['calendar']['status']=='removed' and not provider.events
    # Current pairing revocation is effective without recreating an app account.
    app.authority.pairs['one']='human-two'
    assert not app.agenda.calendar.connection('one','being-one')
    assert not call(app,'state',actor='human-two')['calendar']['connected']


def test_google_failure_does_not_hide_a_saved_task(app):
    provider=connect(app);provider.fail=True
    project=call(app,'state')['projects'][0]['id']
    result=call(app,'task-create',{'title':'Still saved','date':'2026-11-01','project_id':project},operation='calendar-down')
    assert result['task']['title']=='Still saved' and result['calendar']['status']=='pending'
    assert len(call(app,'state')['tasks'])==1


def test_calendar_adapter_inserts_then_patches_known_event(monkeypatch):
    provider=object.__new__(GoogleCalendar)
    seen=[]
    def request(method,url,**kwargs):
        seen.append((method,url,kwargs))
        if method=='GET': return None if len(seen)==1 else {'id':'existing'}
        return {'id':'fixed-id'}
    monkeypatch.setattr(provider,'http',request)
    provider.event('fixture','fixed-id',{'summary':'First'})
    provider.event('fixture','fixed-id',{'summary':'Changed'})
    assert [r[0] for r in seen]==['GET','POST','GET','PATCH']
    assert seen[1][2]['body']['id']=='fixed-id'
    assert 'sendUpdates=none' in seen[-1][1]
